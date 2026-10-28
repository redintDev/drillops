"""Multi-target declarative watcher and drill orchestrator for enterprise environments."""

from dataclasses import dataclass, field
import json
import logging
import os
import tempfile
from typing import Any, Dict, List, Optional

from drillops.core.runner import DrillRunner
from drillops.daemon.watcher import DrillWatcher
from drillops.licensing import LicenseValidator
from drillops.models import AssertionRule, DrillSummary, VerificationConfig
from drillops.notifications import NotificationConfig, NotificationDispatcher
from drillops.storage.providers import BaseStorageProvider, LocalStorageProvider, MockS3StorageProvider

logger = logging.getLogger("drillops.orchestrator")


@dataclass
class TargetDefinition:
    """Configuration for a single monitored database target."""
    name: str
    database_type: str
    storage_type: str  # 'local' or 's3'
    storage_path: str  # directory path or bucket/prefix
    expected_tables: List[str] = field(default_factory=list)
    assertion_rules: List[AssertionRule] = field(default_factory=list)
    host: Optional[str] = None
    port: Optional[int] = None
    user: Optional[str] = None
    password: Optional[str] = None


@dataclass
class OrchestratorConfig:
    """Declarative multi-target configuration model."""
    targets: List[TargetDefinition]
    output_dir: str = "./certificates"
    notifications: Optional[NotificationConfig] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OrchestratorConfig":
        raw_targets = data.get("targets", [])
        targets = []
        for t in raw_targets:
            rules = [AssertionRule(**r) for r in t.get("assertion_rules", [])]
            targets.append(
                TargetDefinition(
                    name=t.get("name", "unnamed_target"),
                    database_type=t.get("database_type", t.get("engine", "sqlite")),
                    storage_type=t.get("storage_type", "local"),
                    storage_path=t.get("storage_path", t.get("path", "")),
                    expected_tables=t.get("expected_tables", []),
                    assertion_rules=rules,
                    host=t.get("host"),
                    port=t.get("port"),
                    user=t.get("user"),
                    password=t.get("password"),
                )
            )

        notif = None
        if "notifications" in data:
            notif = NotificationConfig.from_env_or_dict(data["notifications"])

        return cls(
            targets=targets,
            output_dir=data.get("output_dir", "./certificates"),
            notifications=notif,
        )

    @classmethod
    def from_json_file(cls, path: str) -> "OrchestratorConfig":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)


class MultiTargetOrchestrator:
    """Orchestrates scheduled restore drills across multiple heterogeneous database targets."""

    def __init__(
        self,
        config: OrchestratorConfig,
        license_validator: Optional[LicenseValidator] = None,
    ):
        self.config = config
        self.validator = license_validator or LicenseValidator()
        self.dispatcher = NotificationDispatcher(config.notifications) if config.notifications else NotificationDispatcher()

    def _create_storage_provider(self, target: TargetDefinition) -> BaseStorageProvider:
        stype = target.storage_type.lower()
        if stype in ("mock_s3", "mock") or target.storage_path.startswith("mock://"):
            return MockS3StorageProvider(target.storage_path)
        elif stype in ("s3", "r2", "cloud") or target.storage_path.startswith("s3://"):
            from drillops.storage.providers import S3CompatibleStorageProvider
            uri = target.storage_path if target.storage_path.startswith("s3://") else f"s3://{target.storage_path}"
            return S3CompatibleStorageProvider.from_uri(uri)
        return LocalStorageProvider(target.storage_path)

    def run_all_once(self) -> Dict[str, Optional[DrillSummary]]:
        """Executes a single check and restore verification pass across all targets."""
        active_targets = self.config.targets

        # Commercial tier licensing gate:
        # If more than 1 target is monitored, check for Pro/Enterprise tier license
        if len(active_targets) > 1:
            has_multi = self.validator.is_feature_enabled("multi_target")
            if not has_multi:
                logger.warning(
                    "Multi-target monitoring is a DrillOps Pro feature. Running first target only. "
                    "Upgrade to Pro ($79/year) to unlock unlimited database target monitoring."
                )
                print(
                    "⚠️  Notice: Multi-target orchestration is a DrillOps Pro feature.\n"
                    "   Running primary target only. Set DRILLOPS_LICENSE_KEY to unlock all targets."
                )
                active_targets = active_targets[:1]

        results: Dict[str, Optional[DrillSummary]] = {}

        for target in active_targets:
            target_out_dir = os.path.join(self.config.output_dir, target.name)
            os.makedirs(target_out_dir, exist_ok=True)

            provider = self._create_storage_provider(target)
            v_config = VerificationConfig(
                database_type=target.database_type,
                backup_path="",
                expected_tables=target.expected_tables,
                assertion_rules=target.assertion_rules,
                host=target.host,
                port=target.port,
                user=target.user,
                password=target.password,
            )

            watcher = DrillWatcher(
                provider=provider,
                config=v_config,
                output_dir=target_out_dir,
                state_file=os.path.join(target_out_dir, ".drillops_state.json"),
            )

            try:
                summary = watcher.check_and_run_once()
                results[target.name] = summary
                if summary:
                    self.dispatcher.dispatch_all(summary, [])
            except Exception as e:
                logger.error(f"Target '{target.name}' failed during drill run: {e}")
                results[target.name] = None

        return results
