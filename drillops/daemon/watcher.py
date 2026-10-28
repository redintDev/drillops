"""DrillWatcher: Autonomous daemon that monitors backups and triggers scheduled restore drills."""

import json
import logging
import os
import tempfile
import time
import urllib.request
from typing import Callable, Dict, List, Optional

from drillops.core.runner import DrillRunner
from drillops.models import DrillSummary, VerificationConfig
from drillops.storage.archive import ArchiveProcessor
from drillops.storage.providers import BaseStorageProvider

logger = logging.getLogger("drillops.daemon")


class DrillWatcher:
    """
    Watches a storage provider, detects new backup archives,
    runs automated restore drills, records certificates, and pings alert endpoints.
    """

    def __init__(
        self,
        provider: BaseStorageProvider,
        config: VerificationConfig,
        output_dir: str,
        webhook_url: Optional[str] = None,
        heartbeat_url: Optional[str] = None,
        state_file: Optional[str] = None,
    ):
        self.provider = provider
        self.config = config
        self.output_dir = output_dir
        self.webhook_url = webhook_url
        self.heartbeat_url = heartbeat_url
        self.state_file = state_file or os.path.join(output_dir, ".drillops_state.json")
        self.processed_hashes: set = self._load_state()

    def _load_state(self) -> set:
        if os.path.isfile(self.state_file):
            try:
                with open(self.state_file, "r") as f:
                    data = json.load(f)
                    return set(data.get("processed_hashes", []))
            except Exception:
                pass
        return set()

    def _save_state(self) -> None:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.state_file)), exist_ok=True)
            with open(self.state_file, "w") as f:
                json.dump({"processed_hashes": list(self.processed_hashes)}, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to persist state: {e}")

    def ping_heartbeat(self) -> bool:
        """Pings external heartbeat monitor (e.g. Healthchecks.io, Dead Man's Snitch)."""
        if not self.heartbeat_url:
            return False
        try:
            req = urllib.request.Request(self.heartbeat_url, headers={"User-Agent": "DrillOps/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status in (200, 201, 204)
        except Exception as e:
            logger.error(f"Heartbeat ping failed: {e}")
            return False

    def notify_webhook(self, summary: DrillSummary, cert_links: Dict[str, str]) -> bool:
        """Dispatches JSON alert payload to Slack/Discord/custom webhook."""
        if not self.webhook_url:
            return False
        payload = {
            "text": f"🛡️ *DrillOps Restore Drill Completed*: Status={summary.overall_status}",
            "certificate_id": summary.certificate_id,
            "status": summary.overall_status,
            "restore_time_seconds": summary.restore_duration_sec,
            "backup_file": summary.backup_filename,
            "passed_assertions": summary.passed_assertions,
            "failed_assertions": summary.failed_assertions,
        }
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={"Content-Type": "application/json", "User-Agent": "DrillOps/1.0"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status in (200, 201, 204)
        except Exception as e:
            logger.error(f"Webhook notification failed: {e}")
            return False

    def check_and_run_once(self) -> Optional[DrillSummary]:
        """Checks for latest backup, runs drill if not previously verified, returns summary."""
        with tempfile.TemporaryDirectory(prefix="drillops_fetch_") as fetch_dir:
            try:
                downloaded_file = self.provider.fetch_latest(fetch_dir)
            except FileNotFoundError:
                return None

            file_size, sha256 = ArchiveProcessor.inspect_file(downloaded_file)

            if sha256 in self.processed_hashes:
                # Already verified this exact backup artifact
                return None

            # Configure drill
            self.config.backup_path = downloaded_file
            runner = DrillRunner()
            summary, assertions, artifacts = runner.run_drill(self.config, output_dir=self.output_dir)

            # Record state
            self.processed_hashes.add(sha256)
            self._save_state()

            # Trigger notifications
            if summary.overall_status == "PASSED" and self.heartbeat_url:
                self.ping_heartbeat()

            if self.webhook_url:
                self.notify_webhook(summary, artifacts)

            return summary
