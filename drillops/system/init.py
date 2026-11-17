"""Configuration generator and onboarding wizard for DrillOps."""

import json
import os
from typing import Any, Dict, List, Optional


class ConfigWizard:
    """Generates production-grade DrillOps configurations and CI/CD pipelines."""

    ENGINE_DEFAULTS = {
        "postgres": {
            "port": 5432,
            "user": "postgres",
            "host": "localhost",
            "backup_path": "./backups/database_latest.sql.gz",
        },
        "mysql": {
            "port": 3306,
            "user": "root",
            "host": "localhost",
            "backup_path": "./backups/mysql_latest.sql.gz",
        },
        "mariadb": {
            "port": 3306,
            "user": "root",
            "host": "localhost",
            "backup_path": "./backups/mariadb_latest.sql.gz",
        },
        "sqlite": {
            "port": None,
            "user": None,
            "host": None,
            "backup_path": "./backups/database.sqlite",
        },
    }

    DEFAULT_TABLES = ["users", "organizations", "audit_logs"]

    @classmethod
    def generate_config(
        cls,
        engine: str = "postgres",
        backup_path: Optional[str] = None,
        tables: Optional[List[str]] = None,
        max_rpo_hours: float = 24.0,
        scan_pii: bool = True,
        output_dir: str = "./certificates",
        host: Optional[str] = None,
        port: Optional[int] = None,
        user: Optional[str] = None,
        notify_webhook: Optional[str] = None,
        notify_slack: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate a structured DrillOps configuration dictionary."""
        engine_norm = engine.lower()
        defaults = cls.ENGINE_DEFAULTS.get(engine_norm, cls.ENGINE_DEFAULTS["postgres"])

        cfg_backup = backup_path or defaults["backup_path"]
        cfg_tables = tables if tables is not None else list(cls.DEFAULT_TABLES)

        cfg: Dict[str, Any] = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": f"DrillOps Disaster Recovery Verification ({engine_norm.upper()})",
            "database_type": engine_norm,
            "backup_path": cfg_backup,
            "expected_tables": cfg_tables,
            "drop_on_completion": True,
            "scan_pii": scan_pii,
            "max_rpo_hours": max_rpo_hours,
            "output_dir": output_dir,
            "assertion_rules": [
                {
                    "name": "critical_records_present",
                    "query": f"SELECT count(*) FROM {cfg_tables[0] if cfg_tables else 'users'};",
                    "operator": ">=",
                    "expected_value": 1,
                    "critical": True,
                    "description": "Verify core application records restored successfully",
                },
                {
                    "name": "audit_log_traceability",
                    "query": f"SELECT count(*) FROM {cfg_tables[2] if len(cfg_tables) > 2 else 'audit_logs'};",
                    "operator": ">=",
                    "expected_value": 0,
                    "critical": False,
                    "description": "Verify audit log table readiness for SOC 2 CC9.1",
                },
            ],
        }

        if engine_norm != "sqlite":
            cfg["host"] = host or defaults["host"]
            cfg["port"] = port or defaults["port"]
            cfg["user"] = user or defaults["user"]

        if notify_webhook:
            cfg["notify_webhook"] = notify_webhook
        if notify_slack:
            cfg["notify_slack"] = notify_slack

        return cfg

    @classmethod
    def generate_github_workflow(cls, config_path: str = "drillops.config.json") -> str:
        """Generate a turnkey GitHub Actions workflow file for scheduled DR drills."""
        return f"""name: Disaster Recovery Verification Drill

on:
  schedule:
    - cron: '0 3 * * *' # Nightly at 03:00 UTC
  workflow_dispatch:

jobs:
  drillops-verify:
    name: Verify Database Restore SLA & SOC 2 Compliance
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install DrillOps
        run: |
          pip install git+https://github.com/redintDev/drillops.git

      - name: Run Disaster Recovery Verification Drill
        run: |
          drillops verify --config {config_path}

      - name: Generate SOC 2 Evidence Dossier
        if: always()
        run: |
          drillops audit-pack --cert-dir ./certificates --out-zip soc2_audit_pack.zip

      - name: Archive Compliance Dossier Artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: soc2-disaster-recovery-dossier
          path: soc2_audit_pack.zip
          retention-days: 90
"""

    @classmethod
    def generate_gitlab_ci(cls, config_path: str = "drillops.config.json") -> str:
        """Generate a turnkey GitLab CI workflow file for scheduled DR drills."""
        return f"""disaster_recovery_drill:
  stage: test
  image: python:3.12-slim
  before_script:
    - apt-get update && apt-get install -y git postgresql-client default-mysql-client
    - pip install git+https://github.com/redintDev/drillops.git
  script:
    - drillops verify --config {config_path}
    - drillops audit-pack --cert-dir ./certificates --out-zip soc2_audit_pack.zip
  artifacts:
    name: soc2-disaster-recovery-dossier
    when: always
    expire_in: 90 days
    paths:
      - soc2_audit_pack.zip
      - certificates/
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
    - if: $CI_PIPELINE_SOURCE == "web"
"""

    @classmethod
    def save_config(
        cls, config_dict: Dict[str, Any], output_path: str, overwrite: bool = False
    ) -> str:
        """Save configuration dictionary to target path."""
        target = os.path.abspath(output_path)
        if os.path.exists(target) and not overwrite:
            raise FileExistsError(
                f"Configuration file already exists at '{target}'. Use --force to overwrite."
            )
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            json.dump(config_dict, f, indent=2)
        return target

    @classmethod
    def save_ci_workflow(
        cls,
        ci_type: str,
        output_path: Optional[str] = None,
        config_path: str = "drillops.config.json",
        overwrite: bool = False,
    ) -> str:
        """Save CI/CD workflow file for GitHub Actions or GitLab CI."""
        ci_lower = ci_type.lower()
        if ci_lower == "github":
            default_path = os.path.join(".github", "workflows", "drillops.yml")
            content = cls.generate_github_workflow(config_path)
        elif ci_lower == "gitlab":
            default_path = ".gitlab-ci.yml"
            content = cls.generate_gitlab_ci(config_path)
        else:
            raise ValueError(f"Unsupported CI type '{ci_type}'. Choose 'github' or 'gitlab'.")

        target = os.path.abspath(output_path or default_path)
        if os.path.exists(target) and not overwrite:
            raise FileExistsError(
                f"CI workflow file already exists at '{target}'. Use --force to overwrite."
            )
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            f.write(content)
        return target
