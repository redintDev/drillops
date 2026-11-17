"""Unit and integration tests for DrillOps init configuration wizard."""

import json
import os
import pytest

from drillops.cli import main
from drillops.system.init import ConfigWizard


def test_config_wizard_defaults_postgres():
    cfg = ConfigWizard.generate_config(engine="postgres")
    assert cfg["database_type"] == "postgres"
    assert cfg["host"] == "localhost"
    assert cfg["port"] == 5432
    assert cfg["user"] == "postgres"
    assert cfg["scan_pii"] is True
    assert cfg["max_rpo_hours"] == 24.0
    assert cfg["drop_on_completion"] is True
    assert "users" in cfg["expected_tables"]
    assert len(cfg["assertion_rules"]) == 2
    assert cfg["assertion_rules"][0]["critical"] is True


def test_config_wizard_mysql_and_mariadb():
    cfg_mysql = ConfigWizard.generate_config(engine="mysql")
    assert cfg_mysql["database_type"] == "mysql"
    assert cfg_mysql["port"] == 3306
    assert cfg_mysql["user"] == "root"
    assert "mysql" in cfg_mysql["backup_path"]

    cfg_maria = ConfigWizard.generate_config(engine="mariadb")
    assert cfg_maria["database_type"] == "mariadb"
    assert cfg_maria["port"] == 3306
    assert "mariadb" in cfg_maria["backup_path"]


def test_config_wizard_sqlite():
    cfg = ConfigWizard.generate_config(engine="sqlite")
    assert cfg["database_type"] == "sqlite"
    assert "host" not in cfg
    assert "port" not in cfg
    assert "user" not in cfg
    assert cfg["backup_path"].endswith(".sqlite")


def test_config_wizard_custom_params():
    cfg = ConfigWizard.generate_config(
        engine="postgres",
        backup_path="./custom/path.sql.gz",
        tables=["accounts", "transactions"],
        max_rpo_hours=6.5,
        scan_pii=False,
        output_dir="./custom_certs",
        notify_webhook="https://alerts.example.com/webhook",
        notify_slack="https://hooks.slack.com/services/T00/B00/X00",
    )
    assert cfg["backup_path"] == "./custom/path.sql.gz"
    assert cfg["expected_tables"] == ["accounts", "transactions"]
    assert cfg["max_rpo_hours"] == 6.5
    assert cfg["scan_pii"] is False
    assert cfg["output_dir"] == "./custom_certs"
    assert cfg["notify_webhook"] == "https://alerts.example.com/webhook"
    assert cfg["notify_slack"] == "https://hooks.slack.com/services/T00/B00/X00"
    assert "SELECT count(*) FROM accounts;" in cfg["assertion_rules"][0]["query"]


def test_config_wizard_save_config_and_overwrite(tmp_path):
    out_file = tmp_path / "drillops.config.json"
    cfg = ConfigWizard.generate_config(engine="postgres")

    saved = ConfigWizard.save_config(cfg, str(out_file), overwrite=False)
    assert os.path.exists(saved)

    with open(saved, "r") as f:
        loaded = json.load(f)
    assert loaded["database_type"] == "postgres"

    # Attempting to overwrite without flag should raise FileExistsError
    with pytest.raises(FileExistsError):
        ConfigWizard.save_config(cfg, str(out_file), overwrite=False)

    # With overwrite=True it should succeed
    saved2 = ConfigWizard.save_config(cfg, str(out_file), overwrite=True)
    assert saved2 == saved


def test_config_wizard_save_ci_workflow_github_and_gitlab(tmp_path):
    gh_file = tmp_path / ".github" / "workflows" / "drillops.yml"
    saved_gh = ConfigWizard.save_ci_workflow(
        "github", output_path=str(gh_file), config_path="custom.config.json"
    )
    assert os.path.exists(saved_gh)
    with open(saved_gh, "r") as f:
        content = f.read()
    assert "drillops verify --config custom.config.json" in content
    assert "drillops audit-pack" in content

    gl_file = tmp_path / ".gitlab-ci.yml"
    saved_gl = ConfigWizard.save_ci_workflow(
        "gitlab", output_path=str(gl_file), config_path="custom.config.json"
    )
    assert os.path.exists(saved_gl)
    with open(saved_gl, "r") as f:
        gl_content = f.read()
    assert "drillops verify --config custom.config.json" in gl_content

    with pytest.raises(ValueError):
        ConfigWizard.save_ci_workflow("invalid_ci", output_path=str(tmp_path / "ci.yml"))


def test_cli_init_command_terminal_output(capsys, tmp_path):
    out_file = tmp_path / "init_test.json"
    code = main([
        "init",
        "--engine", "postgres",
        "--out", str(out_file),
    ])
    assert code == 0
    assert os.path.exists(out_file)

    captured = capsys.readouterr()
    assert "DRILLOPS DISASTER RECOVERY CONFIGURATION WIZARD" in captured.out
    assert "postgres" in captured.out
    assert "Generated configuration file" in captured.out


def test_cli_init_command_json_output(capsys, tmp_path):
    out_file = tmp_path / "init_json.json"
    code = main([
        "init",
        "--engine", "mariadb",
        "--tables", "users,orders,audit_logs",
        "--out", str(out_file),
        "--json",
    ])
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["status"] == "success"
    assert data["engine"] == "mariadb"
    assert data["config"]["expected_tables"] == ["users", "orders", "audit_logs"]


def test_cli_init_command_file_conflict(capsys, tmp_path):
    out_file = tmp_path / "existing.json"
    out_file.write_text("{\"existing\": true}")

    code = main([
        "init",
        "--engine", "postgres",
        "--out", str(out_file),
    ])
    assert code == 1
    captured = capsys.readouterr()
    assert "already exists" in captured.err

    # With --force it should succeed
    code_force = main([
        "init",
        "--engine", "postgres",
        "--out", str(out_file),
        "--force",
    ])
    assert code_force == 0
