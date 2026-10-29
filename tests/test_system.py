"""Unit and integration tests for SystemDoctor diagnostics and Systemd generator."""

import json
import os
import shutil
import tempfile
import pytest

from drillops.cli import main
from drillops.system.doctor import DiagnosticCheck, SystemDoctor
from drillops.system.systemd import SystemdServiceGenerator


def test_system_doctor_diagnostics_baseline():
    doc = SystemDoctor()
    checks = doc.run_diagnostics()

    assert len(checks) >= 6
    for c in checks:
        assert isinstance(c, DiagnosticCheck)
        assert c.status in ("PASS", "WARN", "FAIL")

    categories = {c.category for c in checks}
    assert "Environment" in categories
    assert "Database" in categories
    assert "Storage" in categories
    assert "Licensing" in categories

    assert doc.is_healthy(checks) is True


def test_system_doctor_disk_threshold_warning():
    # Force disk threshold to an impossibly high value (100,000 GB)
    doc = SystemDoctor(min_disk_gb=100000.0)
    checks = doc.run_diagnostics()

    disk_check = next(c for c in checks if c.name == "Disk Capacity")
    assert disk_check.status == "WARN"
    assert "Low disk space" in disk_check.message


def test_system_doctor_print_report(capsys):
    doc = SystemDoctor()
    code = doc.print_report(use_color=False)
    assert code == 0

    captured = capsys.readouterr()
    assert "DRILLOPS SYSTEM DOCTOR & PRE-FLIGHT READINESS INSPECTOR" in captured.out
    assert "Overall Status: HEALTHY" in captured.out


def test_systemd_generator_default():
    unit = SystemdServiceGenerator.generate_service_unit()
    assert "[Unit]" in unit
    assert "[Service]" in unit
    assert "[Install]" in unit
    assert "WantedBy=multi-user.target" in unit
    assert "Restart=always" in unit
    assert "watch --dir /var/backups --type postgres" in unit


def test_systemd_generator_custom_args():
    unit = SystemdServiceGenerator.generate_service_unit(
        executable="/usr/local/bin/drillops",
        working_dir="/var/drillops",
        user="drillops_user",
        command_args="serve --port 8787",
        env_vars={"DRILLOPS_ENV": "production", "PORT": "8787"},
    )
    assert "User=drillops_user" in unit
    assert "WorkingDirectory=/var/drillops" in unit
    assert "ExecStart=/usr/local/bin/drillops serve --port 8787" in unit
    assert 'Environment="DRILLOPS_ENV=production"' in unit
    assert 'Environment="PORT=8787"' in unit


def test_cli_doctor_terminal(capsys):
    ret = main(["doctor"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "DRILLOPS SYSTEM DOCTOR" in captured.out
    assert "Overall Status: HEALTHY" in captured.out


def test_cli_doctor_json(capsys):
    ret = main(["doctor", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["healthy"] is True
    assert isinstance(data["checks"], list)
    assert len(data["checks"]) >= 6


def test_cli_systemd_stdout(capsys):
    ret = main(["systemd", "--cmd", "orchestrate --config targets.json"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "[Unit]" in captured.out
    assert "orchestrate --config targets.json" in captured.out


def test_cli_systemd_file_export(tmp_path):
    out_file = tmp_path / "services" / "drillops.service"
    ret = main([
        "systemd",
        "--user", "deploy",
        "--dir", "/srv/drillops",
        "--cmd", "serve --port 9000",
        "--out", str(out_file),
    ])
    assert ret == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "User=deploy" in content
    assert "WorkingDirectory=/srv/drillops" in content
    assert "serve --port 9000" in content


def test_cli_verify_with_s3_uri(tmp_path, monkeypatch):
    import sqlite3
    from drillops.storage.providers import S3CompatibleStorageProvider

    # Create dummy sqlite db
    dummy_db = tmp_path / "cloud_backup.sqlite"
    conn = sqlite3.connect(str(dummy_db))
    conn.execute("CREATE TABLE products (id INT PRIMARY KEY, name TEXT);")
    conn.execute("INSERT INTO products VALUES (1, 'Widget');")
    conn.commit()
    conn.close()

    def fake_download_object(self, object_key, destination_dir):
        dest = os.path.join(destination_dir, "cloud_backup.sqlite")
        shutil.copy2(str(dummy_db), dest)
        return dest

    monkeypatch.setattr(S3CompatibleStorageProvider, "download_object", fake_download_object)

    cert_dir = tmp_path / "s3_certs"
    ret = main([
        "verify",
        "--backup", "s3://prod-backups/databases/cloud_backup.sqlite",
        "--type", "sqlite",
        "--tables", "products",
        "--out", str(cert_dir),
    ])
    assert ret == 0
    assert any(f.name.endswith(".md") for f in cert_dir.glob("*.md"))
    assert any(f.name.endswith(".json") for f in cert_dir.glob("*.json"))


def test_cli_watch_with_s3_uri(tmp_path, monkeypatch):
    import sqlite3
    from drillops.storage.providers import S3CompatibleStorageProvider, BackupMetadata

    dummy_db = tmp_path / "daily_snapshot.sqlite"
    conn = sqlite3.connect(str(dummy_db))
    conn.execute("CREATE TABLE metrics (id INT PRIMARY KEY);")
    conn.commit()
    conn.close()

    def fake_list_backups(self):
        return [
            BackupMetadata(
                filename="daily_snapshot.sqlite",
                source_uri="s3://cloud-vault/daily_snapshot.sqlite",
                size_bytes=dummy_db.stat().st_size,
                modified_timestamp=1700000000.0,
                storage_type="s3",
            )
        ]

    def fake_download_object(self, object_key, destination_dir):
        dest = os.path.join(destination_dir, "daily_snapshot.sqlite")
        shutil.copy2(str(dummy_db), dest)
        return dest

    monkeypatch.setattr(S3CompatibleStorageProvider, "list_backups", fake_list_backups)
    monkeypatch.setattr(S3CompatibleStorageProvider, "download_object", fake_download_object)

    cert_dir = tmp_path / "watch_certs"
    ret = main([
        "watch",
        "--dir", "s3://cloud-vault/backups",
        "--type", "sqlite",
        "--once",
        "--out", str(cert_dir),
    ])
    assert ret == 0


def test_cli_version(capsys):
    import pytest
    from drillops import __version__
    from drillops.cli import main
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert f"drillops {__version__}" in captured.out


