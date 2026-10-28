"""Unit and integration tests for DrillOps Recovery Point Objective (RPO) & Backup Freshness Auditor."""

from datetime import datetime, timedelta, timezone
import gzip
import json
import os
import sqlite3
import pytest

from drillops.certifier import CertificateGenerator
from drillops.cli import main
from drillops.core.rpo_auditor import RPOAuditor, RPOReport
from drillops.core.runner import DrillRunner
from drillops.models import VerificationConfig
from drillops.monitoring.metrics import PrometheusMetricsExporter


@pytest.fixture
def fresh_sql_file(tmp_path):
    """Creates a fresh SQL backup with a standard pg_dump header comment from 1 hour ago."""
    dt_str = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    content = f"""--
-- PostgreSQL database dump
--
-- Dumped by pg_dump version 16.1 on {dt_str}
--

CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT);
INSERT INTO users VALUES (1, 'alice@example.com');
"""
    sql_path = tmp_path / "fresh_backup.sql"
    sql_path.write_text(content, encoding="utf-8")
    return str(sql_path)


@pytest.fixture
def stale_sql_file(tmp_path):
    """Creates a stale SQL backup with a header comment from 48 hours ago."""
    dt_str = (datetime.now(timezone.utc) - timedelta(hours=48)).strftime("%Y-%m-%d %H:%M:%S")
    content = f"""--
-- SQLite dump created at {dt_str}
--
CREATE TABLE metrics (id INTEGER PRIMARY KEY, val INTEGER);
INSERT INTO metrics VALUES (1, 100);
"""
    sql_path = tmp_path / "stale_backup.sql"
    sql_path.write_text(content, encoding="utf-8")
    return str(sql_path)


@pytest.fixture
def timestamped_filename_backup(tmp_path):
    """Creates a backup file with an ISO timestamp embedded in the filename."""
    # Filename timestamp 30 hours ago: 2026-10-10T12-00-00
    past_dt = datetime.now(timezone.utc) - timedelta(hours=30)
    ts_part = past_dt.strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"prod_db_{ts_part}.sql"
    content = """
    CREATE TABLE orders (id INTEGER PRIMARY KEY, amount INTEGER);
    INSERT INTO orders VALUES (1, 500);
    """
    sql_path = tmp_path / filename
    sql_path.write_text(content.strip(), encoding="utf-8")
    return str(sql_path)


@pytest.fixture
def gzipped_sql_file(fresh_sql_file, tmp_path):
    """Creates a gzipped version of the fresh SQL file."""
    gz_path = tmp_path / "fresh_backup.sql.gz"
    with open(fresh_sql_file, "rb") as f_in, gzip.open(gz_path, "wb") as f_out:
        f_out.write(f_in.read())
    return str(gz_path)


def test_extract_from_pg_dump_header(fresh_sql_file):
    dt, source = RPOAuditor.extract_backup_timestamp(fresh_sql_file)
    assert source == "sql_header"
    assert isinstance(dt, datetime)
    assert dt.tzinfo is not None
    now = datetime.now(timezone.utc)
    diff_sec = (now - dt).total_seconds()
    # Should be approximately 1 hour (3600s)
    assert 3500 <= diff_sec <= 3700


def test_extract_from_gzipped_header(gzipped_sql_file):
    dt, source = RPOAuditor.extract_backup_timestamp(gzipped_sql_file)
    assert source == "sql_header"
    assert isinstance(dt, datetime)
    assert dt.tzinfo is not None
    now = datetime.now(timezone.utc)
    diff_sec = (now - dt).total_seconds()
    assert 3500 <= diff_sec <= 3700


def test_extract_from_filename_timestamp(timestamped_filename_backup):
    dt, source = RPOAuditor.extract_backup_timestamp(timestamped_filename_backup)
    assert source == "filename"
    assert isinstance(dt, datetime)
    now = datetime.now(timezone.utc)
    diff_hours = (now - dt).total_seconds() / 3600.0
    assert 29.5 <= diff_hours <= 30.5


def test_extract_from_file_mtime(tmp_path):
    plain_file = tmp_path / "plain_database.sql"
    plain_file.write_text("CREATE TABLE t (id INT);", encoding="utf-8")

    dt, source = RPOAuditor.extract_backup_timestamp(str(plain_file))
    assert source == "file_mtime"
    assert isinstance(dt, datetime)
    diff_sec = (datetime.now(timezone.utc) - dt).total_seconds()
    assert diff_sec < 5.0  # Just created seconds ago


def test_audit_rpo_fresh_compliant(fresh_sql_file):
    report = RPOAuditor.audit_rpo(fresh_sql_file, max_rpo_hours=24.0)
    assert report.is_compliant is True
    assert report.status == "COMPLIANT"
    assert 0.9 <= report.backup_age_hours <= 1.1
    assert report.margin_hours is not None
    assert report.margin_hours > 22.0

    assertion = RPOAuditor.evaluate_assertion(report)
    assert assertion.rule_name == "soc2_cc9_1_rpo_freshness"
    assert assertion.passed is True
    assert assertion.error is None


def test_audit_rpo_stale_breached(stale_sql_file):
    report = RPOAuditor.audit_rpo(stale_sql_file, max_rpo_hours=24.0)
    assert report.is_compliant is False
    assert report.status == "BREACHED"
    assert report.backup_age_hours >= 47.0
    assert report.margin_hours < 0

    assertion = RPOAuditor.evaluate_assertion(report)
    assert assertion.rule_name == "soc2_cc9_1_rpo_freshness"
    assert assertion.passed is False
    assert assertion.critical is True
    assert "exceeds threshold" in assertion.error


def test_runner_integration_rpo_compliance(fresh_sql_file, tmp_path):
    runner = DrillRunner()
    cfg = VerificationConfig(
        database_type="sqlite",
        backup_path=fresh_sql_file,
        max_rpo_hours=24.0,
    )
    out_dir = tmp_path / "certs"
    summary, assertions, artifacts = runner.run_drill(cfg, output_dir=str(out_dir))

    assert summary.overall_status == "PASSED"
    assert summary.rpo_status == "COMPLIANT"
    assert summary.rpo_sla_hours == 24.0
    assert summary.backup_age_hours is not None

    rpo_rule = next(a for a in assertions if a.rule_name == "soc2_cc9_1_rpo_freshness")
    assert rpo_rule.passed is True

    # Check generated JSON certificate has RPO block
    with open(artifacts["json"], "r", encoding="utf-8") as f:
        cert_data = json.load(f)
    assert "recovery_point_objective" in cert_data
    assert cert_data["recovery_point_objective"]["rpo_status"] == "COMPLIANT"


def test_runner_integration_rpo_breached(stale_sql_file):
    runner = DrillRunner()
    cfg = VerificationConfig(
        database_type="sqlite",
        backup_path=stale_sql_file,
        max_rpo_hours=24.0,
    )
    summary, assertions, _ = runner.run_drill(cfg)

    assert summary.overall_status == "FAILED"
    assert summary.rpo_status == "BREACHED"
    assert any("soc2_cc9_1_rpo_freshness" in err for err in summary.failure_reasons)

    rpo_rule = next(a for a in assertions if a.rule_name == "soc2_cc9_1_rpo_freshness")
    assert rpo_rule.passed is False


def test_cli_check_rpo_command(fresh_sql_file, stale_sql_file, capsys):
    # Compliant check
    ret_clean = main(["check-rpo", "--backup", fresh_sql_file, "--max-rpo-hours", "24"])
    assert ret_clean == 0
    captured = capsys.readouterr()
    assert "Freshness Status:    ✅ COMPLIANT" in captured.out

    # Breached check
    ret_stale = main(["check-rpo", "--backup", stale_sql_file, "--max-rpo-hours", "24"])
    assert ret_stale == 1
    captured_stale = capsys.readouterr()
    assert "Freshness Status:    🔴 BREACHED" in captured_stale.out

    # JSON output
    ret_json = main(["check-rpo", "--backup", fresh_sql_file, "--max-rpo-hours", "24", "--json"])
    assert ret_json == 0
    captured_json = capsys.readouterr()
    data = json.loads(captured_json.out)
    assert data["is_compliant"] is True
    assert data["status"] == "COMPLIANT"
    assert "backup_age_hours" in data


def test_prometheus_metrics_rpo_export(fresh_sql_file, tmp_path):
    runner = DrillRunner()
    cert_dir = tmp_path / "certs_metrics"
    cfg = VerificationConfig(
        database_type="sqlite",
        backup_path=fresh_sql_file,
        max_rpo_hours=24.0,
    )
    runner.run_drill(cfg, output_dir=str(cert_dir))

    exporter = PrometheusMetricsExporter(certificates_dir=str(cert_dir))
    metrics_text = exporter.generate_prometheus_exposition()

    assert "drillops_target_backup_age_seconds" in metrics_text
    assert "drillops_target_rpo_sla_seconds" in metrics_text
    assert "drillops_target_rpo_breached" in metrics_text
    assert 'drillops_target_rpo_breached{target="fresh_backup.sql",database_type="sqlite"} 0' in metrics_text
