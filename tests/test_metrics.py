"""Unit and integration tests for DrillOps Prometheus metrics exporter."""

import io
import json
import os
import sys
from unittest.mock import patch
import pytest

from drillops.cli import main
from drillops.monitoring.metrics import PrometheusMetricsExporter


@pytest.fixture
def cert_fixtures(tmp_path):
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()

    # Cert 1: PASSED postgres drill
    cert1 = {
        "certificate_version": "1.0",
        "certificate_id": "DRC-PASS1",
        "timestamp_utc": "2026-10-10T12:00:00.000000+00:00",
        "overall_status": "PASSED",
        "target": {
            "database_type": "postgres",
            "backup_filename": "prod_users.dump",
            "backup_sha256": "1111111111111111",
            "backup_size_bytes": 100000,
        },
        "metrics": {
            "recovery_time_objective_actual_seconds": 0.50,
            "total_assertions": 4,
            "passed_assertions": 4,
            "failed_assertions": 0,
        },
        "failures": [],
        "assertions": [],
    }

    # Cert 2: FAILED postgres drill
    cert2 = {
        "certificate_version": "1.0",
        "certificate_id": "DRC-FAIL1",
        "timestamp_utc": "2026-10-10T13:00:00.000000+00:00",
        "overall_status": "FAILED",
        "target": {
            "database_type": "postgres",
            "backup_filename": "prod_users.dump",
            "backup_sha256": "2222222222222222",
            "backup_size_bytes": 105000,
        },
        "metrics": {
            "recovery_time_objective_actual_seconds": 0.80,
            "total_assertions": 4,
            "passed_assertions": 3,
            "failed_assertions": 1,
        },
        "failures": ["Assertion failed: missing column"],
        "assertions": [],
    }

    # Cert 3: PASSED sqlite drill on another target
    cert3 = {
        "certificate_version": "1.0",
        "certificate_id": "DRC-PASS2",
        "timestamp_utc": "2026-10-10T14:00:00.000000+00:00",
        "overall_status": "PASSED",
        "target": {
            "database_type": "sqlite",
            "backup_filename": "analytics.sqlite",
            "backup_sha256": "3333333333333333",
            "backup_size_bytes": 50000,
        },
        "metrics": {
            "recovery_time_objective_actual_seconds": 0.20,
            "total_assertions": 2,
            "passed_assertions": 2,
            "failed_assertions": 0,
        },
        "failures": [],
        "assertions": [],
    }

    with open(cert_dir / "drill_cert_drc-pass1.json", "w", encoding="utf-8") as f:
        json.dump(cert1, f)
    with open(cert_dir / "drill_cert_drc-fail1.json", "w", encoding="utf-8") as f:
        json.dump(cert2, f)
    with open(cert_dir / "drill_cert_drc-pass2.json", "w", encoding="utf-8") as f:
        json.dump(cert3, f)

    return str(cert_dir)


def test_empty_certificates_dir(tmp_path):
    empty_dir = tmp_path / "empty_certs"
    empty_dir.mkdir()

    exporter = PrometheusMetricsExporter(str(empty_dir))
    data = exporter.collect_metrics()
    assert data["total_drills"] == 0
    assert data["passed_drills"] == 0
    assert data["failed_drills"] == 0
    assert data["pass_ratio"] == 0.0
    assert data["compliance_status"] == 0
    assert data["targets"] == {}

    text = exporter.generate_prometheus_exposition()
    assert "drillops_up 1" in text
    assert "drillops_drills_total 0" in text
    assert "drillops_compliance_status 0" in text


def test_mixed_drill_certificates_aggregation(cert_fixtures):
    exporter = PrometheusMetricsExporter(cert_fixtures)
    data = exporter.collect_metrics()

    assert data["total_drills"] == 3
    assert data["passed_drills"] == 2
    assert data["failed_drills"] == 1
    assert round(data["pass_ratio"], 2) == 0.67
    assert data["compliance_status"] == 0  # not 100% passed
    assert data["total_assertions"] == 10
    assert data["passed_assertions"] == 9
    assert data["failed_assertions"] == 1

    # Targets aggregation
    assert "prod_users.dump" in data["targets"]
    assert "analytics.sqlite" in data["targets"]

    prod_t = data["targets"]["prod_users.dump"]
    assert prod_t["total_drills"] == 2
    assert prod_t["passed_drills"] == 1
    assert prod_t["last_status"] == 0  # last one at 13:00 failed
    assert prod_t["last_rto"] == 0.80

    ana_t = data["targets"]["analytics.sqlite"]
    assert ana_t["total_drills"] == 1
    assert ana_t["passed_drills"] == 1
    assert ana_t["last_status"] == 1
    assert ana_t["last_rto"] == 0.20

    text = exporter.generate_prometheus_exposition()
    assert "drillops_drills_total 3" in text
    assert "drillops_drills_passed_total 2" in text
    assert "drillops_drills_failed_total 1" in text
    assert 'drillops_target_last_drill_status{target="prod_users.dump",database_type="postgres"} 0' in text
    assert 'drillops_target_last_drill_status{target="analytics.sqlite",database_type="sqlite"} 1' in text
    assert 'drillops_target_drills_total{target="prod_users.dump",database_type="postgres"} 2' in text


def test_timestamp_parsing():
    assert PrometheusMetricsExporter.parse_timestamp_to_epoch("") == 0.0
    assert PrometheusMetricsExporter.parse_timestamp_to_epoch(None) == 0.0

    epoch1 = PrometheusMetricsExporter.parse_timestamp_to_epoch("2026-10-10T12:00:00Z")
    assert epoch1 > 1700000000

    epoch2 = PrometheusMetricsExporter.parse_timestamp_to_epoch("2026-10-10 12:00:00 UTC")
    assert epoch1 == epoch2

    epoch3 = PrometheusMetricsExporter.parse_timestamp_to_epoch("2026-10-10 12:00:00")
    assert epoch3 == epoch1


def test_label_escaping():
    raw = 'foo "bar" \\ baz\nqux'
    escaped = PrometheusMetricsExporter._escape_label_value(raw)
    assert '\\"' in escaped
    assert "\\\\" in escaped
    assert "\\n" in escaped


def test_write_metrics_file(cert_fixtures, tmp_path):
    exporter = PrometheusMetricsExporter(cert_fixtures)
    out_file = tmp_path / "metrics" / "drillops.prom"
    exporter.write_metrics_file(str(out_file))

    assert out_file.is_file()
    content = out_file.read_text(encoding="utf-8")
    assert "drillops_drills_total 3" in content


def test_cli_metrics_command(cert_fixtures, tmp_path):
    # Test stdout text
    with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
        code = main(["metrics", "--cert-dir", cert_fixtures])
        assert code == 0
        out_text = mock_out.getvalue()
        assert "drillops_up 1" in out_text
        assert "drillops_drills_total 3" in out_text

    # Test JSON output
    with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
        code = main(["metrics", "--cert-dir", cert_fixtures, "--json"])
        assert code == 0
        data = json.loads(mock_out.getvalue())
        assert data["total_drills"] == 3
        assert data["passed_drills"] == 2

    # Test file output
    out_prom = tmp_path / "out.prom"
    code = main(["metrics", "--cert-dir", cert_fixtures, "--out", str(out_prom)])
    assert code == 0
    assert out_prom.is_file()
    assert "drillops_drills_total 3" in out_prom.read_text(encoding="utf-8")
