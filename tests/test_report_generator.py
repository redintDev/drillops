"""Unit and integration tests for Executive Disaster Recovery Report Generator."""

import json
import os
import tempfile
import pytest

from drillops.compliance.report_generator import ExecutiveReportGenerator
from drillops.models import AssertionResult, DrillSummary


@pytest.fixture
def sample_drill_summary():
    """Generates a passing DrillSummary with all metadata fields populated."""
    return DrillSummary(
        certificate_id="DRC-99AABBCCDDEE",
        timestamp="2026-10-13T06:00:00Z",
        database_type="postgres",
        backup_filename="prod_backup_oct2026.sql.gz",
        backup_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        backup_size_bytes=104857600,
        restore_duration_sec=3.42,
        total_assertions=5,
        passed_assertions=5,
        failed_assertions=0,
        overall_status="PASSED",
        failure_reasons=[],
        encrypted_at_rest=True,
        encryption_type="aes-256-cbc",
        backup_timestamp="2026-10-13T04:30:00Z",
        backup_age_hours=1.5,
        rpo_sla_hours=4.0,
        rpo_status="COMPLIANT",
        redundancy_status="COMPLIANT",
        redundancy_copies_count=3,
        redundancy_media_types_count=2,
        replication_lag_hours=0.25,
        integrity_status="VERIFIED",
        checksum_manifest_verified=True,
    )


@pytest.fixture
def sample_assertions():
    """Sample list of evaluated AssertionResult instances."""
    return [
        AssertionResult(
            rule_name="schema_tables_exist",
            passed=True,
            actual_value=12,
            expected_value=12,
            execution_time_ms=15.4,
            critical=True,
        ),
        AssertionResult(
            rule_name="customer_records_count",
            passed=True,
            actual_value=50000,
            expected_value=1000,
            execution_time_ms=45.2,
            critical=True,
        ),
        AssertionResult(
            rule_name="pii_scan_clean",
            passed=True,
            actual_value="0 leaks",
            expected_value="0 leaks",
            execution_time_ms=22.1,
            critical=False,
        ),
    ]


def test_generate_html_report_from_drill_summary(sample_drill_summary, sample_assertions):
    html = ExecutiveReportGenerator.generate_html_report(
        summary=sample_drill_summary,
        assertions=sample_assertions,
        company_name="Acme Health Corp",
    )

    assert "<!DOCTYPE html>" in html
    assert "DRC-99AABBCCDDEE" in html
    assert "Acme Health Corp" in html
    assert "VERIFIED / SLA COMPLIANT" in html
    assert "3.42s" in html
    assert "POSTGRES" in html
    assert "schema_tables_exist" in html
    assert "customer_records_count" in html
    assert "Chief Information Security Officer" in html
    assert "Lead Systems Engineer" in html
    assert "SOC2 CC9.1" in html
    assert "@media print" in html


def test_generate_html_report_from_dict():
    cert_dict = {
        "certificate_id": "DRC-1234567890AB",
        "timestamp_utc": "2026-10-13T05:00:00Z",
        "overall_status": "FAILED",
        "target": {
            "database_type": "sqlite",
            "backup_filename": "corrupted_archive.db",
            "backup_sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "backup_size_bytes": 4096,
            "encrypted_at_rest": False,
        },
        "metrics": {
            "recovery_time_objective_actual_seconds": 12.5,
            "total_assertions": 2,
            "passed_assertions": 1,
            "failed_assertions": 1,
        },
        "recovery_point_objective": {
            "backup_timestamp": "2026-10-10T00:00:00Z",
            "backup_age_hours": 77.0,
            "rpo_sla_hours": 24.0,
            "rpo_status": "BREACHED",
        },
        "redundancy_and_resilience": {
            "redundancy_status": "321_NON_COMPLIANT",
            "copies_count": 1,
            "media_types_count": 1,
            "integrity_status": "CORRUPT_ARCHIVE",
        },
        "failures": [
            "Assertion orders_non_empty failed: 0 < 100",
            "RPO threshold breached: backup age 77.0h exceeds SLA 24.0h",
        ],
        "assertions": [
            {
                "rule_name": "orders_non_empty",
                "passed": False,
                "actual": "0",
                "expected": "100",
                "duration_ms": 5.0,
                "critical": True,
            }
        ],
    }

    html = ExecutiveReportGenerator.generate_html_report(cert_dict, company_name="Globex Corp")

    assert "DRC-1234567890AB" in html
    assert "COMPLIANCE DEFICIT" in html
    assert "Detected Compliance Deficits &amp; Failures" in html or "Detected Compliance Deficits & Failures" in html
    assert "orders_non_empty" in html
    assert "BREACHED" in html
    assert "Globex Corp" in html


def test_save_report(sample_drill_summary, sample_assertions):
    with tempfile.TemporaryDirectory(prefix="report_test_") as tmpdir:
        out_file = os.path.join(tmpdir, "subdir", "executive_report.html")
        saved_path = ExecutiveReportGenerator.save_report(
            output_path=out_file,
            summary=sample_drill_summary,
            assertions=sample_assertions,
            company_name="Test Enterprise",
        )

        assert os.path.isfile(saved_path)
        assert saved_path == out_file
        with open(saved_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "Test Enterprise" in content
        assert "DRC-99AABBCCDDEE" in content


def test_cli_report_subcommand(sample_drill_summary, sample_assertions):
    from drillops.cli import main

    with tempfile.TemporaryDirectory(prefix="cli_report_test_") as tmpdir:
        cert_json_path = os.path.join(tmpdir, "drill_cert_test.json")
        out_html_path = os.path.join(tmpdir, "drill_cert_test.html")

        cert_data = {
            "certificate_id": sample_drill_summary.certificate_id,
            "timestamp_utc": sample_drill_summary.timestamp,
            "overall_status": sample_drill_summary.overall_status,
            "target": {
                "database_type": sample_drill_summary.database_type,
                "backup_filename": sample_drill_summary.backup_filename,
                "backup_sha256": sample_drill_summary.backup_sha256,
                "backup_size_bytes": sample_drill_summary.backup_size_bytes,
                "encrypted_at_rest": sample_drill_summary.encrypted_at_rest,
                "encryption_type": sample_drill_summary.encryption_type,
            },
            "metrics": {
                "recovery_time_objective_actual_seconds": sample_drill_summary.restore_duration_sec,
                "total_assertions": sample_drill_summary.total_assertions,
                "passed_assertions": sample_drill_summary.passed_assertions,
                "failed_assertions": sample_drill_summary.failed_assertions,
            },
            "failures": [],
            "assertions": [
                {"rule_name": a.rule_name, "passed": a.passed, "actual": str(a.actual_value), "expected": str(a.expected_value), "duration_ms": a.execution_time_ms, "critical": a.critical}
                for a in sample_assertions
            ],
        }

        with open(cert_json_path, "w", encoding="utf-8") as f:
            json.dump(cert_data, f)

        # Execute CLI report command
        code = main(["report", "--cert", cert_json_path, "--out", out_html_path, "--company", "Audit Corp"])
        assert code == 0
        assert os.path.isfile(out_html_path)

        with open(out_html_path, "r", encoding="utf-8") as f:
            html = f.read()
        assert "Audit Corp" in html
        assert "DRC-99AABBCCDDEE" in html
