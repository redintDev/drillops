"""Unit and integration tests for SOC2 / ISO 27001 Audit Pack generation."""

import json
import os
import tempfile
import zipfile
import pytest

from drillops.compliance.audit_pack import AuditPackGenerator, ComplianceMetrics
from drillops.models import DrillSummary


@pytest.fixture
def sample_cert_dir():
    """Creates a temporary directory with mock drill certificates."""
    with tempfile.TemporaryDirectory(prefix="test_certs_") as tmpdir:
        cert1 = {
            "certificate_version": "1.0",
            "certificate_id": "DRC-AAAA11112222",
            "timestamp_utc": "2026-10-08T10:00:00Z",
            "overall_status": "PASSED",
            "target": {
                "database_type": "postgres",
                "backup_filename": "prod_backup_1.sql.gz",
                "backup_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "backup_size_bytes": 1048576,
            },
            "metrics": {
                "recovery_time_objective_actual_seconds": 1.25,
                "total_assertions": 4,
                "passed_assertions": 4,
                "failed_assertions": 0,
            },
            "failures": [],
            "assertions": [
                {"rule_name": "table_users_exists", "passed": True, "critical": True},
                {"rule_name": "user_count_gt_0", "passed": True, "critical": True},
            ],
        }

        cert2 = {
            "certificate_version": "1.0",
            "certificate_id": "DRC-BBBB33334444",
            "timestamp_utc": "2026-10-09T08:00:00Z",
            "overall_status": "PASSED",
            "target": {
                "database_type": "sqlite",
                "backup_filename": "local_sqlite.db",
                "backup_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "backup_size_bytes": 524288,
            },
            "metrics": {
                "recovery_time_objective_actual_seconds": 0.45,
                "total_assertions": 3,
                "passed_assertions": 3,
                "failed_assertions": 0,
            },
            "failures": [],
            "assertions": [
                {"rule_name": "table_orders_exists", "passed": True, "critical": True},
            ],
        }

        with open(os.path.join(tmpdir, "drill_cert_drc-aaaa11112222.json"), "w") as f:
            json.dump(cert1, f)

        with open(os.path.join(tmpdir, "drill_cert_drc-bbbb33334444.json"), "w") as f:
            json.dump(cert2, f)

        yield tmpdir


def test_load_certificates(sample_cert_dir):
    generator = AuditPackGenerator(sample_cert_dir)
    certs = generator.load_certificates()

    assert len(certs) == 2
    c_ids = [c["certificate_id"] for c in certs]
    assert "DRC-AAAA11112222" in c_ids
    assert "DRC-BBBB33334444" in c_ids
    assert "_cert_sha256" in certs[0]


def test_calculate_metrics(sample_cert_dir):
    generator = AuditPackGenerator(sample_cert_dir)
    certs = generator.load_certificates()
    metrics = generator.calculate_metrics(certs)

    assert metrics.total_drills == 2
    assert metrics.passed_drills == 2
    assert metrics.failed_drills == 0
    assert metrics.success_rate_pct == 100.0
    assert metrics.avg_rto_seconds == round((1.25 + 0.45) / 2, 4)
    assert metrics.max_rto_seconds == 1.25
    assert metrics.min_rto_seconds == 0.45
    assert metrics.total_assertions == 7
    assert "postgres" in metrics.database_types
    assert "sqlite" in metrics.database_types


def test_generate_markdown_dossier(sample_cert_dir):
    generator = AuditPackGenerator(sample_cert_dir)
    certs = generator.load_certificates()
    metrics = generator.calculate_metrics(certs)
    md = generator.generate_markdown_dossier(metrics, certs, company_name="Acme Global")

    assert "# 📋 SOC2 Type II & ISO 27001 Backup Restoration Audit Dossier" in md
    assert "Acme Global" in md
    assert "DRC-AAAA11112222" in md
    assert "DRC-BBBB33334444" in md
    assert "100.0%" in md


def test_generate_html_dossier(sample_cert_dir):
    generator = AuditPackGenerator(sample_cert_dir)
    certs = generator.load_certificates()
    metrics = generator.calculate_metrics(certs)
    html = generator.generate_html_dossier(metrics, certs, company_name="Acme Global")

    assert "<!DOCTYPE html>" in html
    assert "Acme Global" in html
    assert "DRC-AAAA11112222" in html
    assert "VERIFIED / SLA COMPLIANT" in html


def test_export_pack_zip(sample_cert_dir):
    generator = AuditPackGenerator(sample_cert_dir)
    with tempfile.TemporaryDirectory() as outdir:
        zip_path = os.path.join(outdir, "test_audit_pack.zip")
        res = generator.export_pack_zip(zip_path, company_name="Acme Global")

        assert os.path.isfile(res)
        with zipfile.ZipFile(res, "r") as zf:
            namelist = zf.namelist()
            assert "AUDIT_DOSSIER.md" in namelist
            assert "AUDIT_DOSSIER.html" in namelist
            assert "manifest.json" in namelist
            assert any(n.startswith("certificates/drill_cert_") for n in namelist)

            manifest_data = json.loads(zf.read("manifest.json").decode("utf-8"))
            assert manifest_data["organization"] == "Acme Global"
            assert manifest_data["metrics"]["total_drills"] == 2
