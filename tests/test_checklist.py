"""Unit and integration tests for SOC2 CC9.1 / ISO 27001 Checklist Evaluator."""

import json
import os
import tempfile
import pytest

from drillops.cli import main
from drillops.compliance.checklist import AuditControl, SOC2ChecklistEvaluator


@pytest.fixture
def mock_cert_dir():
    """Creates a temporary directory populated with sample drill certificates."""
    with tempfile.TemporaryDirectory(prefix="test_checklist_certs_") as tmpdir:
        cert1 = {
            "certificate_version": "1.0",
            "certificate_id": "DRC-TEST001",
            "timestamp_utc": "2026-10-10T10:00:00Z",
            "overall_status": "PASSED",
            "metrics": {
                "recovery_time_objective_actual_seconds": 1.2,
                "total_assertions": 4,
                "passed_assertions": 4,
                "failed_assertions": 0,
            },
        }
        cert2 = {
            "certificate_version": "1.0",
            "certificate_id": "DRC-TEST002",
            "timestamp_utc": "2026-10-10T11:00:00Z",
            "overall_status": "PASSED",
            "metrics": {
                "recovery_time_objective_actual_seconds": 0.8,
                "total_assertions": 3,
                "passed_assertions": 3,
                "failed_assertions": 0,
            },
        }
        cert3 = {
            "certificate_version": "1.0",
            "certificate_id": "DRC-TEST003",
            "timestamp_utc": "2026-10-10T12:00:00Z",
            "overall_status": "FAILED",
            "metrics": {
                "recovery_time_objective_actual_seconds": 0.0,
                "total_assertions": 2,
                "passed_assertions": 1,
                "failed_assertions": 1,
            },
        }

        for c in (cert1, cert2, cert3):
            path = os.path.join(tmpdir, f"drill_cert_{c['certificate_id']}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(c, f)

        yield tmpdir


def test_evaluator_no_certs():
    """Verify evaluation behavior without certificate history."""
    evaluator = SOC2ChecklistEvaluator(cert_dir=None)
    controls = evaluator.evaluate(company="TestCorp")

    assert len(controls) == 8
    for c in controls:
        assert isinstance(c, AuditControl)
        assert c.status == "ACTION_REQUIRED"
        assert "TestCorp" in c.details


def test_evaluator_with_certs(mock_cert_dir):
    """Verify evaluation behavior when passing drill certificates are present."""
    evaluator = SOC2ChecklistEvaluator(cert_dir=mock_cert_dir)
    controls = evaluator.evaluate(company="Acme Corp")

    assert len(controls) == 8
    ctrl_map = {c.id: c for c in controls}

    # Core automated verification controls should be COMPLIANT
    for cid in ("DR-03", "DR-04", "DR-05", "DR-06"):
        assert ctrl_map[cid].status == "COMPLIANT"
        assert "Verified: 3 drill(s) executed" in ctrl_map[cid].details
        assert "Avg RTO: 1.0s" in ctrl_map[cid].details  # (1.2 + 0.8) / 2 = 1.0s

    # Tooling / Export controls should be READY
    for cid in ("DR-07", "DR-08"):
        assert ctrl_map[cid].status == "READY"

    # Policy / Generation controls still require external action
    for cid in ("DR-01", "DR-02"):
        assert ctrl_map[cid].status == "ACTION_REQUIRED"


def test_markdown_generation(mock_cert_dir):
    """Verify auditor-ready Markdown export."""
    evaluator = SOC2ChecklistEvaluator(cert_dir=mock_cert_dir)
    md = evaluator.to_markdown(company="FintechSecure")

    assert "# SOC2 CC9.1 & ISO 27001 Disaster Recovery Audit Preparation Checklist" in md
    assert "FintechSecure" in md
    assert "- **Audit Readiness Score**: **75.0%** (6 of 8 Controls Verified)" in md
    assert "DR-01" in md
    assert "DR-04" in md
    assert "🟢 COMPLIANT" in md
    assert "🟡 ACTION_REQUIRED" in md
    assert "## Executive Summary" in md
    assert "## Detailed Control Evidence & Auditor Requirements" in md
    assert "Recommended Next Action" in md


def test_print_terminal(mock_cert_dir, capsys):
    """Verify terminal printing output formatting."""
    evaluator = SOC2ChecklistEvaluator(cert_dir=mock_cert_dir)
    evaluator.print_terminal(company="TerminalTest", use_color=False)
    captured = capsys.readouterr()

    assert "SOC2 CC9.1 & ISO 27001 DISASTER RECOVERY AUDIT CHECKLIST" in captured.out
    assert "Organization:    TerminalTest" in captured.out
    assert "Readiness Score: 75.0% (6/8 controls verified)" in captured.out
    assert "DR-01" in captured.out
    assert "DR-04" in captured.out


def test_cli_checklist_terminal(mock_cert_dir, capsys):
    """Verify 'drillops checklist' command executes with terminal output."""
    ret = main(["checklist", "--cert-dir", mock_cert_dir, "--company", "CLITestCo"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "SOC2 CC9.1 & ISO 27001 DISASTER RECOVERY AUDIT CHECKLIST" in captured.out
    assert "CLITestCo" in captured.out


def test_cli_checklist_json(mock_cert_dir, capsys):
    """Verify 'drillops checklist --json' command outputs valid JSON."""
    ret = main(["checklist", "--cert-dir", mock_cert_dir, "--company", "JSONCo", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    assert len(data) == 8
    assert data[0]["id"] == "DR-01"
    assert data[3]["status"] == "COMPLIANT"


def test_cli_checklist_file_export(mock_cert_dir, tmp_path):
    """Verify 'drillops checklist --out <path>' exports markdown document."""
    out_file = tmp_path / "reports" / "SOC2_DR_CHECKLIST.md"
    ret = main([
        "checklist",
        "--cert-dir", mock_cert_dir,
        "--company", "ExportCo",
        "--out", str(out_file),
    ])
    assert ret == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "ExportCo" in content
    assert "Audit Readiness Score" in content
