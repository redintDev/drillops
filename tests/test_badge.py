"""Unit and integration tests for ComplianceBadgeGenerator and CLI badge command."""

import json
import os
import tempfile
import pytest

from drillops.cli import main
from drillops.compliance.badge import ComplianceBadgeGenerator


@pytest.fixture
def mock_cert_dir_passed():
    """Temporary directory with passing drill certificates."""
    with tempfile.TemporaryDirectory(prefix="test_badge_passed_") as tmpdir:
        cert = {
            "certificate_version": "1.0",
            "certificate_id": "DRC-PASS001",
            "overall_status": "PASSED",
            "metrics": {
                "recovery_time_objective_actual_seconds": 0.162,
                "total_assertions": 3,
                "passed_assertions": 3,
                "failed_assertions": 0,
            },
        }
        with open(os.path.join(tmpdir, "drill_cert_pass001.json"), "w", encoding="utf-8") as f:
            json.dump(cert, f)
        yield tmpdir


@pytest.fixture
def mock_cert_dir_failing():
    """Temporary directory with a failed drill certificate."""
    with tempfile.TemporaryDirectory(prefix="test_badge_failed_") as tmpdir:
        cert = {
            "certificate_version": "1.0",
            "certificate_id": "DRC-FAIL001",
            "overall_status": "FAILED",
            "metrics": {
                "recovery_time_objective_actual_seconds": 0.0,
                "total_assertions": 3,
                "passed_assertions": 1,
                "failed_assertions": 2,
            },
        }
        with open(os.path.join(tmpdir, "drill_cert_fail001.json"), "w", encoding="utf-8") as f:
            json.dump(cert, f)
        yield tmpdir


def test_badge_status_no_data():
    gen = ComplianceBadgeGenerator(cert_dir=None)
    status = gen.get_badge_status()
    assert status["message"] == "NO DATA"
    assert status["color"] == "#6b7280"
    assert status["compliant"] is False
    assert status["total_drills"] == 0


def test_badge_status_compliant(mock_cert_dir_passed):
    gen = ComplianceBadgeGenerator(cert_dir=mock_cert_dir_passed)
    status = gen.get_badge_status()
    assert "SOC2 CC9.1 PASS" in status["message"]
    assert "0.162s RTO" in status["message"]
    assert status["color"] == "#10b981"
    assert status["shields_color"] == "brightgreen"
    assert status["compliant"] is True
    assert status["total_drills"] == 1


def test_badge_status_failing(mock_cert_dir_failing):
    gen = ComplianceBadgeGenerator(cert_dir=mock_cert_dir_failing)
    status = gen.get_badge_status()
    assert status["message"] == "0/1 PASSED"
    assert status["color"] == "#ef4444"
    assert status["shields_color"] == "red"
    assert status["compliant"] is False


def test_badge_generate_svg(mock_cert_dir_passed):
    gen = ComplianceBadgeGenerator(cert_dir=mock_cert_dir_passed)
    svg = gen.generate_svg()
    assert svg.startswith("<svg")
    assert svg.endswith("</svg>")
    assert 'aria-label="DR Verified:' in svg
    assert "#10b981" in svg
    assert "SOC2 CC9.1 PASS" in svg


def test_badge_generate_shields_json(mock_cert_dir_passed):
    gen = ComplianceBadgeGenerator(cert_dir=mock_cert_dir_passed)
    payload = gen.generate_shields_json()
    assert payload["schemaVersion"] == 1
    assert payload["label"] == "DR Verified"
    assert "SOC2 CC9.1 PASS" in payload["message"]
    assert payload["color"] == "brightgreen"


def test_badge_markdown_embed(mock_cert_dir_passed):
    gen = ComplianceBadgeGenerator(cert_dir=mock_cert_dir_passed)
    md = gen.generate_markdown(badge_path="https://example.com/badge.svg", target_url="https://drillops.dev")
    assert md == "[![DrillOps DR Verified](https://example.com/badge.svg)](https://drillops.dev)"


def test_cli_badge_stdout_svg(mock_cert_dir_passed, capsys):
    ret = main(["badge", "--cert-dir", mock_cert_dir_passed])
    assert ret == 0
    captured = capsys.readouterr()
    assert "<svg" in captured.out
    assert "SOC2 CC9.1 PASS" in captured.out


def test_cli_badge_file_output(mock_cert_dir_passed, tmp_path):
    out_badge = tmp_path / "compliance_badge.svg"
    ret = main(["badge", "--cert-dir", mock_cert_dir_passed, "--out", str(out_badge)])
    assert ret == 0
    assert out_badge.exists()
    content = out_badge.read_text(encoding="utf-8")
    assert "<svg" in content
    assert "#10b981" in content


def test_cli_badge_shields_json(mock_cert_dir_passed, capsys):
    ret = main(["badge", "--cert-dir", mock_cert_dir_passed, "--shields-json"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["schemaVersion"] == 1
    assert data["label"] == "DR Verified"
    assert data["color"] == "brightgreen"


def test_cli_badge_markdown(mock_cert_dir_passed, capsys):
    ret = main(["badge", "--cert-dir", mock_cert_dir_passed, "--markdown", "--out", "./assets/badge.svg"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "[![DrillOps DR Verified](./assets/badge.svg)](https://drillops.dev)" in captured.out
