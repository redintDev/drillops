"""Unit tests for DrillOps embedded HTTP server and compliance API."""

import json
import threading
import time
import urllib.request
import pytest

from drillops.models import DrillSummary
from drillops.server.app import run_dashboard_server


@pytest.fixture
def running_server(tmp_path):
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()

    # Seed a sample certificate
    sample_cert = {
        "certificate_version": "1.0",
        "certificate_id": "DRC-TEST123456",
        "timestamp_utc": "2026-10-09T00:00:00.000000+00:00",
        "overall_status": "PASSED",
        "target": {
            "database_type": "postgres",
            "backup_filename": "prod_backup.dump",
            "backup_sha256": "abc1234567890",
            "backup_size_bytes": 1048576,
        },
        "metrics": {
            "recovery_time_objective_actual_seconds": 1.45,
            "total_assertions": 5,
            "passed_assertions": 5,
            "failed_assertions": 0,
        },
        "failures": [],
        "assertions": [],
    }
    with open(cert_dir / "drill_cert_drc-test123456.json", "w") as f:
        json.dump(sample_cert, f)

    with open(cert_dir / "drill_cert_drc-test123456.md", "w") as f:
        f.write("# Disaster Recovery Drill Certificate\nID: DRC-TEST123456\nStatus: PASSED")

    server = run_dashboard_server(host="127.0.0.1", port=0, cert_dir=str(cert_dir))
    allocated_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.05)

    yield f"http://127.0.0.1:{allocated_port}"

    server.shutdown()
    server.server_close()


def test_api_status_endpoint(running_server):
    with urllib.request.urlopen(f"{running_server}/api/status") as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["compliance_status"] == "COMPLIANT"
        assert data["total_drills"] == 1
        assert data["passed_drills"] == 1
        assert data["pass_rate_percent"] == 100.0
        assert data["average_rto_seconds"] == 1.45


def test_api_certificates_endpoint(running_server):
    with urllib.request.urlopen(f"{running_server}/api/certificates") as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert len(data["certificates"]) == 1
        assert data["certificates"][0]["certificate_id"] == "DRC-TEST123456"


def test_api_markdown_endpoint(running_server):
    with urllib.request.urlopen(f"{running_server}/api/certificates/drc-test123456/markdown") as resp:
        assert resp.status == 200
        content = resp.read().decode("utf-8")
        assert "DRC-TEST123456" in content


def test_dashboard_html_endpoint(running_server):
    with urllib.request.urlopen(f"{running_server}/dashboard") as resp:
        assert resp.status == 200
        html = resp.read().decode("utf-8")
        assert "DrillOps" in html
        assert "DRC-TEST123456" in html
        assert "SOC2 AUDIT READY" in html


def test_api_badge_svg_endpoint(running_server):
    with urllib.request.urlopen(f"{running_server}/api/badge.svg") as resp:
        assert resp.status == 200
        assert resp.headers.get("Content-Type") == "image/svg+xml"
        svg = resp.read().decode("utf-8")
        assert svg.startswith("<svg")
        assert "SOC2 CC9.1 PASS" in svg


def test_api_badge_shields_endpoint(running_server):
    with urllib.request.urlopen(f"{running_server}/api/badge/shields.json") as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["label"] == "DR Verified"
        assert "SOC2 CC9.1 PASS" in data["message"]
        assert data["color"] == "brightgreen"


def test_api_checklist_endpoint(running_server):
    with urllib.request.urlopen(f"{running_server}/api/checklist?company=AcmeCorp") as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["company"] == "AcmeCorp"
        assert data["total_controls"] == 8
        assert data["verified_controls"] >= 4


def test_api_lead_capture_lifecycle(running_server):
    # Test POST /api/leads
    payload = json.dumps({
        "type": "purchase_inquiry",
        "email": "lead@acme.com",
        "company": "Acme Corp",
        "tier": "enterprise",
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{running_server}/api/leads",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 201
        data = json.loads(resp.read().decode("utf-8"))
        assert data["status"] == "success"
        assert "lead_id" in data

    # Test GET /api/leads
    with urllib.request.urlopen(f"{running_server}/api/leads") as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["total_leads"] >= 1
        assert any(l["email"] == "lead@acme.com" for l in data["leads"])


def test_api_metrics_endpoint(running_server):
    with urllib.request.urlopen(f"{running_server}/metrics") as resp:
        assert resp.status == 200
        assert "text/plain" in resp.headers.get("Content-Type")
        body = resp.read().decode("utf-8")
        assert "drillops_up 1" in body
        assert "drillops_drills_total 1" in body
        assert "drillops_drills_passed_total 1" in body
        assert "drillops_compliance_status 1" in body
        assert 'drillops_target_last_drill_status{target="prod_backup.dump",database_type="postgres"} 1' in body

    # Also test /api/metrics alias
    with urllib.request.urlopen(f"{running_server}/api/metrics") as resp:
        assert resp.status == 200
        body = resp.read().decode("utf-8")
        assert "drillops_up 1" in body

