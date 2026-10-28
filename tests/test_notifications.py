"""Unit tests for DrillOps multi-channel notification dispatcher."""

import hashlib
import hmac
import http.server
import json
import socketserver
import threading
from typing import List, Tuple
import pytest

from drillops.models import DrillSummary
from drillops.notifications import (
    NotificationConfig,
    NotificationDispatcher,
)


class MockWebhookServer:
    """Threaded mock HTTP server that logs received requests."""

    def __init__(self):
        self.received_requests: List[Tuple[str, dict, dict]] = []
        server_instance = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_POST(self):
                content_len = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_len).decode("utf-8")
                try:
                    payload = json.loads(body)
                except Exception:
                    payload = {"raw": body}

                headers_dict = {k: v for k, v in self.headers.items()}
                server_instance.received_requests.append((self.path, headers_dict, payload))

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')

        class ReusableServer(socketserver.TCPServer):
            allow_reuse_address = True

        self.server = ReusableServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}/webhook"


@pytest.fixture
def mock_webhook():
    srv = MockWebhookServer()
    srv.start()
    yield srv
    srv.stop()


@pytest.fixture
def sample_summary():
    return DrillSummary(
        certificate_id="DRC-NOTIFTEST01",
        timestamp="2026-10-09T12:00:00Z",
        database_type="postgres",
        backup_filename="prod_data.dump",
        backup_sha256="abc123def456",
        backup_size_bytes=1048576,
        restore_duration_sec=0.25,
        total_assertions=4,
        passed_assertions=4,
        failed_assertions=0,
        overall_status="PASSED",
    )


def test_send_generic_webhook(mock_webhook, sample_summary):
    secret = "my-secret-key"
    cfg = NotificationConfig(webhook_secret=secret)
    dispatcher = NotificationDispatcher(cfg)

    res = dispatcher.send_generic_webhook(mock_webhook.url, sample_summary, [])

    assert res.success is True
    assert res.status_code == 200
    assert len(mock_webhook.received_requests) == 1

    path, headers, payload = mock_webhook.received_requests[0]
    assert payload["event"] == "restore_drill.completed"
    assert payload["certificate_id"] == "DRC-NOTIFTEST01"
    assert payload["status"] == "PASSED"
    assert "X-Drillops-Signature" in headers

    # Verify HMAC signature
    sig_header = headers["X-Drillops-Signature"]
    assert sig_header.startswith("sha256=")
    expected_hash = sig_header.split("=")[1]
    raw_payload_bytes = json.dumps(payload).encode("utf-8")
    calc_sig = hmac.new(secret.encode("utf-8"), raw_payload_bytes, hashlib.sha256).hexdigest()
    assert expected_hash == calc_sig


def test_send_slack(mock_webhook, sample_summary):
    dispatcher = NotificationDispatcher()
    res = dispatcher.send_slack(mock_webhook.url, sample_summary)

    assert res.success is True
    assert len(mock_webhook.received_requests) == 1

    path, headers, payload = mock_webhook.received_requests[0]
    assert "RESTORE DRILL PASSED" in payload["text"]
    assert payload["attachments"][0]["color"] == "#10B981"


def test_send_discord(mock_webhook, sample_summary):
    dispatcher = NotificationDispatcher()
    res = dispatcher.send_discord(mock_webhook.url, sample_summary)

    assert res.success is True
    assert len(mock_webhook.received_requests) == 1

    path, headers, payload = mock_webhook.received_requests[0]
    assert len(payload["embeds"]) == 1
    assert payload["embeds"][0]["color"] == 0x10B981
    assert "PASSED" in payload["embeds"][0]["title"]


def test_notification_connection_failure():
    dispatcher = NotificationDispatcher(NotificationConfig(timeout_sec=0.5))
    # Unreachable port
    res = dispatcher.send_generic_webhook("http://127.0.0.1:59999/unreachable", DrillSummary.create_new("sqlite", "f.db", "sha", 100), [])

    assert res.success is False
    assert res.error is not None


def test_dispatch_all(mock_webhook, sample_summary):
    cfg = NotificationConfig(
        webhook_url=mock_webhook.url,
        slack_webhook_url=mock_webhook.url,
        discord_webhook_url=mock_webhook.url,
        pagerduty_routing_key=mock_webhook.url,
        vanta_webhook_url=mock_webhook.url,
        drata_webhook_url=mock_webhook.url,
        notify_on_pass=True,
    )
    dispatcher = NotificationDispatcher(cfg)
    results = dispatcher.dispatch_all(sample_summary, [])

    assert len(results) == 6
    assert all(r.success for r in results)
    assert len(mock_webhook.received_requests) == 6


def test_send_vanta_passed_and_failed(mock_webhook, sample_summary):
    dispatcher = NotificationDispatcher()

    # Test PASSED
    res_pass = dispatcher.send_vanta(mock_webhook.url, sample_summary)
    assert res_pass.success is True
    assert res_pass.channel == "vanta"

    path, headers, payload = mock_webhook.received_requests[-1]
    assert payload["testStatus"] == "PASSED"
    assert payload["control"] == "SOC2 CC9.1"
    assert payload["metadata"]["certificate_id"] == "DRC-NOTIFTEST01"
    assert payload["metadata"]["database_type"] == "postgres"
    assert "DrillOps Autonomous DR Engine" in payload["evidence"]

    # Test FAILED
    sample_summary.overall_status = "FAILED"
    sample_summary.failure_reasons = ["Checksum mismatch"]
    res_fail = dispatcher.send_vanta(mock_webhook.url, sample_summary)
    assert res_fail.success is True

    path2, headers2, payload2 = mock_webhook.received_requests[-1]
    assert payload2["testStatus"] == "FAILED"


def test_send_drata_passed_and_failed(mock_webhook, sample_summary):
    dispatcher = NotificationDispatcher()

    # Test PASSED
    res_pass = dispatcher.send_drata(mock_webhook.url, sample_summary)
    assert res_pass.success is True
    assert res_pass.channel == "drata"

    path, headers, payload = mock_webhook.received_requests[-1]
    assert payload["status"] == "PASSED"
    assert payload["controlIdentifier"] == "DR-01"
    assert payload["standard"] == "SOC2 CC9.1 / ISO 27001 A.12.3.1"
    assert payload["evidenceSummary"]["certificateId"] == "DRC-NOTIFTEST01"
    assert "DrillOps verification outcome: PASSED" in payload["outcomeDetails"]

    # Test FAILED
    sample_summary.overall_status = "FAILED"
    res_fail = dispatcher.send_drata(mock_webhook.url, sample_summary)
    assert res_fail.success is True

    path2, headers2, payload2 = mock_webhook.received_requests[-1]
    assert payload2["status"] == "FAILED"


def test_send_pagerduty(mock_webhook, sample_summary):
    dispatcher = NotificationDispatcher()
    res = dispatcher.send_pagerduty(mock_webhook.url, sample_summary)
    assert res.success is True
    assert res.channel == "pagerduty"

    path, headers, payload = mock_webhook.received_requests[-1]
    assert payload["event_action"] == "resolve"
    assert payload["payload"]["severity"] == "info"
    assert payload["dedup_key"] == f"drillops-{sample_summary.backup_filename}"
    assert payload["payload"]["custom_details"]["certificate_id"] == "DRC-NOTIFTEST01"


def test_notification_config_from_dict_and_env(monkeypatch):
    data = {
        "vanta_webhook_url": "https://api.vanta.com/v1/custom_tests/test-1/upload",
        "drata_webhook_url": "https://public-api.drata.com/public/compliance/tests/dr-01",
        "notify_on_pass": False,
        "notify_on_fail": True,
        "timeout_sec": 7.5,
    }
    cfg = NotificationConfig.from_env_or_dict(data)
    assert cfg.vanta_webhook_url == "https://api.vanta.com/v1/custom_tests/test-1/upload"
    assert cfg.drata_webhook_url == "https://public-api.drata.com/public/compliance/tests/dr-01"
    assert cfg.notify_on_pass is False
    assert cfg.timeout_sec == 7.5

    # Test env fallback
    monkeypatch.setenv("DRILLOPS_VANTA_WEBHOOK", "https://api.vanta.com/env-test")
    monkeypatch.setenv("DRILLOPS_DRATA_WEBHOOK", "https://public-api.drata.com/env-test")
    cfg2 = NotificationConfig.from_env_or_dict({})
    assert cfg2.vanta_webhook_url == "https://api.vanta.com/env-test"
    assert cfg2.drata_webhook_url == "https://public-api.drata.com/env-test"

