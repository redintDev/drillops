"""Pluggable notification and alert dispatcher for DrillOps restore drill results."""

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from drillops.models import AssertionResult, DrillSummary


@dataclass
class NotificationConfig:
    """Notification endpoints and credential routing configuration."""
    webhook_url: Optional[str] = None
    webhook_secret: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    discord_webhook_url: Optional[str] = None
    pagerduty_routing_key: Optional[str] = None
    vanta_webhook_url: Optional[str] = None
    drata_webhook_url: Optional[str] = None
    notify_on_pass: bool = True
    notify_on_fail: bool = True
    timeout_sec: float = 5.0

    @classmethod
    def from_env_or_dict(cls, data: Optional[Dict[str, Any]] = None) -> "NotificationConfig":
        """Instantiates configuration merging optional dictionary with environment variables."""
        cfg = data or {}
        return cls(
            webhook_url=cfg.get("webhook_url") or os.environ.get("DRILLOPS_WEBHOOK_URL"),
            webhook_secret=cfg.get("webhook_secret") or os.environ.get("DRILLOPS_WEBHOOK_SECRET"),
            slack_webhook_url=cfg.get("slack_webhook_url") or os.environ.get("DRILLOPS_SLACK_WEBHOOK"),
            discord_webhook_url=cfg.get("discord_webhook_url") or os.environ.get("DRILLOPS_DISCORD_WEBHOOK"),
            pagerduty_routing_key=cfg.get("pagerduty_routing_key") or os.environ.get("DRILLOPS_PAGERDUTY_KEY"),
            vanta_webhook_url=cfg.get("vanta_webhook_url") or os.environ.get("DRILLOPS_VANTA_WEBHOOK"),
            drata_webhook_url=cfg.get("drata_webhook_url") or os.environ.get("DRILLOPS_DRATA_WEBHOOK"),
            notify_on_pass=cfg.get("notify_on_pass", True),
            notify_on_fail=cfg.get("notify_on_fail", True),
            timeout_sec=float(cfg.get("timeout_sec", 5.0)),
        )


@dataclass
class NotificationResult:
    """Record of a dispatched notification attempt."""
    channel: str
    target_url: str
    success: bool
    status_code: Optional[int] = None
    error: Optional[str] = None


class NotificationDispatcher:
    """Dispatches drill result notifications across multiple channels."""

    def __init__(self, config: Optional[NotificationConfig] = None):
        self.config = config or NotificationConfig.from_env_or_dict()

    def _post_json(self, url: str, payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> int:
        """Sends a JSON HTTP POST request with configurable headers."""
        data_bytes = json.dumps(payload).encode("utf-8")
        req_headers = {"Content-Type": "application/json", "User-Agent": "DrillOps-Notifier/1.0"}
        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(url, data=data_bytes, headers=req_headers, method="POST")
        with urllib.request.urlopen(req, timeout=self.config.timeout_sec) as resp:
            return resp.status

    def send_generic_webhook(self, url: str, summary: DrillSummary, assertions: List[AssertionResult]) -> NotificationResult:
        """Sends a structured DrillOps payload to a generic HTTP webhook."""
        payload = {
            "event": "restore_drill.completed",
            "certificate_id": summary.certificate_id,
            "timestamp": summary.timestamp,
            "status": summary.overall_status,
            "target": {
                "database_type": summary.database_type,
                "backup_filename": summary.backup_filename,
                "backup_sha256": summary.backup_sha256,
                "backup_size_bytes": summary.backup_size_bytes,
            },
            "metrics": {
                "restore_duration_sec": summary.restore_duration_sec,
                "total_assertions": summary.total_assertions,
                "passed_assertions": summary.passed_assertions,
                "failed_assertions": summary.failed_assertions,
            },
            "failures": summary.failure_reasons,
        }

        headers = {
            "X-DrillOps-Event": "restore_drill.completed",
            "X-DrillOps-Status": summary.overall_status,
            "X-DrillOps-Cert": summary.certificate_id,
        }

        if self.config.webhook_secret:
            raw_body = json.dumps(payload).encode("utf-8")
            sig = hmac.new(self.config.webhook_secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
            headers["X-DrillOps-Signature"] = f"sha256={sig}"

        try:
            status = self._post_json(url, payload, headers=headers)
            return NotificationResult("generic_webhook", url, True, status_code=status)
        except Exception as e:
            return NotificationResult("generic_webhook", url, False, error=str(e))

    def send_slack(self, url: str, summary: DrillSummary) -> NotificationResult:
        """Formats and posts a Slack Block Kit message."""
        is_pass = summary.overall_status == "PASSED"
        status_text = "🟢 RESTORE DRILL PASSED" if is_pass else "🚨 RESTORE DRILL FAILED"
        color = "#10B981" if is_pass else "#EF4444"

        payload = {
            "text": f"{status_text} - {summary.backup_filename}",
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {"type": "plain_text", "text": f"{status_text} 🛡️"},
                        },
                        {
                            "type": "section",
                            "fields": [
                                {"type": "mrkdwn", "text": f"*Certificate ID:*\n`{summary.certificate_id}`"},
                                {"type": "mrkdwn", "text": f"*Database:*\n`{summary.database_type}`"},
                                {"type": "mrkdwn", "text": f"*Backup File:*\n`{summary.backup_filename}`"},
                                {"type": "mrkdwn", "text": f"*Restore RTO:*\n`{summary.restore_duration_sec:.2f}s`"},
                                {"type": "mrkdwn", "text": f"*Assertions:*\n`{summary.passed_assertions}/{summary.total_assertions} Passed`"},
                                {"type": "mrkdwn", "text": f"*SHA-256 Digest:*\n`{summary.backup_sha256[:12]}...`"},
                            ],
                        },
                    ],
                }
            ],
        }

        if summary.failure_reasons:
            failures_str = "\n".join(f"• {f}" for f in summary.failure_reasons[:5])
            payload["attachments"][0]["blocks"].append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Failure Causes:*\n```{failures_str}```"},
            })

        try:
            status = self._post_json(url, payload)
            return NotificationResult("slack", url, True, status_code=status)
        except Exception as e:
            return NotificationResult("slack", url, False, error=str(e))

    def send_discord(self, url: str, summary: DrillSummary) -> NotificationResult:
        """Formats and posts a Discord webhook with an embed."""
        is_pass = summary.overall_status == "PASSED"
        color = 0x10B981 if is_pass else 0xEF4444
        title = f"{'🟢' if is_pass else '🚨'} DrillOps: Restore Drill {summary.overall_status}"

        fields = [
            {"name": "Certificate ID", "value": f"`{summary.certificate_id}`", "inline": True},
            {"name": "Engine", "value": f"`{summary.database_type}`", "inline": True},
            {"name": "Restore RTO", "value": f"`{summary.restore_duration_sec:.2f}s`", "inline": True},
            {"name": "Backup File", "value": f"`{summary.backup_filename}`", "inline": False},
            {"name": "Assertions", "value": f"{summary.passed_assertions}/{summary.total_assertions} Passed", "inline": True},
            {"name": "SHA-256", "value": f"`{summary.backup_sha256[:16]}...`", "inline": True},
        ]

        if summary.failure_reasons:
            fields.append({
                "name": "Failure Details",
                "value": "\n".join(f"• {r}" for r in summary.failure_reasons[:4])[:1000],
                "inline": False,
            })

        payload = {
            "username": "DrillOps Certifier",
            "embeds": [
                {
                    "title": title,
                    "color": color,
                    "fields": fields,
                    "footer": {"text": "DrillOps Automated Disaster Recovery Engine"},
                    "timestamp": summary.timestamp,
                }
            ],
        }

        try:
            status = self._post_json(url, payload)
            return NotificationResult("discord", url, True, status_code=status)
        except Exception as e:
            return NotificationResult("discord", url, False, error=str(e))

    def send_pagerduty(self, routing_key: str, summary: DrillSummary, endpoint_url: Optional[str] = None) -> NotificationResult:
        """Triggers or resolves a PagerDuty Events API v2 incident."""
        if endpoint_url:
            url = endpoint_url
        elif routing_key.startswith("http://") or routing_key.startswith("https://"):
            url = routing_key
        else:
            url = "https://events.pagerduty.com/v2/enqueue"
        is_pass = summary.overall_status == "PASSED"
        action = "resolve" if is_pass else "trigger"

        payload = {
            "routing_key": routing_key,
            "event_action": action,
            "dedup_key": f"drillops-{summary.backup_filename}",
            "payload": {
                "summary": f"DrillOps {summary.overall_status}: {summary.backup_filename} (RTO: {summary.restore_duration_sec:.2f}s)",
                "source": "DrillOps Restore Engine",
                "severity": "info" if is_pass else "critical",
                "custom_details": {
                    "certificate_id": summary.certificate_id,
                    "database_type": summary.database_type,
                    "backup_sha256": summary.backup_sha256,
                    "failures": summary.failure_reasons,
                },
            },
        }

        try:
            status = self._post_json(url, payload)
            return NotificationResult("pagerduty", url, True, status_code=status)
        except Exception as e:
            return NotificationResult("pagerduty", url, False, error=str(e))

    def send_vanta(self, url: str, summary: DrillSummary) -> NotificationResult:
        """Sends automated evidence payload conforming to Vanta Custom Test API schema."""
        is_pass = summary.overall_status == "PASSED"
        evidence_text = (
            f"DrillOps Autonomous DR Engine verified {summary.database_type.upper()} restore "
            f"of '{summary.backup_filename}' with RTO {summary.restore_duration_sec:.3f}s. "
            f"Assertions: {summary.passed_assertions}/{summary.total_assertions} passed. "
            f"SHA-256 Digest: {summary.backup_sha256}."
        )
        payload = {
            "testStatus": "PASSED" if is_pass else "FAILED",
            "name": "Database Disaster Recovery Restore Drill",
            "description": "Continuous ephemeral database restore drill verifying backup recoverability and integrity.",
            "control": "SOC2 CC9.1",
            "timestamp": summary.timestamp,
            "metadata": {
                "certificate_id": summary.certificate_id,
                "database_type": summary.database_type,
                "backup_filename": summary.backup_filename,
                "backup_sha256": summary.backup_sha256,
                "recovery_time_objective_actual_seconds": summary.restore_duration_sec,
                "assertions_passed": summary.passed_assertions,
                "assertions_total": summary.total_assertions,
            },
            "evidence": evidence_text,
        }

        try:
            status = self._post_json(url, payload)
            return NotificationResult("vanta", url, True, status_code=status)
        except Exception as e:
            return NotificationResult("vanta", url, False, error=str(e))

    def send_drata(self, url: str, summary: DrillSummary) -> NotificationResult:
        """Sends automated evidence payload conforming to Drata Custom Test Evidence schema."""
        is_pass = summary.overall_status == "PASSED"
        outcome_details = (
            f"DrillOps verification outcome: {summary.overall_status}. "
            f"Recovery duration (RTO): {summary.restore_duration_sec:.3f}s. "
            f"Backup archive: {summary.backup_filename} ({summary.backup_size_bytes:,} bytes). "
            f"Integrity SHA-256: {summary.backup_sha256}."
        )
        payload = {
            "status": "PASSED" if is_pass else "FAILED",
            "controlIdentifier": "DR-01",
            "standard": "SOC2 CC9.1 / ISO 27001 A.12.3.1",
            "testName": "Continuous Database Restore Drill Verification",
            "timestamp": summary.timestamp,
            "source": "DrillOps Autonomous DR Engine",
            "evidenceSummary": {
                "certificateId": summary.certificate_id,
                "database": summary.database_type,
                "backupFile": summary.backup_filename,
                "sha256": summary.backup_sha256,
                "rtoSeconds": summary.restore_duration_sec,
                "passedAssertions": summary.passed_assertions,
                "totalAssertions": summary.total_assertions,
            },
            "outcomeDetails": outcome_details,
        }

        try:
            status = self._post_json(url, payload)
            return NotificationResult("drata", url, True, status_code=status)
        except Exception as e:
            return NotificationResult("drata", url, False, error=str(e))

    def dispatch_all(
        self,
        summary: DrillSummary,
        assertions: Optional[List[AssertionResult]] = None,
    ) -> List[NotificationResult]:
        """Dispatches results to all configured notification channels."""
        is_pass = summary.overall_status == "PASSED"
        if is_pass and not self.config.notify_on_pass:
            return []
        if not is_pass and not self.config.notify_on_fail:
            return []

        assertions_list = assertions or []
        results: List[NotificationResult] = []

        if self.config.webhook_url:
            results.append(self.send_generic_webhook(self.config.webhook_url, summary, assertions_list))

        if self.config.slack_webhook_url:
            results.append(self.send_slack(self.config.slack_webhook_url, summary))

        if self.config.discord_webhook_url:
            results.append(self.send_discord(self.config.discord_webhook_url, summary))

        if self.config.pagerduty_routing_key:
            results.append(self.send_pagerduty(self.config.pagerduty_routing_key, summary))

        if self.config.vanta_webhook_url:
            results.append(self.send_vanta(self.config.vanta_webhook_url, summary))

        if self.config.drata_webhook_url:
            results.append(self.send_drata(self.config.drata_webhook_url, summary))

        return results
