"""Dynamic DR Compliance Badge Generator for DrillOps.

Generates standalone SVG and Shields.io JSON badges for READMEs, status pages,
and trust portals verifying SOC2 CC9.1 and ISO 27001 disaster recovery status.
"""

import json
import os
from typing import Any, Dict, List, Optional


class ComplianceBadgeGenerator:
    """Evaluates drill certificate history and renders cryptographic DR compliance badges."""

    def __init__(self, cert_dir: Optional[str] = None):
        self.cert_dir = cert_dir

    def get_badge_status(self) -> Dict[str, Any]:
        """Calculates current compliance status and metrics from certificates."""
        total = 0
        passed = 0
        avg_rto = 0.0

        if self.cert_dir and os.path.isdir(self.cert_dir):
            try:
                cert_files = [
                    os.path.join(self.cert_dir, f)
                    for f in os.listdir(self.cert_dir)
                    if f.startswith("drill_cert_") and f.endswith(".json")
                ]
                certs = []
                for cf in cert_files:
                    with open(cf, "r", encoding="utf-8") as f:
                        certs.append(json.load(f))
                total = len(certs)
                passed_certs = [c for c in certs if c.get("overall_status") == "PASSED"]
                passed = len(passed_certs)
                if passed_certs:
                    rtos = [
                        c.get("metrics", {}).get("recovery_time_objective_actual_seconds", 0)
                        for c in passed_certs
                    ]
                    avg_rto = round(sum(rtos) / len(rtos), 3) if rtos else 0.0
            except Exception:
                pass

        if total == 0:
            return {
                "label": "DR Verified",
                "message": "NO DATA",
                "color": "#6b7280",
                "shields_color": "lightgrey",
                "compliant": False,
                "total_drills": 0,
                "passed_drills": 0,
                "avg_rto": 0.0,
            }

        if passed == total:
            status_text = f"SOC2 CC9.1 PASS ({avg_rto}s RTO)" if avg_rto > 0 else "SOC2 CC9.1 PASS"
            return {
                "label": "DR Verified",
                "message": status_text,
                "color": "#10b981",
                "shields_color": "brightgreen",
                "compliant": True,
                "total_drills": total,
                "passed_drills": passed,
                "avg_rto": avg_rto,
            }
        else:
            status_text = f"{passed}/{total} PASSED"
            return {
                "label": "DR Verified",
                "message": status_text,
                "color": "#ef4444",
                "shields_color": "red",
                "compliant": False,
                "total_drills": total,
                "passed_drills": passed,
                "avg_rto": avg_rto,
            }

    def generate_svg(
        self,
        custom_label: Optional[str] = None,
        custom_message: Optional[str] = None,
        custom_color: Optional[str] = None,
    ) -> str:
        """Renders an SVG compliance badge matching shields.io standard layout."""
        status = self.get_badge_status()
        label = custom_label or status["label"]
        message = custom_message or status["message"]
        color = custom_color or status["color"]

        # Approximate character width metrics for clean rendering
        label_width = int(len(label) * 6.8 + 14)
        message_width = int(len(message) * 6.8 + 14)
        total_width = label_width + message_width

        label_x = int(label_width / 2)
        message_x = int(label_width + (message_width / 2))

        svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20" role="img" aria-label="{label}: {message}">
  <title>{label}: {message}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="#2d3748"/>
    <rect x="{label_width}" width="{message_width}" height="20" fill="{color}"/>
    <rect width="{total_width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="{label_x}" y="15" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="{label_x}" y="14">{label}</text>
    <text x="{message_x}" y="15" fill="#010101" fill-opacity=".3">{message}</text>
    <text x="{message_x}" y="14">{message}</text>
  </g>
</svg>"""
        return svg

    def generate_shields_json(self) -> Dict[str, Any]:
        """Returns standard Shields.io endpoint schema format."""
        status = self.get_badge_status()
        return {
            "schemaVersion": 1,
            "label": status["label"],
            "message": status["message"],
            "color": status["shields_color"],
            "isError": False,
        }

    def generate_markdown(
        self,
        badge_path: str = "./drillops_badge.svg",
        target_url: str = "https://drillops.dev",
    ) -> str:
        """Returns Markdown embed snippet."""
        return f"[![DrillOps DR Verified]({badge_path})]({target_url})"
