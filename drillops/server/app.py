"""Lightweight embedded HTTP web server and compliance dashboard for DrillOps."""

import http.server
import json
import os
import socketserver
import urllib.parse
from typing import Dict, List, Optional

from drillops import __version__
from drillops.certifier import CertificateGenerator


class DrillOpsHTTPHandler(http.server.BaseHTTPRequestHandler):
    """Handles REST API queries and serves the SOC2 compliance dashboard."""

    certificates_dir: str = "./certificates"

    def log_message(self, format, *args):
        # Quiet down standard access logging in automated environments
        pass

    def _send_json(self, status: int, data: Dict):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status: int, html_str: str):
        body = html_str.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_binary(self, status: int, data: bytes, content_type: str, filename: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/status":
            certs = self._load_certificates()
            passed = sum(1 for c in certs if c.get("overall_status") == "PASSED")
            total = len(certs)
            rtos = [c.get("metrics", {}).get("recovery_time_objective_actual_seconds", 0) for c in certs if "metrics" in c]
            avg_rto = round(sum(rtos) / len(rtos), 3) if rtos else 0.0

            self._send_json(200, {
                "system": "DrillOps Compliance Monitor",
                "version": "0.1.0",
                "compliance_status": "COMPLIANT" if (total > 0 and passed == total) else ("DEFICIT" if total > 0 else "NO_DATA"),
                "total_drills": total,
                "passed_drills": passed,
                "pass_rate_percent": round((passed / total) * 100, 1) if total > 0 else 0.0,
                "average_rto_seconds": avg_rto,
            })

        elif path == "/api/certificates":
            certs = self._load_certificates()
            self._send_json(200, {"certificates": certs})

        elif path.startswith("/api/certificates/") and path.endswith("/markdown"):
            cert_id = path.split("/")[3]
            md_file = os.path.join(self.certificates_dir, f"drill_cert_{cert_id.lower()}.md")
            if os.path.isfile(md_file):
                with open(md_file, "r", encoding="utf-8") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/markdown; charset=utf-8")
                self.send_header("Content-Length", str(len(content.encode("utf-8"))))
                self.end_headers()
                self.wfile.write(content.encode("utf-8"))
            else:
                self._send_json(404, {"error": "Certificate markdown not found"})

        elif path.startswith("/api/certificates/"):
            cert_id = path.split("/")[3]
            json_file = os.path.join(self.certificates_dir, f"drill_cert_{cert_id.lower()}.json")
            if os.path.isfile(json_file):
                with open(json_file, "r", encoding="utf-8") as f:
                    self._send_json(200, json.load(f))
            else:
                self._send_json(404, {"error": "Certificate not found"})

        elif path in ("/", "/index.html"):
            web_index = os.path.join(os.path.dirname(__file__), "..", "..", "web", "index.html")
            if os.path.isfile(web_index):
                with open(web_index, "r", encoding="utf-8") as f:
                    self._send_html(200, f.read())
            else:
                certs = self._load_certificates()
                self._send_html(200, self._render_dashboard_html(certs))

        elif path == "/dashboard":
            certs = self._load_certificates()
            html = self._render_dashboard_html(certs)
            self._send_html(200, html)

        elif path == "/api/audit-pack":
            from drillops.compliance.audit_pack import AuditPackGenerator
            import tempfile
            generator = AuditPackGenerator(self.certificates_dir)
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                tmp_path = tmp.name
            try:
                generator.export_pack_zip(tmp_path)
                with open(tmp_path, "rb") as f:
                    zip_bytes = f.read()
                self._send_binary(200, zip_bytes, "application/zip", "drillops_audit_dossier.zip")
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

        elif path in ("/dossier", "/audit-dossier"):
            from drillops.compliance.audit_pack import AuditPackGenerator
            generator = AuditPackGenerator(self.certificates_dir)
            certs = generator.load_certificates()
            metrics = generator.calculate_metrics(certs)
            html = generator.generate_html_dossier(metrics, certs)
            self._send_html(200, html)

        elif path in ("/api/badge.svg", "/api/badge"):
            from drillops.compliance.badge import ComplianceBadgeGenerator
            gen = ComplianceBadgeGenerator(self.certificates_dir)
            svg_data = gen.generate_svg().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "image/svg+xml")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(svg_data)))
            self.end_headers()
            self.wfile.write(svg_data)

        elif path == "/api/badge/shields.json":
            from drillops.compliance.badge import ComplianceBadgeGenerator
            gen = ComplianceBadgeGenerator(self.certificates_dir)
            self._send_json(200, gen.generate_shields_json())

        elif path == "/api/checklist":
            from dataclasses import asdict
            from drillops.compliance.checklist import SOC2ChecklistEvaluator
            company = urllib.parse.parse_qs(parsed.query).get("company", ["Organization"])[0]
            evaluator = SOC2ChecklistEvaluator(self.certificates_dir)
            controls = evaluator.evaluate(company=company)
            self._send_json(200, {
                "company": company,
                "controls": [asdict(c) for c in controls],
                "total_controls": len(controls),
                "verified_controls": sum(1 for c in controls if c.status in ("COMPLIANT", "READY")),
            })

        elif path == "/api/leads":
            leads_file = os.path.join(self.certificates_dir, "leads.jsonl")
            leads = []
            if os.path.isfile(leads_file):
                with open(leads_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            try:
                                leads.append(json.loads(line.strip()))
                            except Exception:
                                pass
            self._send_json(200, {"leads": leads, "total_leads": len(leads)})

        elif path in ("/metrics", "/api/metrics"):
            from drillops.monitoring.metrics import PrometheusMetricsExporter
            exporter = PrometheusMetricsExporter(self.certificates_dir)
            metrics_text = exporter.generate_prometheus_exposition().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(metrics_text)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(metrics_text)

        else:
            self._send_json(404, {"error": "Not Found"})

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/api/leads", "/api/inquiry"):
            content_len = int(self.headers.get("Content-Length", 0))
            if content_len == 0:
                self._send_json(400, {"error": "Empty request body"})
                return

            post_body = self.rfile.read(content_len)
            try:
                lead_data = json.loads(post_body.decode("utf-8"))
            except Exception:
                self._send_json(400, {"error": "Invalid JSON"})
                return

            import uuid
            from datetime import datetime, timezone
            lead_id = f"LEAD-{uuid.uuid4().hex[:8].upper()}"
            lead_data["lead_id"] = lead_id
            lead_data["received_at_utc"] = datetime.now(timezone.utc).isoformat()

            leads_file = os.path.join(self.certificates_dir, "leads.jsonl")
            os.makedirs(os.path.dirname(os.path.abspath(leads_file)), exist_ok=True)
            with open(leads_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(lead_data) + "\n")

            self._send_json(201, {
                "status": "success",
                "lead_id": lead_id,
                "message": "Lead inquiry recorded successfully",
            })
        else:
            self._send_json(404, {"error": "Not Found"})

    def _load_certificates(self) -> List[Dict]:
        if not os.path.isdir(self.certificates_dir):
            return []
        items = []
        for fname in sorted(os.listdir(self.certificates_dir), reverse=True):
            if fname.endswith(".json") and fname.startswith("drill_cert_"):
                fpath = os.path.join(self.certificates_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        items.append(json.load(f))
                except Exception:
                    pass
        return items

    def _render_dashboard_html(self, certs: List[Dict]) -> str:
        passed = sum(1 for c in certs if c.get("overall_status") == "PASSED")
        total = len(certs)
        rate = f"{(passed / total * 100):.1f}%" if total > 0 else "N/A"
        badge_color = "#10b981" if (total > 0 and passed == total) else "#f59e0b"
        badge_text = "SOC2 AUDIT READY" if (total > 0 and passed == total) else "MONITORING ACTIVE"

        rows = []
        for c in certs:
            cid = c.get("certificate_id", "UNKNOWN")
            ts = c.get("timestamp_utc", "N/A")[:19].replace("T", " ")
            status = c.get("overall_status", "UNKNOWN")
            db = c.get("target", {}).get("database_type", "N/A")
            rto = c.get("metrics", {}).get("recovery_time_objective_actual_seconds", 0)
            status_cls = "text-green-400" if status == "PASSED" else "text-red-400"

            rows.append(f"""
            <tr class="border-b border-gray-800 hover:bg-gray-800/40">
                <td class="py-3 px-4 font-mono text-sm text-indigo-400">{cid}</td>
                <td class="py-3 px-4 text-sm text-gray-300">{ts} UTC</td>
                <td class="py-3 px-4 text-sm font-semibold uppercase text-gray-400">{db}</td>
                <td class="py-3 px-4 text-sm font-semibold {status_cls}">{status}</td>
                <td class="py-3 px-4 text-sm text-gray-300">{rto}s</td>
                <td class="py-3 px-4 text-sm">
                    <a href="/api/certificates/{cid.lower()}/markdown" target="_blank" class="text-blue-400 hover:underline mr-3">View MD</a>
                    <a href="/api/certificates/{cid.lower()}" target="_blank" class="text-gray-400 hover:underline">JSON</a>
                </td>
            </tr>
            """)

        table_body = "".join(rows) if rows else "<tr><td colspan='6' class='py-6 text-center text-gray-500'>No restore drills recorded yet.</td></tr>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DrillOps — Disaster Recovery & SOC2 Audit Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {{ background-color: #0b0f17; color: #f3f4f6; }}
    </style>
</head>
<body class="font-sans antialiased min-h-screen p-6 md:p-12">
    <div class="max-w-6xl mx-auto">
        <!-- Header -->
        <div class="flex flex-col md:flex-row md:items-center justify-between pb-8 border-b border-gray-800 gap-4">
            <div>
                <div class="flex items-center gap-3">
                    <h1 class="text-2xl md:text-3xl font-extrabold tracking-tight text-white">DrillOps</h1>
                    <span class="px-2.5 py-0.5 text-xs font-bold rounded-full text-black uppercase" style="background-color: {badge_color};">{badge_text}</span>
                </div>
                <p class="text-sm text-gray-400 mt-1">Autonomous Database Restore Drill Runner & Compliance Audit System</p>
            </div>
            <div class="flex items-center gap-3">
                <a href="/api/status" target="_blank" class="px-4 py-2 text-xs font-medium bg-gray-800 hover:bg-gray-700 text-gray-200 rounded-lg border border-gray-700 transition">API Health</a>
                <a href="/api/certificates" target="_blank" class="px-4 py-2 text-xs font-medium bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg transition">Export Certificates</a>
            </div>
        </div>

        <!-- Metrics Grid -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 my-8">
            <div class="bg-gray-900 border border-gray-800 rounded-xl p-5">
                <div class="text-xs uppercase font-medium text-gray-500">Total Drills</div>
                <div class="text-2xl md:text-3xl font-bold text-white mt-1">{total}</div>
                <div class="text-xs text-gray-400 mt-1">Verified archives</div>
            </div>
            <div class="bg-gray-900 border border-gray-800 rounded-xl p-5">
                <div class="text-xs uppercase font-medium text-gray-500">Pass Rate</div>
                <div class="text-2xl md:text-3xl font-bold text-emerald-400 mt-1">{rate}</div>
                <div class="text-xs text-gray-400 mt-1">{passed} passed without deficits</div>
            </div>
            <div class="bg-gray-900 border border-gray-800 rounded-xl p-5">
                <div class="text-xs uppercase font-medium text-gray-500">Compliance Standard</div>
                <div class="text-2xl md:text-3xl font-bold text-indigo-400 mt-1">SOC2 / ISO</div>
                <div class="text-xs text-gray-400 mt-1">Disaster Recovery RTO</div>
            </div>
            <div class="bg-gray-900 border border-gray-800 rounded-xl p-5">
                <div class="text-xs uppercase font-medium text-gray-500">Operating Cost</div>
                <div class="text-2xl md:text-3xl font-bold text-emerald-400 mt-1">$0.00</div>
                <div class="text-xs text-gray-400 mt-1">Self-hosted local runner</div>
            </div>
        </div>

        <!-- Audit Ledger -->
        <div class="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden shadow-2xl">
            <div class="p-5 border-b border-gray-800 flex justify-between items-center">
                <h2 class="text-lg font-semibold text-white">Disaster Recovery Certificate Ledger</h2>
                <span class="text-xs text-gray-400 font-mono">Ledger Count: {total}</span>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="border-b border-gray-800 bg-gray-950/50 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                            <th class="py-3 px-4">Certificate ID</th>
                            <th class="py-3 px-4">Timestamp</th>
                            <th class="py-3 px-4">Engine</th>
                            <th class="py-3 px-4">Status</th>
                            <th class="py-3 px-4">Restore RTO</th>
                            <th class="py-3 px-4">Audit Records</th>
                        </tr>
                    </thead>
                    <tbody>
                        {table_body}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Footer -->
        <div class="mt-8 text-center text-xs text-gray-500">
            DrillOps v{__version__} • Running autonomously inside container sandbox • Zero external accounts required
        </div>
    </div>
</body>
</html>
"""


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def run_dashboard_server(host: str = "127.0.0.1", port: int = 8787, cert_dir: str = "./certificates") -> socketserver.TCPServer:
    """Instantiates the HTTP server bound to host and port."""
    DrillOpsHTTPHandler.certificates_dir = cert_dir
    httpd = ReusableTCPServer((host, port), DrillOpsHTTPHandler)
    return httpd
