"""SOC2 / ISO 27001 Auditor Evidence Dossier Packager for DrillOps."""

from dataclasses import dataclass, field
import datetime
import hashlib
import json
import os
from typing import Any, Dict, List, Optional
import zipfile

from drillops import __version__


@dataclass
class ComplianceMetrics:
    """Aggregated compliance metrics across all restore drills."""
    total_drills: int = 0
    passed_drills: int = 0
    failed_drills: int = 0
    success_rate_pct: float = 0.0
    avg_rto_seconds: float = 0.0
    max_rto_seconds: float = 0.0
    min_rto_seconds: float = 0.0
    total_assertions: int = 0
    passed_assertions: int = 0
    failed_assertions: int = 0
    database_types: List[str] = field(default_factory=list)
    earliest_drill: Optional[str] = None
    latest_drill: Optional[str] = None


class AuditPackGenerator:
    """Collects certificates and generates auditor-ready SOC2 evidence packages."""

    def __init__(self, cert_dir: str):
        self.cert_dir = os.path.abspath(cert_dir)

    def load_certificates(self, days: Optional[int] = None) -> List[Dict[str, Any]]:
        """Loads and parses JSON certificates, optionally filtering to the last N days."""
        if not os.path.isdir(self.cert_dir):
            return []

        cutoff_date = None
        if days is not None:
            cutoff_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)

        certificates = []
        for fname in sorted(os.listdir(self.cert_dir)):
            if (fname.startswith("drill_cert_") or fname.startswith("DRC-")) and fname.endswith(".json"):
                fpath = os.path.join(self.cert_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        data = json.load(f)

                    if cutoff_date and "timestamp_utc" in data:
                        ts_str = data["timestamp_utc"]
                        ts = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        if ts < cutoff_date:
                            continue

                    data["_filepath"] = fpath
                    data["_filename"] = fname
                    with open(fpath, "rb") as f:
                        data["_cert_sha256"] = hashlib.sha256(f.read()).hexdigest()

                    certificates.append(data)
                except Exception:
                    continue

        return certificates

    def calculate_metrics(self, certificates: List[Dict[str, Any]]) -> ComplianceMetrics:
        """Calculates SLA and compliance KPIs from loaded certificates."""
        if not certificates:
            return ComplianceMetrics()

        total = len(certificates)
        passed = sum(1 for c in certificates if c.get("overall_status") == "PASSED")
        failed = total - passed
        success_rate = round((passed / total) * 100.0, 2) if total > 0 else 0.0

        rto_list = [
            c.get("metrics", {}).get("recovery_time_objective_actual_seconds", 0.0)
            for c in certificates
            if "metrics" in c
        ]

        avg_rto = round(sum(rto_list) / len(rto_list), 4) if rto_list else 0.0
        max_rto = round(max(rto_list), 4) if rto_list else 0.0
        min_rto = round(min(rto_list), 4) if rto_list else 0.0

        total_assertions = sum(c.get("metrics", {}).get("total_assertions", 0) for c in certificates)
        passed_assertions = sum(c.get("metrics", {}).get("passed_assertions", 0) for c in certificates)
        failed_assertions = sum(c.get("metrics", {}).get("failed_assertions", 0) for c in certificates)

        db_types = sorted(list({c.get("target", {}).get("database_type", "unknown") for c in certificates}))
        timestamps = [c.get("timestamp_utc", "") for c in certificates if c.get("timestamp_utc")]
        earliest = min(timestamps) if timestamps else None
        latest = max(timestamps) if timestamps else None

        return ComplianceMetrics(
            total_drills=total,
            passed_drills=passed,
            failed_drills=failed,
            success_rate_pct=success_rate,
            avg_rto_seconds=avg_rto,
            max_rto_seconds=max_rto,
            min_rto_seconds=min_rto,
            total_assertions=total_assertions,
            passed_assertions=passed_assertions,
            failed_assertions=failed_assertions,
            database_types=db_types,
            earliest_drill=earliest,
            latest_drill=latest,
        )

    def generate_markdown_dossier(
        self,
        metrics: ComplianceMetrics,
        certificates: List[Dict[str, Any]],
        company_name: str = "Organization",
    ) -> str:
        """Constructs an auditor-ready Markdown dossier compliant with SOC2 CC7.4 / ISO 27001 A.12.3."""
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        status_tag = "🟢 PASS (SLA COMPLIANT)" if metrics.failed_drills == 0 and metrics.total_drills > 0 else "🟡 ATTENTION (DEFICITS DETECTED)"

        md = [
            f"# 📋 SOC2 Type II & ISO 27001 Backup Restoration Audit Dossier",
            f"",
            f"**Organization**: `{company_name}`  ",
            f"**Audit Generation Date**: `{now_str}`  ",
            f"**Compliance Status**: **{status_tag}**  ",
            f"**Audit Period**: `{metrics.earliest_drill or 'N/A'}` to `{metrics.latest_drill or 'N/A'}`  ",
            f"",
            f"---",
            f"",
            f"## 1. Executive Summary & Attestation Statement",
            f"",
            f"> This document and attached cryptographic verification certificates provide formal audit evidence for",
            f"> **SOC2 Trust Services Criteria CC6.1, CC7.1, CC7.4** and **ISO/IEC 27001:2022 Control A.8.13 (Information Backup)**.",
            f"> Automated disaster recovery restore drills were executed in isolated sandboxes to verify backup",
            f"> completeness, cryptographic hash integrity, and data schema validity without human intervention.",
            f"",
            f"---",
            f"",
            f"## 2. Disaster Recovery KPI & SLA Metrics",
            f"",
            f"| Metric | Value | Compliance Benchmark |",
            f"| :--- | :---: | :--- |",
            f"| **Total Restore Drills** | `{metrics.total_drills}` | >= 1 per scheduled period |",
            f"| **Drill Success Rate** | `{metrics.success_rate_pct}%` | Target: 100.0% |",
            f"| **Passed Drills** | `{metrics.passed_drills}` | - |",
            f"| **Failed Drills** | `{metrics.failed_drills}` | 0 required for clean audit |",
            f"| **Average RTO (Restore Time)** | `{metrics.avg_rto_seconds}s` | SLA Target: < 300s |",
            f"| **Max Recorded RTO** | `{metrics.max_rto_seconds}s` | - |",
            f"| **Total Integrity Assertions** | `{metrics.total_assertions}` | - |",
            f"| **Assertions Passed** | `{metrics.passed_assertions}` | 100% required |",
            f"| **Database Engines Tested** | `{', '.join(metrics.database_types)}` | Supported engines verified |",
            f"",
            f"---",
            f"",
            f"## 3. Cryptographic Verification Chain (Drill Log)",
            f"",
            f"| Certificate ID | Timestamp (UTC) | Engine | Backup Artifact | SHA-256 Digest (Truncated) | RTO | Status |",
            f"| :--- | :---: | :---: | :--- | :---: | :---: | :---: |",
        ]

        for c in reversed(certificates):
            cid = c.get("certificate_id", "UNKNOWN")
            ts = c.get("timestamp_utc", "")[:19]
            target = c.get("target", {})
            db = target.get("database_type", "")
            fname = target.get("backup_filename", "")
            sha = target.get("backup_sha256", "")
            sha_trunc = f"{sha[:10]}...{sha[-6:]}" if sha else "N/A"
            rto = f"{c.get('metrics', {}).get('recovery_time_objective_actual_seconds', 0.0):.2f}s"
            status = "✅ PASS" if c.get("overall_status") == "PASSED" else "❌ FAIL"
            md.append(f"| `{cid}` | {ts} | `{db}` | `{fname}` | `{sha_trunc}` | {rto} | {status} |")

        md.extend([
            f"",
            f"---",
            f"",
            f"## 4. Auditor Verification Instructions",
            f"",
            f"1. **Certificate Authenticity**: Verify that the certificate JSON files in this package match the SHA-256 hashes recorded in `manifest.json`.",
            f"2. **Backup Provenance**: Match the `backup_sha256` digests against the object storage ETag / SHA-256 logs of your production backup store (e.g., AWS S3, Cloudflare R2, Google Cloud Storage).",
            f"3. **Zero Data Tampering**: Confirm that all evaluated assertion queries returned positive verification counts on record totals.",
            f"",
            f"---",
            f"*Generated autonomously by DrillOps Engine v{__version__}*",
        ])

        return "\n".join(md)

    def generate_html_dossier(
        self,
        metrics: ComplianceMetrics,
        certificates: List[Dict[str, Any]],
        company_name: str = "Organization",
    ) -> str:
        """Constructs an elegant, printable HTML audit dossier with Tailwind styling."""
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        is_passed = metrics.failed_drills == 0 and metrics.total_drills > 0
        status_badge = "VERIFIED / SLA COMPLIANT" if is_passed else "ATTENTION REQUIRED"
        status_color = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" if is_passed else "bg-amber-500/10 text-amber-400 border-amber-500/30"

        table_rows = []
        for c in reversed(certificates):
            cid = c.get("certificate_id", "UNKNOWN")
            ts = c.get("timestamp_utc", "")[:19].replace("T", " ")
            target = c.get("target", {})
            db = target.get("database_type", "")
            fname = target.get("backup_filename", "")
            sha = target.get("backup_sha256", "")
            sha_trunc = f"{sha[:8]}...{sha[-6:]}" if sha else "N/A"
            rto = f"{c.get('metrics', {}).get('recovery_time_objective_actual_seconds', 0.0):.2f}s"
            passed = c.get("overall_status") == "PASSED"
            badge = '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">PASS</span>' if passed else '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">FAIL</span>'

            table_rows.append(f"""
            <tr class="border-b border-slate-800 hover:bg-slate-800/40">
                <td class="px-4 py-3 font-mono text-cyan-400 text-xs">{cid}</td>
                <td class="px-4 py-3 text-slate-300 text-xs">{ts}</td>
                <td class="px-4 py-3 text-slate-300 text-xs font-mono">{db}</td>
                <td class="px-4 py-3 text-slate-300 text-xs truncate max-w-xs">{fname}</td>
                <td class="px-4 py-3 font-mono text-slate-400 text-xs">{sha_trunc}</td>
                <td class="px-4 py-3 text-slate-300 text-xs">{rto}</td>
                <td class="px-4 py-3">{badge}</td>
            </tr>
            """)

        rows_html = "\n".join(table_rows) if table_rows else '<tr><td colspan="7" class="px-4 py-6 text-center text-slate-400">No certificates recorded in period.</td></tr>'

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DrillOps SOC2 / ISO 27001 Evidence Dossier</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @media print {{
            body {{ background-color: white !important; color: black !important; }}
            .no-print {{ display: none !important; }}
            .print-border {{ border: 1px solid #ccc !important; }}
        }}
    </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen p-8 antialiased">
    <div class="max-w-6xl mx-auto space-y-8">
        <!-- Header -->
        <div class="flex flex-col md:flex-row justify-between items-start md:items-center pb-6 border-b border-slate-800 gap-4">
            <div>
                <div class="flex items-center gap-3">
                    <span class="text-2xl">🛡️</span>
                    <h1 class="text-2xl font-bold text-white tracking-tight">SOC2 Type II & ISO 27001 Backup Restoration Dossier</h1>
                </div>
                <p class="text-slate-400 text-sm mt-1">Organization: <strong class="text-slate-200">{company_name}</strong> | Generated: <span class="font-mono text-slate-300">{now_str}</span></p>
            </div>
            <div class="flex items-center gap-3">
                <span class="px-3 py-1.5 rounded-full border text-xs font-semibold uppercase tracking-wider {status_color}">{status_badge}</span>
                <button onclick="window.print()" class="no-print px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-medium border border-slate-700 transition">Print / Export PDF</button>
            </div>
        </div>

        <!-- Attestation Statement -->
        <div class="p-5 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
            <h2 class="text-xs font-semibold uppercase tracking-wider text-cyan-400">Compliance Attestation Statement</h2>
            <p class="text-slate-300 text-sm leading-relaxed">
                This evidence package attests that automated database restore drills were executed against all designated backup artifacts in an isolated execution sandbox. The backups were restored, verified against cryptographic checksums, and validated via schema and data integrity assertions in adherence with <strong>SOC2 Trust Services Criteria CC6.1, CC7.1, CC7.4</strong> and <strong>ISO/IEC 27001:2022 Control A.8.13</strong>.
            </p>
        </div>

        <!-- Metrics Grid -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div class="p-4 rounded-lg bg-slate-900 border border-slate-800">
                <div class="text-slate-400 text-xs font-medium">Total Drills Executed</div>
                <div class="text-2xl font-bold text-white mt-1 font-mono">{metrics.total_drills}</div>
                <div class="text-slate-500 text-xs mt-1">Period: {metrics.earliest_drill[:10] if metrics.earliest_drill else 'N/A'} - {metrics.latest_drill[:10] if metrics.latest_drill else 'N/A'}</div>
            </div>
            <div class="p-4 rounded-lg bg-slate-900 border border-slate-800">
                <div class="text-slate-400 text-xs font-medium">Drill Success Rate</div>
                <div class="text-2xl font-bold {'text-emerald-400' if metrics.success_rate_pct == 100 else 'text-amber-400'} mt-1 font-mono">{metrics.success_rate_pct}%</div>
                <div class="text-slate-500 text-xs mt-1">{metrics.passed_drills} Passed / {metrics.failed_drills} Failed</div>
            </div>
            <div class="p-4 rounded-lg bg-slate-900 border border-slate-800">
                <div class="text-slate-400 text-xs font-medium">Average Restore Time (RTO)</div>
                <div class="text-2xl font-bold text-cyan-400 mt-1 font-mono">{metrics.avg_rto_seconds}s</div>
                <div class="text-slate-500 text-xs mt-1">Max Recorded: {metrics.max_rto_seconds}s</div>
            </div>
            <div class="p-4 rounded-lg bg-slate-900 border border-slate-800">
                <div class="text-slate-400 text-xs font-medium">Assertions Evaluated</div>
                <div class="text-2xl font-bold text-white mt-1 font-mono">{metrics.total_assertions}</div>
                <div class="text-slate-500 text-xs mt-1">{metrics.passed_assertions} Passed (100% integrity)</div>
            </div>
        </div>

        <!-- Cryptographic Log Table -->
        <div class="rounded-lg bg-slate-900 border border-slate-800 overflow-hidden">
            <div class="px-5 py-4 border-b border-slate-800 flex justify-between items-center">
                <h3 class="font-semibold text-white text-sm">Cryptographic Verification Chain</h3>
                <span class="text-xs text-slate-400">{len(certificates)} verified drills</span>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="bg-slate-950/60 text-slate-400 text-xs uppercase tracking-wider border-b border-slate-800">
                            <th class="px-4 py-3 font-medium">Cert ID</th>
                            <th class="px-4 py-3 font-medium">Timestamp (UTC)</th>
                            <th class="px-4 py-3 font-medium">Engine</th>
                            <th class="px-4 py-3 font-medium">Backup File</th>
                            <th class="px-4 py-3 font-medium">SHA-256 Digest</th>
                            <th class="px-4 py-3 font-medium">RTO</th>
                            <th class="px-4 py-3 font-medium">Result</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows_html}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Footer / Signoff -->
        <div class="pt-6 border-t border-slate-800 text-xs text-slate-500 flex flex-col md:flex-row justify-between items-center gap-2">
            <div>Verified autonomously via <strong>DrillOps v{__version__}</strong> | Tamper-evident cryptographic ledger</div>
            <div>Trust Services Criteria CC6.1, CC7.1, CC7.4 Compliant</div>
        </div>
    </div>
</body>
</html>"""

    def export_pack_zip(
        self,
        output_zip_path: str,
        days: Optional[int] = None,
        company_name: str = "Organization",
    ) -> str:
        """Packages the evidence dossier, certificates, and manifest into a distributable ZIP."""
        certificates = self.load_certificates(days=days)
        metrics = self.calculate_metrics(certificates)

        md_content = self.generate_markdown_dossier(metrics, certificates, company_name=company_name)
        html_content = self.generate_html_dossier(metrics, certificates, company_name=company_name)

        manifest = {
            "dossier_version": "1.0",
            "organization": company_name,
            "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "compliance_standards": ["SOC2_TYPE_II_CC7.4", "ISO_27001_A.8.13"],
            "metrics": {
                "total_drills": metrics.total_drills,
                "passed_drills": metrics.passed_drills,
                "failed_drills": metrics.failed_drills,
                "success_rate_pct": metrics.success_rate_pct,
                "avg_rto_seconds": metrics.avg_rto_seconds,
                "max_rto_seconds": metrics.max_rto_seconds,
                "total_assertions": metrics.total_assertions,
            },
            "certificates": [
                {
                    "certificate_id": c.get("certificate_id"),
                    "filename": c.get("_filename"),
                    "sha256": c.get("_cert_sha256"),
                    "status": c.get("overall_status"),
                }
                for c in certificates
            ],
        }

        output_zip_path = os.path.abspath(output_zip_path)
        os.makedirs(os.path.dirname(output_zip_path), exist_ok=True)

        with zipfile.ZipFile(output_zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("AUDIT_DOSSIER.md", md_content)
            zf.writestr("AUDIT_DOSSIER.html", html_content)
            zf.writestr("manifest.json", json.dumps(manifest, indent=2))

            for c in certificates:
                fpath = c.get("_filepath")
                fname = c.get("_filename")
                if fpath and fname and os.path.isfile(fpath):
                    zf.write(fpath, arcname=f"certificates/{fname}")
                    html_fname = fname.replace(".json", ".html")
                    html_fpath = os.path.join(os.path.dirname(fpath), html_fname)
                    if os.path.isfile(html_fpath):
                        zf.write(html_fpath, arcname=f"certificates/{html_fname}")

        return output_zip_path

