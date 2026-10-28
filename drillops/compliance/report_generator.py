"""Executive Disaster Recovery Audit Report Generator for DrillOps.

Produces standalone, print-ready, CISO/Auditor-grade HTML documents
summarizing the complete Disaster Recovery Triad:
1. RTO (Recovery Time Objective): Restore duration, throughput, and performance.
2. RPO (Recovery Point Objective): Backup creation age, freshness SLA compliance.
3. 3-2-1 Redundancy: Multi-copy count, media type diversity, offsite replication parity.
4. Security & Compliance: Encryption at rest (SOC2 CC6.1), PII leak prevention, cold-storage integrity.
"""

from datetime import datetime, timezone
import json
import os
from typing import Any, Dict, List, Optional, Union

from drillops.models import AssertionResult, DrillSummary


class ExecutiveReportGenerator:
    """Generates standalone, CSS-styled, print-to-PDF ready executive disaster recovery reports."""

    @classmethod
    def generate_html_report(
        cls,
        summary: Union[DrillSummary, Dict[str, Any]],
        assertions: Optional[List[Union[AssertionResult, Dict[str, Any]]]] = None,
        company_name: str = "Organization",
    ) -> str:
        """Constructs a self-contained, publication-ready HTML compliance report."""
        # Normalize summary dictionary / dataclass
        if isinstance(summary, DrillSummary):
            cert_id = summary.certificate_id
            timestamp = summary.timestamp
            status = summary.overall_status
            db_type = summary.database_type
            fname = summary.backup_filename
            sha256 = summary.backup_sha256
            size_bytes = summary.backup_size_bytes
            rto_sec = summary.restore_duration_sec
            encrypted = summary.encrypted_at_rest
            enc_type = summary.encryption_type
            backup_ts = summary.backup_timestamp
            backup_age_h = summary.backup_age_hours
            rpo_sla_h = summary.rpo_sla_hours
            rpo_status = summary.rpo_status
            red_status = getattr(summary, "redundancy_status", "N/A")
            copies_cnt = getattr(summary, "redundancy_copies_count", None)
            media_cnt = getattr(summary, "redundancy_media_types_count", None)
            rep_lag_h = getattr(summary, "replication_lag_hours", None)
            int_status = getattr(summary, "integrity_status", "N/A")
            failures = summary.failure_reasons
        else:
            cert_id = summary.get("certificate_id", "UNKNOWN")
            timestamp = summary.get("timestamp_utc", summary.get("timestamp", ""))
            status = summary.get("overall_status", "UNKNOWN")
            target = summary.get("target", {})
            db_type = target.get("database_type", summary.get("database_type", "unknown"))
            fname = target.get("backup_filename", summary.get("backup_filename", "unknown"))
            sha256 = target.get("backup_sha256", summary.get("backup_sha256", "N/A"))
            size_bytes = int(target.get("backup_size_bytes", summary.get("backup_size_bytes", 0)))
            metrics = summary.get("metrics", {})
            rto_sec = float(metrics.get("recovery_time_objective_actual_seconds", summary.get("restore_duration_sec", 0.0)))
            encrypted = bool(target.get("encrypted_at_rest", summary.get("encrypted_at_rest", False)))
            enc_type = target.get("encryption_type", summary.get("encryption_type"))
            rpo_obj = summary.get("recovery_point_objective", {})
            backup_ts = rpo_obj.get("backup_timestamp", summary.get("backup_timestamp"))
            backup_age_h = rpo_obj.get("backup_age_hours", summary.get("backup_age_hours"))
            rpo_sla_h = rpo_obj.get("rpo_sla_hours", summary.get("rpo_sla_hours"))
            rpo_status = rpo_obj.get("rpo_status", summary.get("rpo_status", "N/A"))
            red_obj = summary.get("redundancy_and_resilience", {})
            red_status = red_obj.get("redundancy_status", summary.get("redundancy_status", "N/A"))
            copies_cnt = red_obj.get("copies_count", summary.get("redundancy_copies_count"))
            media_cnt = red_obj.get("media_types_count", summary.get("redundancy_media_types_count"))
            rep_lag_h = red_obj.get("replication_lag_hours", summary.get("replication_lag_hours"))
            int_status = red_obj.get("integrity_status", summary.get("integrity_status", "N/A"))
            failures = summary.get("failures", summary.get("failure_reasons", []))

        # Normalize assertions
        normalized_assertions = []
        if assertions is not None:
            for a in assertions:
                if isinstance(a, AssertionResult):
                    normalized_assertions.append({
                        "name": a.rule_name,
                        "passed": a.passed,
                        "actual": str(a.actual_value),
                        "expected": str(a.expected_value),
                        "duration_ms": a.execution_time_ms,
                        "critical": a.critical,
                        "error": a.error,
                    })
                elif isinstance(a, dict):
                    normalized_assertions.append({
                        "name": a.get("rule_name", a.get("name", "")),
                        "passed": a.get("passed", False),
                        "actual": str(a.get("actual", a.get("actual_value", ""))),
                        "expected": str(a.get("expected", a.get("expected_value", ""))),
                        "duration_ms": float(a.get("duration_ms", a.get("execution_time_ms", 0.0))),
                        "critical": a.get("critical", True),
                        "error": a.get("error"),
                    })
        elif isinstance(summary, dict) and "assertions" in summary:
            for a in summary["assertions"]:
                normalized_assertions.append({
                    "name": a.get("rule_name", ""),
                    "passed": a.get("passed", False),
                    "actual": str(a.get("actual", "")),
                    "expected": str(a.get("expected", "")),
                    "duration_ms": float(a.get("duration_ms", 0.0)),
                    "critical": a.get("critical", True),
                    "error": a.get("error"),
                })

        is_passed = (status == "PASSED")
        status_tag = "VERIFIED / SLA COMPLIANT" if is_passed else "COMPLIANCE DEFICIT"
        status_bg = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" if is_passed else "bg-rose-500/10 text-rose-400 border-rose-500/30"
        status_icon = "🟢" if is_passed else "🔴"

        # Assertion table rows
        table_rows = []
        for a in normalized_assertions:
            mark = "PASS" if a["passed"] else "FAIL"
            badge = '<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">PASS</span>' if a["passed"] else '<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">FAIL</span>'
            sev = '<span class="text-rose-400 font-semibold text-[11px]">CRITICAL</span>' if a["critical"] else '<span class="text-slate-400 text-[11px]">OPTIONAL</span>'
            table_rows.append(f"""
            <tr class="border-b border-slate-800 hover:bg-slate-800/30">
                <td class="px-4 py-2.5 font-mono text-cyan-400 text-xs">{a['name']}</td>
                <td class="px-4 py-2.5">{badge}</td>
                <td class="px-4 py-2.5 text-slate-300 text-xs font-mono">{a['actual'][:40]}</td>
                <td class="px-4 py-2.5 text-slate-400 text-xs font-mono">{a['expected'][:30]}</td>
                <td class="px-4 py-2.5 text-slate-400 text-xs font-mono">{a['duration_ms']:.1f}ms</td>
                <td class="px-4 py-2.5">{sev}</td>
            </tr>
            """)

        assertions_html = "\n".join(table_rows) if table_rows else '<tr><td colspan="6" class="px-4 py-4 text-center text-slate-400">No assertions recorded.</td></tr>'

        # Defect section
        failures_html = ""
        if failures:
            fail_items = "\n".join(f'<li class="text-rose-300 text-xs">⚠️ {f}</li>' for f in failures)
            failures_html = f"""
            <div class="p-4 rounded-xl bg-rose-950/20 border border-rose-800/40 space-y-2">
                <h3 class="text-xs font-bold uppercase tracking-wider text-rose-400">Detected Compliance Deficits & Failures</h3>
                <ul class="space-y-1 pl-2 list-disc list-inside">
                    {fail_items}
                </ul>
            </div>
            """

        rpo_text = f"{backup_age_h:.2f} hrs" if backup_age_h is not None else "N/A"
        rpo_sla_text = f"{rpo_sla_h:.1f} hrs ({rpo_status})" if rpo_sla_h is not None else "N/A"
        enc_text = f"YES ({enc_type})" if encrypted else "NO (UNENCRYPTED)"
        red_text = f"{red_status}" if red_status != "N/A" else "UNSPECIFIED"
        copies_text = f"{copies_cnt} copies" if copies_cnt is not None else "1 copy"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DrillOps Executive DR Audit Report - {cert_id}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @media print {{
            body {{ background-color: white !important; color: black !important; }}
            .no-print {{ display: none !important; }}
            .print-border {{ border: 1px solid #ddd !important; }}
            .bg-slate-900, .bg-slate-950 {{ background-color: white !important; color: black !important; }}
            .text-white {{ color: black !important; }}
            .text-slate-300, .text-slate-400 {{ color: #444 !important; }}
        }}
    </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen p-6 md:p-12 antialiased">
    <div class="max-w-5xl mx-auto space-y-8">

        <!-- Top Header & Actions -->
        <div class="flex flex-col md:flex-row justify-between items-start md:items-center pb-6 border-b border-slate-800 gap-4">
            <div>
                <div class="flex items-center gap-3">
                    <span class="text-3xl">🛡️</span>
                    <div>
                        <h1 class="text-2xl font-bold text-white tracking-tight">Executive Disaster Recovery Audit Report</h1>
                        <p class="text-xs text-slate-400 font-mono mt-0.5">Certificate ID: <strong class="text-cyan-400">{cert_id}</strong> &bull; Organization: <strong class="text-slate-200">{company_name}</strong></p>
                    </div>
                </div>
            </div>
            <div class="flex items-center gap-3">
                <span class="px-3 py-1 rounded-full border text-xs font-bold uppercase tracking-wider {status_bg}">{status_icon} {status_tag}</span>
                <button onclick="window.print()" class="no-print px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold border border-slate-700 transition">Print to PDF</button>
            </div>
        </div>

        <!-- Attestation Statement -->
        <div class="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-2">
            <h2 class="text-[11px] font-bold uppercase tracking-wider text-cyan-400">Formal Compliance Attestation Statement</h2>
            <p class="text-slate-300 text-xs leading-relaxed">
                This executive report certifies that an automated disaster recovery restoration drill was executed against the database backup artifact in an isolated sandbox environment without production disruption. All cryptographic proofs, recovery time objectives (RTO), recovery point objectives (RPO), and 3-2-1 backup redundancy constraints were evaluated under <strong>SOC2 CC9.1, SOC2 CC6.1, HIPAA §164.308, and ISO/IEC 27001:2022 Control A.8.13</strong>.
            </p>
        </div>

        <!-- 4-Pillar Disaster Recovery Triad & Security Dashboard -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
            <!-- Card 1: RTO -->
            <div class="p-4 rounded-xl bg-slate-900 border border-slate-800">
                <div class="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Pillar 1: RTO (Speed)</div>
                <div class="text-2xl font-bold font-mono text-white mt-1">{rto_sec:.2f}s</div>
                <div class="text-[11px] text-emerald-400 mt-1">Measured Restore Time</div>
            </div>

            <!-- Card 2: RPO -->
            <div class="p-4 rounded-xl bg-slate-900 border border-slate-800">
                <div class="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Pillar 2: RPO (Freshness)</div>
                <div class="text-2xl font-bold font-mono text-white mt-1">{rpo_text}</div>
                <div class="text-[11px] text-slate-400 mt-1">SLA: {rpo_sla_text}</div>
            </div>

            <!-- Card 3: 3-2-1 Redundancy -->
            <div class="p-4 rounded-xl bg-slate-900 border border-slate-800">
                <div class="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Pillar 3: 3-2-1 Redundancy</div>
                <div class="text-xl font-bold font-mono text-white mt-1 truncate">{red_text}</div>
                <div class="text-[11px] text-slate-400 mt-1">{copies_text} across storage tiers</div>
            </div>

            <!-- Card 4: Security & Integrity -->
            <div class="p-4 rounded-xl bg-slate-900 border border-slate-800">
                <div class="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Security & Sanitization</div>
                <div class="text-lg font-bold font-mono text-white mt-1 truncate">{enc_text}</div>
                <div class="text-[11px] text-slate-400 mt-1">Integrity: {int_status}</div>
            </div>
        </div>

        {failures_html}

        <!-- Artifact Provenance & Target Details -->
        <div class="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
            <div class="px-5 py-3 border-b border-slate-800 bg-slate-900/50 flex justify-between items-center">
                <h3 class="text-xs font-bold text-white uppercase tracking-wider">Backup Artifact Provenance</h3>
                <span class="text-[11px] font-mono text-slate-400">Timestamp: {timestamp}</span>
            </div>
            <div class="p-5 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div>
                    <span class="text-slate-400 block mb-0.5">Database Engine:</span>
                    <strong class="font-mono text-cyan-400">{db_type.upper()}</strong>
                </div>
                <div>
                    <span class="text-slate-400 block mb-0.5">Backup Artifact Name:</span>
                    <strong class="font-mono text-slate-200 truncate block">{fname}</strong>
                </div>
                <div>
                    <span class="text-slate-400 block mb-0.5">Artifact Size:</span>
                    <strong class="font-mono text-slate-200">{size_bytes:,} bytes</strong>
                </div>
                <div>
                    <span class="text-slate-400 block mb-0.5">SHA-256 Checksum:</span>
                    <strong class="font-mono text-slate-300 text-[11px] break-all">{sha256}</strong>
                </div>
            </div>
        </div>

        <!-- Assertion Verification Matrix -->
        <div class="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
            <div class="px-5 py-3 border-b border-slate-800 bg-slate-900/50 flex justify-between items-center">
                <h3 class="text-xs font-bold text-white uppercase tracking-wider">Automated Integrity & Compliance Assertions</h3>
                <span class="text-[11px] font-mono text-slate-400">{len(normalized_assertions)} rules evaluated</span>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left">
                    <thead class="bg-slate-950 text-[11px] uppercase tracking-wider text-slate-400 border-b border-slate-800 font-semibold">
                        <tr>
                            <th class="px-4 py-2.5">Rule / Assertion</th>
                            <th class="px-4 py-2.5">Status</th>
                            <th class="px-4 py-2.5">Actual Value</th>
                            <th class="px-4 py-2.5">Expected</th>
                            <th class="px-4 py-2.5">Latency</th>
                            <th class="px-4 py-2.5">Severity</th>
                        </tr>
                    </thead>
                    <tbody>
                        {assertions_html}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Executive Sign-Off & Attestation Seal -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6 pt-6 border-t border-slate-800 text-xs">
            <div class="space-y-4">
                <h4 class="font-bold text-slate-200 uppercase tracking-wider">Auditor Verification & Attestation</h4>
                <p class="text-slate-400 leading-relaxed text-[11px]">
                    This report represents automated machine attestation. Evidence can be cross-verified against cryptographic signatures and cold-storage object versions.
                </p>
                <div class="font-mono text-[10px] text-slate-500 bg-slate-950 p-3 rounded-lg border border-slate-800">
                    Engine: DrillOps Enterprise v0.1.0<br>
                    Cert SHA-256: {sha256[:32]}...
                </div>
            </div>

            <div class="space-y-4">
                <h4 class="font-bold text-slate-200 uppercase tracking-wider">Executive Review Sign-Off</h4>
                <div class="grid grid-cols-2 gap-4 pt-2">
                    <div class="border-b border-slate-700 pb-2">
                        <span class="text-[10px] text-slate-500 block">Lead Systems Engineer:</span>
                        <div class="h-6"></div>
                    </div>
                    <div class="border-b border-slate-700 pb-2">
                        <span class="text-[10px] text-slate-500 block">Chief Information Security Officer:</span>
                        <div class="h-6"></div>
                    </div>
                </div>
            </div>
        </div>

    </div>
</body>
</html>
"""

    @classmethod
    def save_report(
        cls,
        output_path: str,
        summary: Union[DrillSummary, Dict[str, Any]],
        assertions: Optional[List[Union[AssertionResult, Dict[str, Any]]]] = None,
        company_name: str = "Organization",
    ) -> str:
        """Saves the generated HTML executive report to the designated path."""
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        html_content = cls.generate_html_report(summary, assertions, company_name=company_name)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return output_path
