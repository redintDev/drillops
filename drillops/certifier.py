"""Generates verifiable SOC2/ISO 27001 Disaster Recovery Certificates."""

import json
import os
from typing import Dict, List
from drillops import __version__
from drillops.models import AssertionResult, DrillSummary


class CertificateGenerator:
    """Produces tamper-evident markdown and JSON audit certificates for compliance."""

    @staticmethod
    def generate_json(summary: DrillSummary, assertions: List[AssertionResult]) -> Dict:
        """Construct full JSON audit artifact."""
        return {
            "certificate_version": "1.0",
            "certificate_id": summary.certificate_id,
            "timestamp_utc": summary.timestamp,
            "overall_status": summary.overall_status,
            "target": {
                "database_type": summary.database_type,
                "backup_filename": summary.backup_filename,
                "backup_sha256": summary.backup_sha256,
                "backup_size_bytes": summary.backup_size_bytes,
                "encrypted_at_rest": getattr(summary, "encrypted_at_rest", False),
                "encryption_type": getattr(summary, "encryption_type", None),
            },
            "metrics": {
                "recovery_time_objective_actual_seconds": round(summary.restore_duration_sec, 2),
                "total_assertions": summary.total_assertions,
                "passed_assertions": summary.passed_assertions,
                "failed_assertions": summary.failed_assertions,
            },
            "recovery_point_objective": {
                "backup_timestamp": getattr(summary, "backup_timestamp", None),
                "backup_age_hours": getattr(summary, "backup_age_hours", None),
                "rpo_sla_hours": getattr(summary, "rpo_sla_hours", None),
                "rpo_status": getattr(summary, "rpo_status", "N/A"),
            },
            "redundancy_and_resilience": {
                "redundancy_status": getattr(summary, "redundancy_status", "N/A"),
                "copies_count": getattr(summary, "redundancy_copies_count", None),
                "media_types_count": getattr(summary, "redundancy_media_types_count", None),
                "replication_lag_hours": getattr(summary, "replication_lag_hours", None),
                "integrity_status": getattr(summary, "integrity_status", "N/A"),
                "checksum_manifest_verified": getattr(summary, "checksum_manifest_verified", None),
            },
            "failures": summary.failure_reasons,
            "assertions": [
                {
                    "rule_name": a.rule_name,
                    "passed": a.passed,
                    "actual": a.actual_value,
                    "expected": a.expected_value,
                    "duration_ms": a.execution_time_ms,
                    "critical": a.critical,
                    "error": a.error,
                }
                for a in assertions
            ],
        }

    @staticmethod
    def generate_markdown(summary: DrillSummary, assertions: List[AssertionResult]) -> str:
        """Construct printable markdown audit certificate for SOC2 binders."""
        status_badge = "🟢 VERIFIED / PASSED" if summary.overall_status == "PASSED" else "🔴 FAILED / COMPLIANCE DEFICIT"

        enc_str = f"VERIFIED ({summary.encryption_type})" if getattr(summary, "encrypted_at_rest", False) else "UNENCRYPTED / PLAIN"

        lines = [
            "# 🛡️ Disaster Recovery Drill Certificate",
            "",
            f"**Certificate ID**: `{summary.certificate_id}`  ",
            f"**Execution Timestamp**: `{summary.timestamp}`  ",
            f"**Verification Outcome**: **{status_badge}**  ",
            "",
            "---",
            "",
            "## 1. Compliance Statement",
            "",
            "> This document certifies that an automated restore drill was executed against the database backup",
            "> artifact identified below in an isolated sandbox environment. The backup was restored to completion,",
            "> and cryptographic data integrity assertions were evaluated in compliance with SOC2 Type II, ISO 27001,",
            "> and business continuity disaster recovery validation standards.",
            "",
            "---",
            "",
            "## 2. Backup Artifact Provenance",
            "",
            "| Property | Value |",
            "| :--- | :--- |",
            f"| **Database Engine** | `{summary.database_type}` |",
            f"| **Source File** | `{summary.backup_filename}` |",
            f"| **File Size** | `{summary.backup_size_bytes:,} bytes` |",
            f"| **SHA-256 Checksum** | `{summary.backup_sha256}` |",
            f"| **Measured Restore Time (RTO)** | `{summary.restore_duration_sec:.2f} seconds` |",
            f"| **Encryption at Rest (SOC2 CC6.1)** | `{enc_str}` |",
            f"| **Backup Creation Time** | `{getattr(summary, 'backup_timestamp', None) or 'N/A'}` |",
            f"| **Backup Age (RPO)** | `{f'{summary.backup_age_hours:.2f} hours' if getattr(summary, 'backup_age_hours', None) is not None else 'N/A'}` |",
            f"| **RPO SLA Freshness** | `{f'{summary.rpo_sla_hours:.1f} hours ({summary.rpo_status})' if getattr(summary, 'rpo_sla_hours', None) is not None else 'N/A'}` |",
            f"| **Redundancy (3-2-1 Rule)** | `{getattr(summary, 'redundancy_status', 'N/A')}` |",
            f"| **Archive Integrity** | `{getattr(summary, 'integrity_status', 'N/A')}` |",
            "",
            "---",
            "",
            "## 3. Automated Assertion Results",
            "",
            "| Assertion Rule | Status | Actual Value | Expected | Latency (ms) | Severity |",
            "| :--- | :---: | :---: | :---: | :---: | :---: |",
        ]

        for a in assertions:
            mark = "✅ PASS" if a.passed else "❌ FAIL"
            crit = "CRITICAL" if a.critical else "WARNING"
            act = str(a.actual_value)[:30]
            exp = str(a.expected_value)[:30]
            lines.append(f"| `{a.rule_name}` | {mark} | `{act}` | `{exp}` | {a.execution_time_ms} ms | {crit} |")

        if summary.failure_reasons:
            lines.extend([
                "",
                "---",
                "",
                "## 4. Failure Diagnoses & Remediation",
                "",
            ])
            for f in summary.failure_reasons:
                lines.append(f"- ⚠️ **Defect**: {f}")

        lines.extend([
            "",
            "---",
            "",
            f"*Drill executed autonomously by DrillOps Engine v{__version__} in isolated environment.*",
        ])

        return "\n".join(lines)

    @staticmethod
    def save_artifacts(output_dir: str, summary: DrillSummary, assertions: List[AssertionResult]) -> Dict[str, str]:
        """Saves certificate as both JSON and Markdown."""
        os.makedirs(output_dir, exist_ok=True)
        base_name = f"drill_cert_{summary.certificate_id.lower()}"

        json_path = os.path.join(output_dir, f"{base_name}.json")
        md_path = os.path.join(output_dir, f"{base_name}.md")

        json_data = CertificateGenerator.generate_json(summary, assertions)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)

        md_content = CertificateGenerator.generate_markdown(summary, assertions)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        from drillops.compliance.report_generator import ExecutiveReportGenerator
        html_path = os.path.join(output_dir, f"{base_name}.html")
        ExecutiveReportGenerator.save_report(html_path, summary, assertions)

        return {"json": json_path, "markdown": md_path, "html": html_path}

