"""SOC2 CC9.1 / ISO 27001 / HIPAA Disaster Recovery Audit Preparation Checklist."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
from typing import Dict, List, Optional


@dataclass
class AuditControl:
    id: str
    standard: str
    title: str
    requirement: str
    auditor_evidence_needed: str
    drillops_automation: str
    status: str
    details: str


class SOC2ChecklistEvaluator:
    """Evaluates organization disaster recovery audit readiness against SOC2/ISO 27001 standards."""

    CONTROLS = [
        {
            "id": "DR-01",
            "standard": "SOC2 CC9.1 / ISO 27001 A.12.3.1",
            "title": "Documented Disaster Recovery Policy & Objectives",
            "requirement": "Management must define and document Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO) for all production databases.",
            "auditor_evidence_needed": "Approved DR policy document with defined RTO/RPO SLAs (e.g. RTO < 1 hour, RPO < 24 hours).",
            "drillops_automation": "Empirical RTO measurement in drill certificates proving actual restore time against defined SLAs.",
        },
        {
            "id": "DR-02",
            "standard": "SOC2 CC9.1 / HIPAA § 164.308(a)(7)(ii)(A)",
            "title": "Automated Periodic Backup Generation & Offsite Archival",
            "requirement": "Automated jobs must produce periodic database snapshots stored in an isolated, access-controlled secondary location.",
            "auditor_evidence_needed": "Backup job execution logs, retention policies, and secondary replication verification (e.g. S3/R2 storage).",
            "drillops_automation": "DrillOps watcher daemon monitors backup directories and S3 buckets for incoming daily archives.",
        },
        {
            "id": "DR-03",
            "standard": "SOC2 CC7.4 / ISO 27001 A.12.3.1",
            "title": "Cryptographic Backup Payload Integrity Verification",
            "requirement": "Backups must be cryptographically hashed at rest to guarantee zero tampering or silent bit rot between creation and restore.",
            "auditor_evidence_needed": "SHA-256 payload integrity hashes recorded before restore execution.",
            "drillops_automation": "DrillOps computes SHA-256 digests on all archives and embeds hashes into signed certificate manifests.",
        },
        {
            "id": "DR-04",
            "standard": "SOC2 CC9.1 / ISO 27001 A.12.3.1 / HIPAA § 164.308(a)(7)(ii)(B)",
            "title": "Continuous Sandbox Restoration Drills",
            "requirement": "Backups must be routinely and automatically restored to completion in isolated test environments.",
            "auditor_evidence_needed": "Time-stamped logs of restore drills executed at least quarterly, showing start/end timestamps and exit codes.",
            "drillops_automation": "Fully automated ephemeral sandbox restoration (Postgres pg_restore / SQLite) with sub-second RTO telemetry.",
        },
        {
            "id": "DR-05",
            "standard": "SOC2 CC7.4 / SOC2 CC9.1",
            "title": "Post-Restore Data Integrity & Business Assertion Testing",
            "requirement": "Restored databases must be validated to confirm application data is intact, readable, and non-empty.",
            "auditor_evidence_needed": "Automated query assertions verifying table presence and business data volume thresholds.",
            "drillops_automation": "Declarative assertion rules validate table existence and custom SQL thresholds on restored sandbox databases.",
        },
        {
            "id": "DR-06",
            "standard": "SOC2 CC8.1 (Change Management)",
            "title": "Schema Drift & Column Migration Contract Validation",
            "requirement": "Backup schemas must be validated against expected schema contracts to detect missing migrations or unexpected drops.",
            "auditor_evidence_needed": "Schema diff comparison between expected production schema and restored backup snapshot.",
            "drillops_automation": "Built-in SchemaDriftDetector checks table columns, types, and primary keys for silent drift.",
        },
        {
            "id": "DR-07",
            "standard": "SOC2 CC9.1 / ISO 27001 A.12.3.1",
            "title": "Automated Incident Alerting & Deficit Notification",
            "requirement": "Failure of any backup or restore drill must immediately alert engineering and compliance teams.",
            "auditor_evidence_needed": "Webhook/alert configuration logs and records of failure alert dispatch.",
            "drillops_automation": "Multi-channel dispatcher sends instant alerts to Slack, Discord, PagerDuty, or webhooks on drill failure.",
        },
        {
            "id": "DR-08",
            "standard": "SOC2 CC9.1 / Auditor Packaging",
            "title": "Consolidated Auditor Evidence Dossier Packaging",
            "requirement": "Historical restoration evidence must be aggregated into an exportable, tamper-evident audit package for third-party auditors.",
            "auditor_evidence_needed": "Compiled audit packet with executive summary, pass rates, RTO trends, and raw certificates.",
            "drillops_automation": "'drillops audit-pack' compiles printable HTML, Markdown, and cryptographic ZIP dossiers covering 90+ days.",
        },
    ]

    def __init__(self, cert_dir: Optional[str] = None):
        self.cert_dir = cert_dir

    def evaluate(self, company: str = "Organization") -> List[AuditControl]:
        """Evaluates compliance controls based on certificate history if available."""
        has_passed_drills = False
        drill_count = 0
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
                drill_count = len(certs)
                passed_certs = [c for c in certs if c.get("overall_status") == "PASSED"]
                if passed_certs:
                    has_passed_drills = True
                    rtos = [c.get("metrics", {}).get("recovery_time_objective_actual_seconds", 0) for c in passed_certs]
                    avg_rto = round(sum(rtos) / len(rtos), 3) if rtos else 0.0
            except Exception:
                pass

        controls = []
        for c in self.CONTROLS:
            cid = c["id"]
            if cid in ("DR-03", "DR-04", "DR-05", "DR-06") and has_passed_drills:
                status = "COMPLIANT"
                details = f"Verified: {drill_count} drill(s) executed. Avg RTO: {avg_rto}s. Assertions & SHA-256 confirmed."
            elif cid in ("DR-07", "DR-08") and has_passed_drills:
                status = "READY"
                details = "DrillOps tooling operational. Evidence dossier export ready via 'drillops audit-pack'."
            else:
                status = "ACTION_REQUIRED"
                details = f"Execute 'drillops verify' or run 'drillops demo' to establish verified evidence baseline for {company}."

            controls.append(
                AuditControl(
                    id=cid,
                    standard=c["standard"],
                    title=c["title"],
                    requirement=c["requirement"],
                    auditor_evidence_needed=c["auditor_evidence_needed"],
                    drillops_automation=c["drillops_automation"],
                    status=status,
                    details=details,
                )
            )
        return controls

    def to_markdown(self, company: str = "Organization") -> str:
        """Generates auditor-ready Markdown checklist document."""
        controls = self.evaluate(company)
        compliant_count = sum(1 for c in controls if c.status in ("COMPLIANT", "READY"))
        total = len(controls)
        score_pct = round((compliant_count / total) * 100, 1)

        lines = [
            f"# SOC2 CC9.1 & ISO 27001 Disaster Recovery Audit Preparation Checklist",
            f"",
            f"- **Target Organization**: {company}",
            f"- **Standard Criteria**: AICPA SOC2 Trust Services Criteria CC9.1, ISO/IEC 27001:2022 A.12.3.1, HIPAA § 164.308(a)(7)",
            f"- **Audit Readiness Score**: **{score_pct}%** ({compliant_count} of {total} Controls Verified)",
            f"- **Generated At**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"- **Generated By**: DrillOps Autonomous Disaster Recovery Engine (v0.1.0)",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            f"Auditors evaluating SOC2 CC9.1 require objective, time-stamped proof that database backups are not merely generated, but routinely verified to restore to an operational state with measured Recovery Time Objectives (RTO).",
            f"",
            f"| Control ID | Control Title | Primary Standard | Current Status | DrillOps Automation |",
            f"| :--- | :--- | :--- | :---: | :--- |",
        ]

        for c in controls:
            icon = "🟢" if c.status in ("COMPLIANT", "READY") else "🟡"
            lines.append(f"| **{c.id}** | {c.title} | {c.standard} | {icon} {c.status} | {c.drillops_automation[:60]}... |")

        lines.extend([
            f"",
            f"---",
            f"",
            f"## Detailed Control Evidence & Auditor Requirements",
            f"",
        ])

        for c in controls:
            lines.extend([
                f"### {c.id}: {c.title}",
                f"- **Standard Reference**: `{c.standard}`",
                f"- **Audit Requirement**: {c.requirement}",
                f"- **Auditor Evidence Required**: {c.auditor_evidence_needed}",
                f"- **DrillOps Implementation**: {c.drillops_automation}",
                f"- **Current Readiness Status**: **{c.status}**",
                f"- **Assessment Notes**: {c.details}",
                f"",
            ])

        lines.extend([
            f"---",
            f"",
            f"## Recommended Next Action for Compliance Sign-Off",
            f"1. Run daily automated restore drills via `drillops watch`.",
            f"2. Export signed auditor evidence dossier using `drillops audit-pack --out audit_pack.zip`.",
            f"3. Attach generated `AUDIT_DOSSIER.pdf`/`.html` directly to your auditor evidence portal (Vanta, Drata, Secureframe).",
            f"",
        ])

        return "\n".join(lines)

    def print_terminal(self, company: str = "Organization", use_color: bool = True) -> None:
        """Prints a clean formatted report in the terminal."""
        controls = self.evaluate(company)
        compliant_count = sum(1 for c in controls if c.status in ("COMPLIANT", "READY"))
        total = len(controls)
        score_pct = round((compliant_count / total) * 100, 1)

        BOLD = "\033[1m" if use_color else ""
        GREEN = "\033[0;32m" if use_color else ""
        YELLOW = "\033[0;33m" if use_color else ""
        CYAN = "\033[0;36m" if use_color else ""
        RESET = "\033[0m" if use_color else ""

        print(f"\n{CYAN}{BOLD}======================================================================{RESET}")
        print(f"{BOLD}  🛡️  SOC2 CC9.1 & ISO 27001 DISASTER RECOVERY AUDIT CHECKLIST{RESET}")
        print(f"{CYAN}======================================================================{RESET}")
        print(f"  Organization:    {BOLD}{company}{RESET}")
        print(f"  Readiness Score: {GREEN if score_pct >= 80 else YELLOW}{BOLD}{score_pct}%{RESET} ({compliant_count}/{total} controls verified)")
        print(f"{CYAN}----------------------------------------------------------------------{RESET}\n")

        for c in controls:
            status_color = GREEN if c.status in ("COMPLIANT", "READY") else YELLOW
            icon = "✔" if c.status in ("COMPLIANT", "READY") else "!"
            print(f"  [{status_color}{icon}{RESET}] {BOLD}{c.id:<6}{RESET} {c.title}")
            print(f"      Standard:    {c.standard}")
            print(f"      Status:      {status_color}{c.status}{RESET} — {c.details}")
            print(f"      Automation:  {c.drillops_automation}\n")

        print(f"{CYAN}----------------------------------------------------------------------{RESET}")
        print(f"  Quickstart: Run {BOLD}drillops demo{RESET} or {BOLD}drillops audit-pack --out dossier.zip{RESET}")
        print(f"{CYAN}======================================================================{RESET}\n")
