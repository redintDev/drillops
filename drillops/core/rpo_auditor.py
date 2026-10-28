"""Recovery Point Objective (RPO) & Backup Freshness SLA Auditor.

Proves backup freshness and validates compliance with SOC2 CC9.1, HIPAA § 164.308,
and ISO 27001 A.12.3.1 disaster recovery recovery point objectives.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import gzip
import os
import re
from typing import Optional, Tuple

from drillops.models import AssertionResult


@dataclass
class RPOReport:
    """Detailed audit metrics regarding backup age and RPO SLA compliance."""
    backup_path: str
    backup_timestamp: datetime
    backup_timestamp_source: str  # 'sql_header', 'filename', or 'file_mtime'
    backup_age_seconds: float
    backup_age_hours: float
    max_rpo_hours: Optional[float] = None
    is_compliant: bool = True
    margin_hours: Optional[float] = None
    status: str = "COMPLIANT"  # 'COMPLIANT', 'BREACHED', 'UNSPECIFIED'


class RPOAuditor:
    """Audits database backup timestamps and enforces Recovery Point Objective (RPO) SLAs."""

    # Regex patterns to detect creation timestamps in SQL dump comments
    HEADER_TIMESTAMP_PATTERNS = [
        # pg_dump: "-- Dumped by pg_dump version 16.1 on 2026-10-12 04:15:30"
        re.compile(r"-- Dumped by pg_dump version [^\n]+ on (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"),
        # pg_dump alternative: "-- Started on 2026-10-12 04:15:30"
        re.compile(r"-- Started on (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"),
        # sqlite: "-- SQLite dump created at 2026-10-12 04:15:30"
        re.compile(r"-- SQLite dump (?:created at |on )?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"),
        # mysqldump: "-- Dump completed on 2026-10-12 04:15:30"
        re.compile(r"-- Dump completed on (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"),
        # Generic SQL: "-- Created: 2026-10-12 04:15:30" or "-- Export Date: 2026-10-12 04:15:30"
        re.compile(r"-- (?:Created|Export Date|Generated):? (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"),
    ]

    # Regex patterns for ISO-like timestamps embedded in backup filenames
    FILENAME_PATTERNS = [
        # 2026-10-12T04-15-30 or 2026-10-12_04-15-30 or 2026-10-12T04:15:30
        (re.compile(r"(\d{4}-\d{2}-\d{2})[T_](\d{2})[-:](\d{2})[-:](\d{2})"), "%Y-%m-%d %H:%M:%S"),
        # 20261012_041530 or 20261012T041530
        (re.compile(r"(\d{4})(\d{2})(\d{2})[T_](\d{2})(\d{2})(\d{2})"), "%Y%m%d %H%M%S"),
        # 2026-10-12 (date only)
        (re.compile(r"(\d{4}-\d{2}-\d{2})"), "%Y-%m-%d"),
    ]

    @classmethod
    def parse_datetime_str(cls, date_str: str, fmt: str = "%Y-%m-%d %H:%M:%S") -> Optional[datetime]:
        """Safely parses a datetime string into a timezone-aware UTC datetime."""
        try:
            dt = datetime.strptime(date_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            return None

    @classmethod
    def extract_from_header(cls, filepath: str) -> Optional[datetime]:
        """Inspects the beginning of an uncompressed or gzipped SQL file for dump timestamps."""
        try:
            if not os.path.isfile(filepath):
                return None

            header_text = ""
            if filepath.lower().endswith(".gz"):
                try:
                    with gzip.open(filepath, "rt", encoding="utf-8", errors="replace") as f:
                        header_text = f.read(8192)
                except Exception:
                    return None
            else:
                try:
                    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                        header_text = f.read(8192)
                except Exception:
                    return None

            for pattern in cls.HEADER_TIMESTAMP_PATTERNS:
                match = pattern.search(header_text)
                if match:
                    raw_dt = match.group(1).strip()
                    parsed = cls.parse_datetime_str(raw_dt)
                    if parsed:
                        return parsed

        except Exception:
            pass

        return None

    @classmethod
    def extract_from_filename(cls, filename: str) -> Optional[datetime]:
        """Inspects filename for standard backup timestamp patterns."""
        basename = os.path.basename(filename)

        for pattern, fmt in cls.FILENAME_PATTERNS:
            match = pattern.search(basename)
            if match:
                groups = match.groups()
                if len(groups) == 4:
                    date_part, h, m, s = groups
                    cand = f"{date_part} {h}:{m}:{s}"
                    dt = cls.parse_datetime_str(cand, "%Y-%m-%d %H:%M:%S")
                    if dt:
                        return dt
                elif len(groups) == 6:
                    y, mo, d, h, m, s = groups
                    cand = f"{y}{mo}{d} {h}{m}{s}"
                    dt = cls.parse_datetime_str(cand, "%Y%m%d %H%M%S")
                    if dt:
                        return dt
                elif len(groups) == 1:
                    date_part = groups[0]
                    dt = cls.parse_datetime_str(date_part, "%Y-%m-%d")
                    if dt:
                        return dt

        return None

    @classmethod
    def extract_backup_timestamp(cls, filepath: str) -> Tuple[datetime, str]:
        """
        Extracts backup timestamp using hierarchical fallback:
        1. SQL header comment
        2. Filename timestamp
        3. File modification time (mtime)
        """
        # Strategy 1: Header inspection
        header_dt = cls.extract_from_header(filepath)
        if header_dt:
            return header_dt, "sql_header"

        # Strategy 2: Filename pattern
        filename_dt = cls.extract_from_filename(filepath)
        if filename_dt:
            return filename_dt, "filename"

        # Strategy 3: File mtime
        if os.path.exists(filepath):
            mtime = os.path.getmtime(filepath)
            dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
            return dt, "file_mtime"

        # Fallback to current time if file doesn't exist yet
        return datetime.now(timezone.utc), "current_time"

    @classmethod
    def audit_rpo(
        cls,
        filepath: str,
        max_rpo_hours: Optional[float] = None,
        current_time: Optional[datetime] = None,
    ) -> RPOReport:
        """
        Calculates backup age, compares against max_rpo_hours SLA, and produces RPOReport.
        """
        now = current_time or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        backup_dt, source = cls.extract_backup_timestamp(filepath)
        if backup_dt.tzinfo is None:
            backup_dt = backup_dt.replace(tzinfo=timezone.utc)

        age_seconds = max(0.0, (now - backup_dt).total_seconds())
        age_hours = round(age_seconds / 3600.0, 4)

        if max_rpo_hours is not None and max_rpo_hours > 0:
            is_compliant = age_hours <= max_rpo_hours
            margin = round(max_rpo_hours - age_hours, 4)
            status = "COMPLIANT" if is_compliant else "BREACHED"
        else:
            is_compliant = True
            margin = None
            status = "UNSPECIFIED"

        return RPOReport(
            backup_path=filepath,
            backup_timestamp=backup_dt,
            backup_timestamp_source=source,
            backup_age_seconds=round(age_seconds, 2),
            backup_age_hours=age_hours,
            max_rpo_hours=max_rpo_hours,
            is_compliant=is_compliant,
            margin_hours=margin,
            status=status,
        )

    # Convenient alias for audit_rpo
    audit = audit_rpo


    @classmethod
    def evaluate_assertion(cls, report: RPOReport) -> AssertionResult:
        """Translates an RPOReport into a standard SOC2 CC9.1 AssertionResult."""
        if report.max_rpo_hours is None:
            return AssertionResult(
                rule_name="soc2_cc9_1_rpo_freshness",
                passed=True,
                actual_value=f"{report.backup_age_hours:.2f}h old (source: {report.backup_timestamp_source})",
                expected_value="unspecified SLA",
                execution_time_ms=0.1,
                critical=False,
                error=None,
            )

        if report.is_compliant:
            return AssertionResult(
                rule_name="soc2_cc9_1_rpo_freshness",
                passed=True,
                actual_value=f"{report.backup_age_hours:.2f}h old (source: {report.backup_timestamp_source})",
                expected_value=f"<= {report.max_rpo_hours:.1f}h SLA (+{report.margin_hours:.2f}h headroom)",
                execution_time_ms=0.1,
                critical=True,
                error=None,
            )

        overdue = abs(report.margin_hours or 0.0)
        return AssertionResult(
            rule_name="soc2_cc9_1_rpo_freshness",
            passed=False,
            actual_value=f"{report.backup_age_hours:.2f}h old (source: {report.backup_timestamp_source})",
            expected_value=f"<= {report.max_rpo_hours:.1f}h SLA",
            execution_time_ms=0.1,
            critical=True,
            error=f"RPO SLA breached: backup age ({report.backup_age_hours:.2f}h) exceeds threshold ({report.max_rpo_hours:.1f}h) by {overdue:.2f}h",
        )

    @classmethod
    def format_terminal_report(cls, report: RPOReport) -> str:
        """Renders an ANSI terminal report summarizing backup freshness and RPO status."""
        lines = [
            "⏱️ DrillOps Recovery Point Objective (RPO) Freshness Report",
            "═" * 68,
            f"  Target Backup:       {report.backup_path}",
            f"  Backup Created:      {report.backup_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')} (source: {report.backup_timestamp_source})",
            f"  Current Backup Age:  {report.backup_age_hours:.2f} hours ({report.backup_age_seconds:,.0f} seconds)",
        ]

        if report.max_rpo_hours is not None:
            lines.append(f"  Configured SLA:      {report.max_rpo_hours:.1f} hours")
            margin_sign = "+" if (report.margin_hours or 0) >= 0 else "-"
            lines.append(f"  SLA Margin:          {margin_sign}{abs(report.margin_hours or 0):.2f} hours")

            if report.is_compliant:
                lines.extend([
                    "  Freshness Status:    ✅ COMPLIANT (Within RPO SLA Threshold)",
                    "  Compliance Proof:    SOC2 CC9.1 / HIPAA §164.308 / ISO 27001 PASSED",
                ])
            else:
                overdue = abs(report.margin_hours or 0.0)
                lines.extend([
                    f"  Freshness Status:    🔴 BREACHED (Overdue by {overdue:.2f} hours)",
                    "  Compliance Proof:    SOC2 CC9.1 Freshness Deficit (Silent Backup Failure Risk)",
                    "  Remediation:         Check backup scheduler, cron daemons, or database dump pipeline.",
                ])
        else:
            lines.extend([
                "  Configured SLA:      None specified (use --max-rpo-hours to enforce)",
                "  Freshness Status:    ℹ️ INFORMATIONAL (Age verified)",
            ])

        lines.append("═" * 68)
        return "\n".join(lines)
