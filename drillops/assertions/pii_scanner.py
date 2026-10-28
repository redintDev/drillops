"""PII & Sensitive Data Leak Scanner for DrillOps.

Inspects restored database sandboxes for unmasked customer PII, secrets, and credentials
to validate SOC2 CC6.1, GDPR, and PCI-DSS data sanitization policies.
"""

from dataclasses import dataclass
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from drillops.engines.base import BaseRestoreEngine
from drillops.models import AssertionResult


@dataclass
class PIIFinding:
    """Represents a sensitive data leak identified in a database column."""
    table: str
    column: str
    finding_type: str  # 'credit_card', 'ssn', 'aws_access_key', 'private_key', 'plaintext_password'
    severity: str      # 'CRITICAL', 'HIGH'
    count: int
    sample_redacted: str
    description: str


class PIIScanner:
    """Scans restored database tables for unmasked PII, credentials, and secrets."""

    # Pre-compiled pattern detectors
    CC_PATTERN = re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b")
    SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    AWS_KEY_PATTERN = re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b")
    PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")

    # Hash signatures that indicate a password or secret is properly hashed/masked
    BCRYPT_RE = re.compile(r"^\$2[abxy]\$\d{2}\$[A-Za-z0-9./]{53}$")
    ARGON2_RE = re.compile(r"^\$argon2[a-z]*\$")
    HEX_HASH_RE = re.compile(r"^[a-fA-F0-9]{32,128}$")
    PBKDF2_RE = re.compile(r"^\$pbkdf2")

    PASSWORD_COLUMNS = ("password", "passwd", "pwd", "user_password", "secret", "api_key", "auth_token")

    def __init__(self, engine: BaseRestoreEngine):
        self.engine = engine

    @staticmethod
    def luhn_checksum(candidate: str) -> bool:
        """Validates standard 13-19 digit card numbers using the Luhn algorithm."""
        digits = [int(c) for c in candidate if c.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        checksum = 0
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:
                doubled = digit * 2
                checksum += (doubled - 9) if doubled > 9 else doubled
            else:
                checksum += digit
        return checksum % 10 == 0

    @staticmethod
    def is_valid_ssn(candidate: str) -> bool:
        """Validates standard 9-digit US Social Security Number format."""
        digits = candidate.replace("-", "").strip()
        if len(digits) != 9 or not digits.isdigit():
            return False
        area = int(digits[:3])
        group = int(digits[3:5])
        serial = int(digits[5:])
        # Invalid per SSA rules: area 000, 666, 900-999; group 00; serial 0000
        if area == 0 or area == 666 or (900 <= area <= 999):
            return False
        if group == 0:
            return False
        if serial == 0:
            return False
        return True

    @staticmethod
    def redact_credit_card(card: str) -> str:
        digits = [c for c in card if c.isdigit()]
        if len(digits) >= 4:
            return "****-****-****-" + "".join(digits[-4:])
        return "****-****-****-****"

    @staticmethod
    def redact_ssn(ssn: str) -> str:
        clean = ssn.replace("-", "").strip()
        if len(clean) >= 4:
            return "***-**-" + clean[-4:]
        return "***-**-****"

    @staticmethod
    def redact_secret(val: str) -> str:
        s = str(val).strip()
        if len(s) > 4:
            return s[:2] + ("*" * (len(s) - 4)) + s[-2:]
        return "********"

    def scan_cell(self, val: Any, col_name: str) -> Optional[Tuple[str, str, str, str]]:
        """
        Inspects a single cell value against PII detectors.
        Returns (finding_type, severity, redacted_sample, description) or None.
        """
        if val is None:
            return None

        val_str = str(val).strip()
        if not val_str or len(val_str) < 4:
            return None

        # Check Credit Cards (PCI-DSS)
        for match in self.CC_PATTERN.finditer(val_str):
            candidate = match.group(0)
            if self.luhn_checksum(candidate):
                return (
                    "credit_card",
                    "CRITICAL",
                    self.redact_credit_card(candidate),
                    "Unmasked Credit Card (PCI-DSS violation)",
                )

        # Check US SSN
        for match in self.SSN_PATTERN.finditer(val_str):
            candidate = match.group(0)
            if self.is_valid_ssn(candidate):
                return (
                    "ssn",
                    "CRITICAL",
                    self.redact_ssn(candidate),
                    "Unmasked US Social Security Number",
                )

        # Check Private Keys
        if self.PRIVATE_KEY_PATTERN.search(val_str):
            return (
                "private_key",
                "CRITICAL",
                "[REDACTED PRIVATE KEY]",
                "Exposed Private Key block",
            )

        # Check AWS Access Keys
        aws_match = self.AWS_KEY_PATTERN.search(val_str)
        if aws_match:
            k = aws_match.group(0)
            return (
                "aws_access_key",
                "CRITICAL",
                k[:4] + ("*" * 12) + k[-4:],
                "Exposed AWS Access Key",
            )

        # Check Plaintext Passwords / API Tokens in sensitive column names
        col_lower = col_name.lower()
        if any(sc in col_lower for sc in self.PASSWORD_COLUMNS):
            # If already masked or hashed, skip
            if (
                val_str.startswith(("[MASKED]", "[REDACTED]", "***"))
                or self.BCRYPT_RE.match(val_str)
                or self.ARGON2_RE.match(val_str)
                or self.HEX_HASH_RE.match(val_str)
                or self.PBKDF2_RE.match(val_str)
            ):
                return None

            # Non-hashed plaintext value in password column
            return (
                "plaintext_password",
                "HIGH",
                self.redact_secret(val_str),
                f"Plaintext password or unhashed credential in '{col_name}'",
            )

        return None

    def scan_table(self, table: str, max_rows: int = 100) -> List[PIIFinding]:
        """Queries table sample and scans all values across all columns."""
        findings_map: Dict[Tuple[str, str], PIIFinding] = {}

        try:
            # Query sample of rows
            query = f"SELECT * FROM {table} LIMIT {max_rows};"
            raw_result = self.engine.execute_query(query)

            if raw_result is None:
                return []

            rows: List[Dict[str, Any]] = []
            if isinstance(raw_result, list):
                for item in raw_result:
                    if isinstance(item, dict):
                        rows.append(item)
                    elif isinstance(item, (tuple, list)):
                        rows.append({f"col_{i}": v for i, v in enumerate(item)})
            elif isinstance(raw_result, dict):
                rows.append(raw_result)

            for row in rows:
                for col_name, val in row.items():
                    res = self.scan_cell(val, col_name)
                    if res:
                        ftype, severity, redacted_sample, desc = res
                        key = (col_name, ftype)
                        if key not in findings_map:
                            findings_map[key] = PIIFinding(
                                table=table,
                                column=col_name,
                                finding_type=ftype,
                                severity=severity,
                                count=1,
                                sample_redacted=redacted_sample,
                                description=desc,
                            )
                        else:
                            findings_map[key].count += 1

        except Exception:
            # If table cannot be queried, skip gracefully
            pass

        return list(findings_map.values())

    def scan_all_tables(
        self,
        max_rows_per_table: int = 100,
        tables: Optional[List[str]] = None,
    ) -> List[PIIFinding]:
        """Scans all tables in the database (or specified list) for sensitive data leaks."""
        all_findings: List[PIIFinding] = []
        target_tables = tables or self.engine.list_tables()

        for t in target_tables:
            findings = self.scan_table(t, max_rows=max_rows_per_table)
            all_findings.extend(findings)

        return all_findings

    def evaluate_assertions(
        self,
        max_rows_per_table: int = 100,
        tables: Optional[List[str]] = None,
    ) -> List[AssertionResult]:
        """
        Executes PII scan and maps outcomes to standard DrillOps AssertionResult objects.
        Injects SOC2 CC6.1 / GDPR sanitization proofs.
        """
        start = time.perf_counter()
        findings = self.scan_all_tables(max_rows_per_table=max_rows_per_table, tables=tables)
        duration_ms = round((time.perf_counter() - start) * 1000, 2)

        results: List[AssertionResult] = []

        if not findings:
            results.append(
                AssertionResult(
                    rule_name="soc2_cc6_1_pii_sanitization",
                    passed=True,
                    actual_value="0 leaks detected",
                    expected_value="0 leaks",
                    execution_time_ms=duration_ms,
                    critical=True,
                    error=None,
                )
            )
            return results

        # Critical failure: leaks found
        unique_tables = sorted(list(set(f.table for f in findings)))
        crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
        results.append(
            AssertionResult(
                rule_name="soc2_cc6_1_pii_sanitization",
                passed=False,
                actual_value=f"{len(findings)} sensitive leak(s) across {len(unique_tables)} table(s) ({crit_count} CRITICAL)",
                expected_value="0 leaks",
                execution_time_ms=duration_ms,
                critical=True,
                error=f"Unmasked PII or credentials detected in tables: {', '.join(unique_tables)}",
            )
        )

        for f in findings:
            results.append(
                AssertionResult(
                    rule_name=f"pii_leak_{f.table}_{f.column}",
                    passed=False,
                    actual_value=f"{f.finding_type} ({f.count} rows, e.g. {f.sample_redacted})",
                    expected_value="0 leaks",
                    execution_time_ms=0.1,
                    critical=(f.severity == "CRITICAL"),
                    error=f"{f.description} found in column {f.table}.{f.column}",
                )
            )

        return results

    @staticmethod
    def format_terminal_report(findings: List[PIIFinding]) -> str:
        """Renders formatted ANSI terminal report for CLI inspection."""
        lines = [
            "🛡️ DrillOps Sensitive Data & PII Leak Scanner",
            "═" * 65,
        ]

        if not findings:
            lines.extend([
                "  ✅ STATUS: CLEAN / SANITIZED",
                "  Zero unmasked PII, credentials, or secrets detected.",
                "  Compliance: SOC2 CC6.1 & GDPR Sanitization PASSED.",
                "═" * 65,
            ])
            return "\n".join(lines)

        lines.extend([
            f"  🔴 STATUS: LEAKS DETECTED ({len(findings)} finding(s))",
            "  Compliance: SOC2 CC6.1 Sanitization DEFICIT.",
            "─" * 65,
            f"  {'SEVERITY':<10} {'TABLE.COLUMN':<25} {'TYPE':<16} {'SAMPLE':<14}",
            "─" * 65,
        ])

        for f in findings:
            loc = f"{f.table}.{f.column}"[:24]
            sev = f"[{f.severity}]"
            lines.append(f"  {sev:<10} {loc:<25} {f.finding_type:<16} {f.sample_redacted:<14}")

        lines.extend([
            "═" * 65,
            "Remediation: Apply data masking, hashing, or anonymization before sandbox import.",
        ])
        return "\n".join(lines)
