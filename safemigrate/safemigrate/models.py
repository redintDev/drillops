"""Core data models for SafeMigrate."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    """Lock severity rating for database operations."""
    CRITICAL = "CRITICAL"  # Full table exclusive lock (AccessExclusiveLock), blocks reads and writes
    HIGH = "HIGH"          # Blocks writes (ShareLock / ExclusiveLock)
    MEDIUM = "MEDIUM"      # Potential long-running table scan or lock upgrade
    LOW = "LOW"            # Brief metadata lock or best-practice violation
    INFO = "INFO"          # Advisory suggestion


class Dialect(str, Enum):
    """Supported SQL database dialects."""
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"


@dataclass
class Remediation:
    """Actionable zero-downtime multi-step SQL instructions."""
    title: str
    description: str
    steps: List[str] = field(default_factory=list)


@dataclass
class Violation:
    """A detected migration safety hazard or locking violation."""
    rule_id: str
    rule_name: str
    severity: Severity
    message: str
    line_number: int
    statement: str
    remediation: Optional[Remediation] = None

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "message": self.message,
            "line_number": self.line_number,
            "statement": self.statement.strip(),
            "remediation": {
                "title": self.remediation.title,
                "description": self.remediation.description,
                "steps": self.remediation.steps,
            } if self.remediation else None,
        }


@dataclass
class LintResult:
    """Aggregated lint results for a single migration file."""
    file_path: str
    violations: List[Violation] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """Returns True if there are zero CRITICAL or HIGH severity violations."""
        return not any(v.severity in (Severity.CRITICAL, Severity.HIGH) for v in self.violations)

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == Severity.LOW)
