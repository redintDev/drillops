"""Data models and configurations for DrillOps restore drill verification."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid


@dataclass
class AssertionRule:
    """A data verification assertion to run against the restored database."""
    name: str
    query: str
    operator: str = ">="  # '==', '!=', '>', '>=', '<', '<=', 'not_empty'
    expected_value: Any = 1
    critical: bool = True
    description: str = ""


@dataclass
class AssertionResult:
    """The outcome of an evaluated assertion rule."""
    rule_name: str
    passed: bool
    actual_value: Any
    expected_value: Any
    execution_time_ms: float
    error: Optional[str] = None
    critical: bool = True


@dataclass
class VerificationConfig:
    """Configuration defining the restore drill target and parameters."""
    database_type: str  # 'sqlite' or 'postgres'
    backup_path: str
    admin_database: str = "postgres"
    expected_tables: List[str] = field(default_factory=list)
    assertion_rules: List[AssertionRule] = field(default_factory=list)
    host: Optional[str] = None
    port: Optional[int] = None
    user: Optional[str] = None
    password: Optional[str] = None
    drop_on_completion: bool = True
    decrypt_passphrase: Optional[str] = None
    decrypt_cipher: Optional[str] = "aes-256-cbc"
    scan_pii: bool = False
    max_rpo_hours: Optional[float] = None
    replica_paths: List[str] = field(default_factory=list)
    max_replication_lag_hours: Optional[float] = None
    require_321_redundancy: bool = False
    verify_manifest_path: Optional[str] = None
    verify_integrity: bool = False


@dataclass
class DrillSummary:
    """High-level metrics and result summary of a restore drill."""
    certificate_id: str
    timestamp: str
    database_type: str
    backup_filename: str
    backup_sha256: str
    backup_size_bytes: int
    restore_duration_sec: float
    total_assertions: int
    passed_assertions: int
    failed_assertions: int
    overall_status: str  # 'PASSED' or 'FAILED'
    failure_reasons: List[str] = field(default_factory=list)
    encrypted_at_rest: bool = False
    encryption_type: Optional[str] = None
    backup_timestamp: Optional[str] = None
    backup_age_hours: Optional[float] = None
    rpo_sla_hours: Optional[float] = None
    rpo_status: str = "N/A"  # 'COMPLIANT', 'BREACHED', 'N/A'
    redundancy_status: str = "N/A"  # 'COMPLIANT', 'PARITY_MISMATCH', 'LAG_BREACHED', '321_NON_COMPLIANT', 'N/A'
    redundancy_copies_count: Optional[int] = None
    redundancy_media_types_count: Optional[int] = None
    replication_lag_hours: Optional[float] = None
    integrity_status: str = "N/A"  # 'VERIFIED', 'CORRUPT_ARCHIVE', 'MANIFEST_MISMATCH', 'N/A'
    checksum_manifest_verified: Optional[bool] = None

    @classmethod
    def create_new(
        cls,
        database_type: str,
        backup_filename: str,
        sha256: str,
        size: int,
        encrypted_at_rest: bool = False,
        encryption_type: Optional[str] = None,
        backup_timestamp: Optional[str] = None,
        backup_age_hours: Optional[float] = None,
        rpo_sla_hours: Optional[float] = None,
        rpo_status: str = "N/A",
        redundancy_status: str = "N/A",
        redundancy_copies_count: Optional[int] = None,
        redundancy_media_types_count: Optional[int] = None,
        replication_lag_hours: Optional[float] = None,
        integrity_status: str = "N/A",
        checksum_manifest_verified: Optional[bool] = None,
    ) -> "DrillSummary":
        cert_id = f"DRC-{uuid.uuid4().hex[:12].upper()}"
        now_utc = datetime.now(timezone.utc).isoformat()
        return cls(
            certificate_id=cert_id,
            timestamp=now_utc,
            database_type=database_type,
            backup_filename=backup_filename,
            backup_sha256=sha256,
            backup_size_bytes=size,
            restore_duration_sec=0.0,
            total_assertions=0,
            passed_assertions=0,
            failed_assertions=0,
            overall_status="INITIALIZED",
            encrypted_at_rest=encrypted_at_rest,
            encryption_type=encryption_type,
            backup_timestamp=backup_timestamp,
            backup_age_hours=backup_age_hours,
            rpo_sla_hours=rpo_sla_hours,
            rpo_status=rpo_status,
            redundancy_status=redundancy_status,
            redundancy_copies_count=redundancy_copies_count,
            redundancy_media_types_count=redundancy_media_types_count,
            replication_lag_hours=replication_lag_hours,
            integrity_status=integrity_status,
            checksum_manifest_verified=checksum_manifest_verified,
        )

