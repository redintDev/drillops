"""Automated 3-2-1 Backup Redundancy and Cold-Storage Parity Auditor for DrillOps.

Enforces SOC2 CC9.1 and ISO 27001 Annex A.12.3.1 requirements:
- 3 copies of data (1 production + 2 backups)
- 2 distinct storage media types (e.g., local block/filesystem + cloud object storage)
- 1 offsite geographically isolated copy (e.g., AWS S3, Cloudflare R2, MinIO)
- Cryptographic checksum parity (SHA-256) between primary and replica archives
- Replication freshness / synchronization lag verification
- Encryption-at-rest verification across all backup locations (SOC2 CC6.1)
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from drillops.storage.archive import ArchiveProcessor
from drillops.core.rpo_auditor import RPOAuditor


@dataclass
class StorageCopy:
    """Represents a single evaluated backup copy across local or cloud storage."""
    location: str
    storage_type: str  # 'local', 's3', 'mock'
    size_bytes: int
    sha256: str
    timestamp: Optional[datetime] = None
    is_encrypted: bool = False
    encryption_type: Optional[str] = None
    is_offsite: bool = False
    healthy: bool = True
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "location": self.location,
            "storage_type": self.storage_type,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "is_encrypted": self.is_encrypted,
            "encryption_type": self.encryption_type,
            "is_offsite": self.is_offsite,
            "healthy": self.healthy,
            "error_message": self.error_message,
        }


@dataclass
class RedundancyReport:
    """Comprehensive SOC2 CC9.1 / ISO 27001 3-2-1 Redundancy Audit Report."""
    primary_location: str
    primary_copy: StorageCopy
    replicas: List[StorageCopy]
    total_copies_count: int  # Live database (1) + primary backup (1) + replicas (N)
    backup_copies_count: int  # primary backup (1) + replicas (N)
    distinct_media_types: List[str]
    offsite_copies_count: int
    is_321_compliant: bool
    checksum_parity: bool
    all_encrypted: bool
    observed_replication_lag_seconds: float
    max_replication_lag_hours: Optional[float]
    replication_lag_breached: bool
    status: str  # 'COMPLIANT', 'PARITY_MISMATCH', 'LAG_BREACHED', '321_NON_COMPLIANT', 'UNHEALTHY_REPLICA'
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "primary_location": self.primary_location,
            "primary_copy": self.primary_copy.to_dict(),
            "replicas": [r.to_dict() for r in self.replicas],
            "total_copies_count": self.total_copies_count,
            "backup_copies_count": self.backup_copies_count,
            "distinct_media_types": self.distinct_media_types,
            "offsite_copies_count": self.offsite_copies_count,
            "is_321_compliant": self.is_321_compliant,
            "checksum_parity": self.checksum_parity,
            "all_encrypted": self.all_encrypted,
            "observed_replication_lag_seconds": self.observed_replication_lag_seconds,
            "max_replication_lag_hours": self.max_replication_lag_hours,
            "replication_lag_breached": self.replication_lag_breached,
            "status": self.status,
            "summary": self.summary,
        }


class RedundancyAuditor:
    """
    Audits primary backups and secondary replicas across local disks and remote
    cloud storage (S3/R2/MinIO) to prove 3-2-1 disaster recovery compliance.
    """

    @classmethod
    def inspect_location(
        cls,
        location: str,
        work_dir: Optional[str] = None,
        s3_endpoint_url: Optional[str] = None,
        s3_region: Optional[str] = None,
    ) -> StorageCopy:
        """Inspects a backup location (local path or s3:// URI) and gathers provenance."""
        if location.startswith("s3://"):
            return cls._inspect_s3(
                location,
                work_dir=work_dir,
                endpoint_url=s3_endpoint_url,
                region_name=s3_region,
            )
        else:
            return cls._inspect_local(location)

    @classmethod
    def _inspect_local(cls, path: str) -> StorageCopy:
        """Inspects a local filesystem backup copy."""
        if not os.path.exists(path):
            return StorageCopy(
                location=path,
                storage_type="local",
                size_bytes=0,
                sha256="",
                is_offsite=False,
                healthy=False,
                error_message=f"File not found: {path}",
            )

        try:
            size_bytes = os.path.getsize(path)
            sha256 = ArchiveProcessor.calculate_sha256(path)
            enc_type = ArchiveProcessor.detect_encryption(path)
            is_enc = enc_type is not None

            # Extract timestamp using RPO extractor
            rpo_rep = RPOAuditor.audit_rpo(path)
            timestamp = rpo_rep.backup_timestamp

            return StorageCopy(
                location=path,
                storage_type="local",
                size_bytes=size_bytes,
                sha256=sha256,
                timestamp=timestamp,
                is_encrypted=is_enc,
                encryption_type=enc_type,
                is_offsite=False,
                healthy=True,
            )
        except Exception as e:
            return StorageCopy(
                location=path,
                storage_type="local",
                size_bytes=0,
                sha256="",
                healthy=False,
                error_message=str(e),
            )

    @classmethod
    def _inspect_s3(
        cls,
        s3_uri: str,
        work_dir: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        region_name: Optional[str] = None,
    ) -> StorageCopy:
        """Inspects a remote S3/R2 backup copy by streaming or downloading to staging."""
        from drillops.storage.providers import S3CompatibleStorageProvider, parse_s3_uri

        bucket, key = parse_s3_uri(s3_uri)
        provider = S3CompatibleStorageProvider(
            bucket_name=bucket,
            prefix=key,
            endpoint_url=endpoint_url,
            region_name=region_name,
        )

        staging_cleanup = False
        target_dir = work_dir
        if not target_dir:
            target_dir = tempfile.mkdtemp(prefix="drillops_s3_redundancy_")
            staging_cleanup = True

        try:
            staged_path = provider.download_object(key, target_dir)
            local_copy = cls._inspect_local(staged_path)
            return StorageCopy(
                location=s3_uri,
                storage_type="s3",
                size_bytes=local_copy.size_bytes,
                sha256=local_copy.sha256,
                timestamp=local_copy.timestamp,
                is_encrypted=local_copy.is_encrypted,
                encryption_type=local_copy.encryption_type,
                is_offsite=True,
                healthy=local_copy.healthy,
                error_message=local_copy.error_message,
            )
        except Exception as e:
            return StorageCopy(
                location=s3_uri,
                storage_type="s3",
                size_bytes=0,
                sha256="",
                is_offsite=True,
                healthy=False,
                error_message=f"S3 fetch failed: {e}",
            )
        finally:
            if staging_cleanup and os.path.exists(target_dir):
                import shutil
                shutil.rmtree(target_dir, ignore_errors=True)

    @classmethod
    def audit(
        cls,
        primary_location: str,
        replica_locations: List[str],
        max_replication_lag_hours: Optional[float] = None,
        require_321: bool = False,
        live_database_present: bool = True,
        s3_endpoint_url: Optional[str] = None,
        s3_region: Optional[str] = None,
    ) -> RedundancyReport:
        """
        Executes a 3-2-1 backup redundancy and parity audit across primary and replicas.
        """
        primary_copy = cls.inspect_location(
            primary_location,
            s3_endpoint_url=s3_endpoint_url,
            s3_region=s3_region,
        )

        replicas: List[StorageCopy] = []
        for rep_loc in replica_locations:
            rep_copy = cls.inspect_location(
                rep_loc,
                s3_endpoint_url=s3_endpoint_url,
                s3_region=s3_region,
            )
            replicas.append(rep_copy)

        # 1. Total copies & media types
        # Count: Live database counts as 1 copy when active (standard 3-2-1 rule definition)
        live_count = 1 if live_database_present else 0
        backup_copies_count = (1 if primary_copy.healthy else 0) + sum(1 for r in replicas if r.healthy)
        total_copies_count = live_count + backup_copies_count

        media_types_set = set()
        if live_database_present:
            media_types_set.add("production_rdbms")
        if primary_copy.healthy:
            media_types_set.add(primary_copy.storage_type)
        for r in replicas:
            if r.healthy:
                media_types_set.add(r.storage_type)

        distinct_media_types = sorted(list(media_types_set))

        # Offsite copies count
        offsite_copies_count = (1 if primary_copy.is_offsite and primary_copy.healthy else 0) + sum(
            1 for r in replicas if r.is_offsite and r.healthy
        )

        # 2. Checksum parity evaluation
        checksum_parity = True
        if not primary_copy.healthy:
            checksum_parity = False
        else:
            for r in replicas:
                if not r.healthy or r.sha256 != primary_copy.sha256:
                    checksum_parity = False
                    break

        # 3. Encryption check
        all_encrypted = primary_copy.is_encrypted and all(r.is_encrypted for r in replicas)

        # 4. Replication lag evaluation
        observed_lag_seconds = 0.0
        lag_breached = False

        if primary_copy.timestamp:
            for r in replicas:
                if r.timestamp:
                    diff = abs((primary_copy.timestamp - r.timestamp).total_seconds())
                    if diff > observed_lag_seconds:
                        observed_lag_seconds = diff

        if max_replication_lag_hours is not None:
            max_allowed_seconds = max_replication_lag_hours * 3600.0
            if observed_lag_seconds > max_allowed_seconds:
                lag_breached = True

        # 5. Determine 3-2-1 compliance
        # 3-2-1 rule criteria:
        # - >= 3 total copies (or >= 2 backups + 1 live)
        # - >= 2 distinct media types
        # - >= 1 offsite copy
        # - Checksum parity verified
        # - No replication lag breach
        # - All healthy
        has_min_copies = total_copies_count >= 3
        has_min_media = len(distinct_media_types) >= 2
        has_offsite = offsite_copies_count >= 1

        is_321_compliant = (
            has_min_copies
            and has_min_media
            and has_offsite
            and checksum_parity
            and not lag_breached
            and primary_copy.healthy
            and all(r.healthy for r in replicas)
        )

        # Determine overall status
        any_unhealthy = (not primary_copy.healthy) or any(not r.healthy for r in replicas)

        if any_unhealthy:
            status = "UNHEALTHY_REPLICA"
            summary = "One or more backup copies or replicas could not be read or verified."
        elif not checksum_parity:
            status = "PARITY_MISMATCH"
            summary = f"Replica checksum mismatch: replica SHA-256 differs from primary ({primary_copy.sha256[:12]}...)."
        elif lag_breached:
            status = "LAG_BREACHED"
            summary = f"Replication lag of {observed_lag_seconds / 3600.0:.2f}h breaches maximum SLA threshold ({max_replication_lag_hours}h)."
        elif require_321 and not is_321_compliant:
            status = "321_NON_COMPLIANT"
            summary = (
                f"3-2-1 redundancy rule not satisfied: {total_copies_count}/3 copies, "
                f"{len(distinct_media_types)}/2 media types, {offsite_copies_count}/1 offsite copies."
            )
        else:
            status = "COMPLIANT"
            lag_str = f" (sync lag: {observed_lag_seconds / 60.0:.1f}m)" if observed_lag_seconds > 0 else ""
            summary = (
                f"Redundancy verified: {total_copies_count} copies across {len(distinct_media_types)} media types "
                f"({offsite_copies_count} offsite); cryptographic parity confirmed{lag_str}."
            )

        return RedundancyReport(
            primary_location=primary_location,
            primary_copy=primary_copy,
            replicas=replicas,
            total_copies_count=total_copies_count,
            backup_copies_count=backup_copies_count,
            distinct_media_types=distinct_media_types,
            offsite_copies_count=offsite_copies_count,
            is_321_compliant=is_321_compliant,
            checksum_parity=checksum_parity,
            all_encrypted=all_encrypted,
            observed_replication_lag_seconds=observed_lag_seconds,
            max_replication_lag_hours=max_replication_lag_hours,
            replication_lag_breached=lag_breached,
            status=status,
            summary=summary,
        )
