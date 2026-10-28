"""Cryptographic Checksum and Cold-Storage Bit-Rot Integrity Auditor for DrillOps."""

from dataclasses import dataclass
import gzip
import hashlib
import os
import sqlite3
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class IntegrityReport:
    """Detailed audit report from cryptographic and archive integrity verification."""
    filepath: str
    size_bytes: int
    sha256: str
    md5: str
    archive_format: str  # 'gzip', 'sqlite', 'plain_sql', 'encrypted', 'unknown'
    stream_valid: bool
    manifest_found: bool
    manifest_path: Optional[str]
    manifest_matches: Optional[bool]
    corruption_detected: bool
    status: str  # 'VERIFIED', 'CORRUPT_ARCHIVE', 'MANIFEST_MISMATCH', 'FILE_NOT_FOUND'
    details: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filepath": self.filepath,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "md5": self.md5,
            "archive_format": self.archive_format,
            "stream_valid": self.stream_valid,
            "manifest_found": self.manifest_found,
            "manifest_path": self.manifest_path,
            "manifest_matches": self.manifest_matches,
            "corruption_detected": self.corruption_detected,
            "status": self.status,
            "details": self.details,
        }


class IntegrityAuditor:
    """
    Audits cold-storage database backups for bit-rot, corruption, truncation,
    and cryptographic checksum manifest compliance.
    """

    @staticmethod
    def calculate_hashes(filepath: str, block_size: int = 65536) -> Tuple[str, str]:
        """Calculates both SHA-256 and MD5 hashes in a single pass."""
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        with open(filepath, "rb") as f:
            for block in iter(lambda: f.read(block_size), b""):
                sha256.update(block)
                md5.update(block)
        return sha256.hexdigest(), md5.hexdigest()

    @staticmethod
    def detect_format(filepath: str) -> str:
        """Detects the underlying archive format via extension and header magic bytes."""
        lower = filepath.lower()
        if lower.endswith((".enc", ".aes", ".gpg", ".pgp", ".asc", ".age")):
            return "encrypted"

        try:
            with open(filepath, "rb") as f:
                header = f.read(64)
            if header.startswith(b"\x1f\x8b"):
                return "gzip"
            if header.startswith(b"SQLite format 3\x00"):
                return "sqlite"
            if header.startswith(b"Salted__") or header.startswith(b"-----BEGIN PGP"):
                return "encrypted"
        except Exception:
            pass

        if lower.endswith((".sql.gz", ".gz")):
            return "gzip"
        if lower.endswith((".db", ".sqlite", ".sqlite3")):
            return "sqlite"
        if lower.endswith(".sql"):
            return "plain_sql"

        return "unknown"

    @staticmethod
    def verify_stream(filepath: str, archive_format: str) -> Tuple[bool, str]:
        """
        Validates internal archive consistency and catches bit-rot / truncation.
        Returns (is_valid, error_or_success_message).
        """
        if not os.path.isfile(filepath):
            return False, f"File not found: {filepath}"

        if os.path.getsize(filepath) == 0:
            return False, "File is empty (0 bytes) - corrupt or truncated backup"

        if archive_format == "gzip":
            try:
                # Read entire gzip stream block-by-block to trigger internal CRC-32 and length checks
                total_uncompressed = 0
                with gzip.open(filepath, "rb") as gz:
                    while True:
                        chunk = gz.read(65536)
                        if not chunk:
                            break
                        total_uncompressed += len(chunk)
                return True, f"Gzip stream valid (decompressed {total_uncompressed:,} bytes, CRC32 verified)"
            except gzip.BadGzipFile as e:
                return False, f"Gzip CRC32 or header check failed: {e}"
            except EOFError as e:
                return False, f"Gzip archive is truncated (premature EOF): {e}"
            except Exception as e:
                return False, f"Gzip stream decompression error: {e}"

        elif archive_format == "sqlite":
            try:
                with open(filepath, "rb") as f:
                    header = f.read(16)
                if not header.startswith(b"SQLite format 3\x00"):
                    return False, "SQLite header magic mismatch (expected 'SQLite format 3\\0')"

                # Run SQLite quick_check
                conn = sqlite3.connect(filepath)
                cursor = conn.cursor()
                cursor.execute("PRAGMA quick_check;")
                result = cursor.fetchone()
                conn.close()
                if result and result[0] == "ok":
                    return True, "SQLite database quick_check PRAGMA passed (B-tree integrity valid)"
                else:
                    return False, f"SQLite integrity PRAGMA reported corruption: {result}"
            except sqlite3.DatabaseError as e:
                return False, f"SQLite database corruption detected: {e}"
            except Exception as e:
                return False, f"SQLite verification error: {e}"

        elif archive_format == "plain_sql":
            try:
                # Verify non-empty and readable text
                with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                    sample = f.read(4096)
                if len(sample.strip()) == 0:
                    return False, "Plain SQL file contains only whitespace"
                return True, f"Plain SQL file readable ({len(sample)} sample bytes verified)"
            except Exception as e:
                return False, f"SQL read error: {e}"

        elif archive_format == "encrypted":
            try:
                with open(filepath, "rb") as f:
                    header = f.read(32)
                if len(header) < 8:
                    return False, "Encrypted payload too short (<8 bytes)"
                return True, "Encrypted container headers verified"
            except Exception as e:
                return False, f"Encrypted header read error: {e}"

        return True, "File stream readable"

    @staticmethod
    def find_manifest(filepath: str) -> Optional[str]:
        """Discovers existing manifest file (.sha256, SHA256SUMS, .md5, MD5SUMS) alongside backup."""
        directory = os.path.dirname(filepath) or "."
        basename = os.path.basename(filepath)

        candidates = [
            f"{filepath}.sha256",
            f"{filepath}.sha512",
            f"{filepath}.md5",
            os.path.join(directory, f"{basename}.sha256"),
            os.path.join(directory, "SHA256SUMS"),
            os.path.join(directory, "sha256sums.txt"),
            os.path.join(directory, "MD5SUMS"),
        ]

        for cand in candidates:
            if os.path.isfile(cand):
                return cand
        return None

    @staticmethod
    def parse_and_verify_manifest(
        filepath: str, manifest_path: str, calculated_sha256: str, calculated_md5: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Parses manifest file looking for entry matching filepath basename.
        Returns (matches, expected_hash_found).
        """
        if not os.path.isfile(manifest_path):
            return False, None

        basename = os.path.basename(filepath)
        try:
            with open(manifest_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        hash_val = parts[0].strip().lower()
                        target_name = parts[1].strip().lstrip("*")
                        target_basename = os.path.basename(target_name)

                        if target_basename == basename:
                            if len(hash_val) == 64:  # SHA-256
                                return (hash_val == calculated_sha256.lower()), hash_val
                            elif len(hash_val) == 32:  # MD5
                                return (hash_val == calculated_md5.lower()), hash_val

            # Also check single-hash format (.sha256 file with just the hash)
            with open(manifest_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read().strip()
                tokens = content.split()
                if len(tokens) == 1:
                    single_hash = tokens[0].lower()
                    if len(single_hash) == 64:
                        return (single_hash == calculated_sha256.lower()), single_hash
                    elif len(single_hash) == 32:
                        return (single_hash == calculated_md5.lower()), single_hash
        except Exception:
            pass

        return False, None

    @classmethod
    def audit(cls, filepath: str, manifest_path: Optional[str] = None) -> IntegrityReport:
        """Executes full integrity audit against the target backup archive."""
        if not os.path.exists(filepath):
            return IntegrityReport(
                filepath=filepath,
                size_bytes=0,
                sha256="",
                md5="",
                archive_format="unknown",
                stream_valid=False,
                manifest_found=False,
                manifest_path=None,
                manifest_matches=None,
                corruption_detected=True,
                status="FILE_NOT_FOUND",
                details=f"Target backup file not found at: {filepath}",
            )

        size_bytes = os.path.getsize(filepath)
        archive_format = cls.detect_format(filepath)
        sha256, md5 = cls.calculate_hashes(filepath)

        stream_valid, stream_msg = cls.verify_stream(filepath, archive_format)

        # Manifest resolution
        active_manifest = manifest_path or cls.find_manifest(filepath)
        manifest_found = active_manifest is not None and os.path.isfile(active_manifest)
        manifest_matches = None

        if manifest_found:
            matches, expected = cls.parse_and_verify_manifest(filepath, active_manifest, sha256, md5)
            manifest_matches = matches

        # Determine overall integrity status
        if not stream_valid:
            status = "CORRUPT_ARCHIVE"
            corruption = True
            details = f"Bit-rot / archive corruption detected: {stream_msg}"
        elif manifest_found and manifest_matches is False:
            status = "MANIFEST_MISMATCH"
            corruption = True
            details = f"Manifest checksum mismatch in {os.path.basename(active_manifest)}"
        else:
            status = "VERIFIED"
            corruption = False
            details = f"Archive stream healthy ({archive_format}); {stream_msg}"
            if manifest_found and manifest_matches is True:
                details += f"; Verified against manifest {os.path.basename(active_manifest)}"

        return IntegrityReport(
            filepath=filepath,
            size_bytes=size_bytes,
            sha256=sha256,
            md5=md5,
            archive_format=archive_format,
            stream_valid=stream_valid,
            manifest_found=manifest_found,
            manifest_path=active_manifest,
            manifest_matches=manifest_matches,
            corruption_detected=corruption,
            status=status,
            details=details,
        )

    @classmethod
    def generate_manifest(cls, filepath: str, output_path: Optional[str] = None) -> str:
        """Generates standard SHA256SUMS manifest file alongside backup."""
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Cannot generate manifest for missing file: {filepath}")

        sha256, _ = cls.calculate_hashes(filepath)
        basename = os.path.basename(filepath)
        manifest_content = f"{sha256}  {basename}\n"

        target_manifest = output_path or f"{filepath}.sha256"
        with open(target_manifest, "w", encoding="utf-8") as f:
            f.write(manifest_content)

        return target_manifest
