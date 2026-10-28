"""Storage and archive processing utilities for database backups."""

import gzip
import hashlib
import os
import shutil
import subprocess
import tempfile
from typing import Optional, Tuple


class ArchiveProcessor:
    """Inspects, hashes, decrypts, and prepares database backup archives for restoration."""

    @staticmethod
    def calculate_sha256(filepath: str, block_size: int = 65536) -> str:
        """Calculate the SHA-256 hash of a file."""
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Backup file not found at: {filepath}")

        sha = hashlib.sha256()
        with open(filepath, "rb") as f:
            for block in iter(lambda: f.read(block_size), b""):
                sha.update(block)
        return sha.hexdigest()

    @staticmethod
    def inspect_file(filepath: str) -> Tuple[int, str]:
        """Returns (size_in_bytes, sha256_checksum) for the target file."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Target archive does not exist: {filepath}")
        size = os.path.getsize(filepath)
        checksum = ArchiveProcessor.calculate_sha256(filepath)
        return size, checksum

    @staticmethod
    def detect_encryption(filepath: str) -> Optional[str]:
        """
        Detects whether an archive file is encrypted at rest via magic bytes or file extension.
        Returns 'openssl', 'gpg', 'age', or None.
        """
        if not os.path.isfile(filepath):
            return None

        lower = filepath.lower()
        if lower.endswith((".enc", ".aes")):
            return "openssl"
        if lower.endswith((".gpg", ".pgp", ".asc")):
            return "gpg"
        if lower.endswith(".age"):
            return "age"

        try:
            with open(filepath, "rb") as f:
                header = f.read(64)
            if header.startswith(b"Salted__"):
                return "openssl"
            if header.startswith(b"-----BEGIN PGP MESSAGE-----"):
                return "gpg"
            if len(header) >= 2 and (header[0] & 0x80) != 0:
                tag = (header[0] & 0x3F) >> 2 if (header[0] & 0x40) == 0 else (header[0] & 0x3F)
                if tag in (1, 2, 3, 9, 18):
                    return "gpg"
            if header.startswith(b"age-encryption.org/v1"):
                return "age"
        except Exception:
            pass

        return None

    @staticmethod
    def decrypt_archive(
        filepath: str,
        work_dir: str,
        passphrase: Optional[str] = None,
        cipher: str = "aes-256-cbc",
    ) -> Tuple[str, str]:
        """
        Ephemerally decrypts an encrypted backup into work_dir.
        Returns (decrypted_path, encryption_type).
        """
        enc_type = ArchiveProcessor.detect_encryption(filepath)
        if not enc_type:
            return filepath, ""

        if not passphrase:
            raise ValueError(
                f"Encrypted backup archive detected ({enc_type}), but no decryption passphrase was provided. "
                "Specify --decrypt-passphrase or set DRILLOPS_DECRYPT_PASSPHRASE."
            )

        basename = os.path.basename(filepath)
        for ext in (".enc", ".aes", ".gpg", ".pgp", ".asc", ".age"):
            if basename.lower().endswith(ext):
                basename = basename[:-len(ext)]
                break
        else:
            basename = f"decrypted_{basename}"

        decrypted_path = os.path.join(work_dir, basename)

        if enc_type in ("openssl", "aes"):
            cmd = [
                "openssl", "enc", "-d", f"-{cipher}", "-pbkdf2",
                "-in", filepath,
                "-out", decrypted_path,
                "-pass", f"pass:{passphrase}",
            ]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode != 0:
                raise RuntimeError(
                    f"OpenSSL decryption failed (exit {res.returncode}): invalid passphrase or corrupted archive. {res.stderr.strip()}"
                )
            return decrypted_path, f"openssl-{cipher}"

        elif enc_type == "gpg":
            cmd = [
                "gpg", "--batch", "--yes",
                "--passphrase", passphrase,
                "--pinentry-mode", "loopback",
                "-d", "-o", decrypted_path,
                filepath,
            ]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode != 0:
                raise RuntimeError(
                    f"GPG decryption failed (exit {res.returncode}): invalid passphrase or corrupted archive. {res.stderr.strip()}"
                )
            return decrypted_path, "gpg"

        else:
            raise NotImplementedError(f"Unsupported encryption type: {enc_type}")

    @staticmethod
    def prepare_archive(
        filepath: str,
        work_dir: str,
        decrypt_passphrase: Optional[str] = None,
        decrypt_cipher: str = "aes-256-cbc",
    ) -> str:
        """
        Multi-stage pipeline:
        1. If encrypted, decrypt into work_dir.
        2. If gzipped (.gz), decompress into work_dir.
        Returns the path to the uncompressed SQL/dump payload.
        """
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        current_path = filepath

        # Stage 1: Decryption
        enc_type = ArchiveProcessor.detect_encryption(current_path)
        if enc_type:
            current_path, _ = ArchiveProcessor.decrypt_archive(
                current_path,
                work_dir=work_dir,
                passphrase=decrypt_passphrase,
                cipher=decrypt_cipher,
            )

        # Stage 2: Decompression (.gz)
        if current_path.endswith(".gz"):
            basename = os.path.basename(current_path)
            uncompressed_name = basename[:-3]
            target_path = os.path.join(work_dir, uncompressed_name)
            with gzip.open(current_path, "rb") as f_in:
                with open(target_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            return target_path

        return current_path
