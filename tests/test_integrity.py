"""Tests for Cryptographic Checksum and Cold-Storage Bit-Rot Integrity Auditor."""

import gzip
import json
import os
import shutil
import tempfile
import pytest

from drillops.storage.integrity import IntegrityAuditor, IntegrityReport
from drillops.core.runner import DrillRunner
from drillops.models import VerificationConfig
from drillops.generator.synthetic import SyntheticDataGenerator
from drillops.cli import main


@pytest.fixture
def temp_integrity_env():
    """Sets up healthy, corrupted, and manifest backup archives for testing."""
    tmpdir = tempfile.mkdtemp(prefix="drillops_int_test_")
    gen = SyntheticDataGenerator()

    # 1. Healthy plain SQL dump (SQLite compatible)
    healthy_sql = os.path.join(tmpdir, "healthy.sql")
    with open(healthy_sql, "w", encoding="utf-8") as f:
        f.write(
            "-- SQLite backup dump\n"
            "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL);\n"
            "INSERT INTO users VALUES (1, 'user@example.com');\n"
        )

    # 2. Healthy Gzip dump
    healthy_gz = os.path.join(tmpdir, "healthy.sql.gz")
    with open(healthy_sql, "rb") as f_in:
        with gzip.open(healthy_gz, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

    # 3. Corrupted Gzip dump (bit flip in payload)
    corrupted_gz = os.path.join(tmpdir, "corrupted.sql.gz")
    with open(healthy_gz, "rb") as f:
        gz_bytes = bytearray(f.read())
    # Corrupt several bytes in the middle of the gzip compressed payload
    if len(gz_bytes) > 50:
        for i in range(20, 35):
            gz_bytes[i] ^= 0xFF
    with open(corrupted_gz, "wb") as f:
        f.write(gz_bytes)

    # 4. Truncated Gzip dump (premature EOF)
    truncated_gz = os.path.join(tmpdir, "truncated.sql.gz")
    with open(healthy_gz, "rb") as f:
        half_bytes = f.read(len(gz_bytes) // 2)
    with open(truncated_gz, "wb") as f:
        f.write(half_bytes)

    # 5. Empty file (0 bytes)
    empty_file = os.path.join(tmpdir, "empty.sql")
    with open(empty_file, "w") as f:
        pass

    yield {
        "dir": tmpdir,
        "healthy_sql": healthy_sql,
        "healthy_gz": healthy_gz,
        "corrupted_gz": corrupted_gz,
        "truncated_gz": truncated_gz,
        "empty_file": empty_file,
    }

    shutil.rmtree(tmpdir, ignore_errors=True)


def test_integrity_report_serialization():
    """Validates IntegrityReport dataclass to_dict."""
    rep = IntegrityReport(
        filepath="/tmp/backup.sql.gz",
        size_bytes=4096,
        sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        md5="1234567890abcdef1234567890abcdef",
        archive_format="gzip",
        stream_valid=True,
        manifest_found=True,
        manifest_path="/tmp/backup.sql.gz.sha256",
        manifest_matches=True,
        corruption_detected=False,
        status="VERIFIED",
        details="Stream verified",
    )
    d = rep.to_dict()
    assert d["filepath"] == "/tmp/backup.sql.gz"
    assert d["size_bytes"] == 4096
    assert d["status"] == "VERIFIED"
    assert d["corruption_detected"] is False


def test_healthy_gzip_integrity(temp_integrity_env):
    """Audits a healthy gzipped archive verifying stream validity."""
    report = IntegrityAuditor.audit(temp_integrity_env["healthy_gz"])
    assert report.status == "VERIFIED"
    assert report.archive_format == "gzip"
    assert report.stream_valid is True
    assert report.corruption_detected is False
    assert len(report.sha256) == 64


def test_corrupted_gzip_integrity(temp_integrity_env):
    """Audits a corrupted gzipped archive detecting CRC32 failure or header corruption."""
    report = IntegrityAuditor.audit(temp_integrity_env["corrupted_gz"])
    assert report.status == "CORRUPT_ARCHIVE"
    assert report.stream_valid is False
    assert report.corruption_detected is True
    assert "Bit-rot / archive corruption detected" in report.details


def test_truncated_gzip_integrity(temp_integrity_env):
    """Audits a truncated gzipped archive detecting premature EOF."""
    report = IntegrityAuditor.audit(temp_integrity_env["truncated_gz"])
    assert report.status == "CORRUPT_ARCHIVE"
    assert report.stream_valid is False
    assert report.corruption_detected is True


def test_empty_backup_file(temp_integrity_env):
    """Audits an empty 0-byte file detecting truncation."""
    report = IntegrityAuditor.audit(temp_integrity_env["empty_file"])
    assert report.status == "CORRUPT_ARCHIVE"
    assert report.corruption_detected is True
    assert "empty (0 bytes)" in report.details


def test_missing_backup_file():
    """Audits a missing file path."""
    report = IntegrityAuditor.audit("/nonexistent/file.dump")
    assert report.status == "FILE_NOT_FOUND"
    assert report.corruption_detected is True


def test_manifest_generation_and_matching(temp_integrity_env):
    """Generates a standard SHA256SUMS manifest and verifies against it."""
    backup = temp_integrity_env["healthy_sql"]
    manifest_path = IntegrityAuditor.generate_manifest(backup)
    assert os.path.isfile(manifest_path)

    # Audit without specifying manifest (auto-discovery)
    report = IntegrityAuditor.audit(backup)
    assert report.status == "VERIFIED"
    assert report.manifest_found is True
    assert report.manifest_matches is True
    assert report.corruption_detected is False


def test_manifest_mismatch(temp_integrity_env):
    """Tests manifest detection when expected hash differs."""
    backup = temp_integrity_env["healthy_sql"]
    manifest_path = f"{backup}.sha256"
    # Write wrong hash
    with open(manifest_path, "w", encoding="utf-8") as f:
        f.write("0000000000000000000000000000000000000000000000000000000000000000  healthy.sql\n")

    report = IntegrityAuditor.audit(backup, manifest_path=manifest_path)
    assert report.status == "MANIFEST_MISMATCH"
    assert report.manifest_matches is False
    assert report.corruption_detected is True


def test_runner_integration_with_integrity(temp_integrity_env):
    """Verifies DrillRunner runs integrity audit and injects assertions."""
    config = VerificationConfig(
        database_type="sqlite",
        backup_path=temp_integrity_env["healthy_sql"],
        verify_integrity=True,
    )
    runner = DrillRunner()
    summary, assertions, _ = runner.run_drill(config)

    assert summary.overall_status == "PASSED"
    assert summary.integrity_status == "VERIFIED"

    int_assertions = [a for a in assertions if a.rule_name == "soc2_cc9_1_backup_integrity"]
    assert len(int_assertions) == 1
    assert int_assertions[0].passed is True


def test_cli_check_integrity(temp_integrity_env, capsys):
    """Verifies drillops check-integrity CLI subcommand."""
    # Test text output
    rc = main(["check-integrity", "--backup", temp_integrity_env["healthy_gz"]])
    assert rc == 0
    captured = capsys.readouterr().out
    assert "DrillOps Backup Integrity Audit" in captured
    assert "VERIFIED" in captured
    assert "HEALTHY" in captured

    # Test generate manifest flag
    rc_gen = main([
        "check-integrity",
        "--backup", temp_integrity_env["healthy_gz"],
        "--generate-manifest",
    ])
    assert rc_gen == 0
    captured_gen = capsys.readouterr().out
    assert "Generated SHA-256 manifest" in captured_gen

    # Test JSON output
    rc_json = main([
        "check-integrity",
        "--backup", temp_integrity_env["healthy_gz"],
        "--json",
    ])
    assert rc_json == 0
    json_out = json.loads(capsys.readouterr().out)
    assert json_out["status"] == "VERIFIED"
    assert json_out["stream_valid"] is True
    assert json_out["corruption_detected"] is False
