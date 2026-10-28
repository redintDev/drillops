"""Unit and integration tests for PostgreSQL PITR WAL Continuity Validator."""

import json
import os
import tempfile
import pytest

from drillops.engines.pitr_validator import PITRValidator, PITRReport, WALSegment
from drillops.cli import main


def test_parse_wal_filename():
    # Valid standard 24-char hex
    parsed = PITRValidator.parse_wal_filename("000000010000000000000001")
    assert parsed == (1, 0, 1)

    parsed = PITRValidator.parse_wal_filename("000000020000000A000000FE")
    assert parsed == (2, 10, 254)

    # With .gz suffix
    parsed = PITRValidator.parse_wal_filename("000000010000000000000002.gz")
    assert parsed == (1, 0, 2)

    # With .partial suffix
    parsed = PITRValidator.parse_wal_filename("000000010000000000000003.partial")
    assert parsed == (1, 0, 3)

    # With .backup suffix
    parsed = PITRValidator.parse_wal_filename("000000010000000000000001.00000028.backup")
    assert parsed == (1, 0, 1)

    # Invalid filename
    assert PITRValidator.parse_wal_filename("not_a_wal_file.txt") is None
    assert PITRValidator.parse_wal_filename("0000000100000000") is None


def test_format_wal_filename():
    formatted = PITRValidator.format_wal_filename(1, 0, 1)
    assert formatted == "000000010000000000000001"

    formatted = PITRValidator.format_wal_filename(2, 15, 255)
    assert formatted == "000000020000000F000000FF"


def test_linear_seq_conversion():
    # 256 segments per log file
    seq0 = PITRValidator.linear_seq(0, 0)
    assert seq0 == 0
    assert PITRValidator.linear_to_log_seg(seq0) == (0, 0)

    seq_fe = PITRValidator.linear_seq(0, 254)
    assert seq_fe == 254
    assert PITRValidator.linear_to_log_seg(seq_fe) == (0, 254)

    # Boundary rollover
    seq_next = PITRValidator.linear_seq(1, 0)
    assert seq_next == 256
    assert PITRValidator.linear_to_log_seg(seq_next) == (1, 0)


def test_audit_nonexistent_and_empty():
    report = PITRValidator.audit("/nonexistent/wal/path")
    assert report.status == "NO_WAL_FILES"
    assert not report.is_continuous

    with tempfile.TemporaryDirectory(prefix="empty_wal_") as tmpdir:
        report = PITRValidator.audit(tmpdir)
        assert report.status == "NO_WAL_FILES"
        assert not report.is_continuous


def test_audit_continuous_unbroken_sequence():
    with tempfile.TemporaryDirectory(prefix="wal_cont_") as tmpdir:
        # Create 5 continuous mock WAL segments (using standard PG16 magic \x7f\xd0 and 1024 bytes for test)
        # Expected size set to 1024 bytes (test override via expected_size_mb)
        expected_bytes = 1024
        timeline = 1
        segments = [
            (timeline, 0, 254),
            (timeline, 0, 255),
            (timeline, 1, 0),
            (timeline, 1, 1),
            (timeline, 1, 2),
        ]

        for tl, log, seg in segments:
            fname = PITRValidator.format_wal_filename(tl, log, seg)
            fpath = os.path.join(tmpdir, fname)
            with open(fpath, "wb") as f:
                f.write(b"\x7f\xd0" + b"\x00" * (expected_bytes - 2))

        report = PITRValidator.audit(tmpdir, expected_size_mb=1)  # expected 1MB, so size mismatch if 1024b
        assert report.status == "SIZE_MISMATCH"

        # Now test with custom file size matching: write mock 1MB segments (1024 * 1024)
        for tl, log, seg in segments:
            fname = PITRValidator.format_wal_filename(tl, log, seg)
            fpath = os.path.join(tmpdir, fname)
            with open(fpath, "wb") as f:
                f.write(b"\x7f\xd0" + b"\x00" * (1024 * 1024 - 2))

        report = PITRValidator.audit(tmpdir, expected_size_mb=1)
        assert report.is_continuous
        assert report.status == "CONTINUOUS"
        assert report.total_segments == 5
        assert len(report.missing_segments) == 0
        assert len(report.invalid_size_segments) == 0
        assert report.start_segment == "0000000100000000000000FE"
        assert report.end_segment == "000000010000000100000002"

        # Verify terminal formatting
        term_str = PITRValidator.format_terminal_report(report)
        assert "UNBROKEN SEQUENCE" in term_str
        assert "CONTINUOUS" in term_str


def test_audit_gap_detection():
    with tempfile.TemporaryDirectory(prefix="wal_gap_") as tmpdir:
        # Create sequence with gap: seg 1, seg 2, seg 4 (missing seg 3)
        timeline = 1
        seg_indices = [1, 2, 4]
        for seg in seg_indices:
            fname = PITRValidator.format_wal_filename(timeline, 0, seg)
            fpath = os.path.join(tmpdir, fname)
            with open(fpath, "wb") as f:
                f.write(b"\x7f\xd0" + b"\x00" * (1024 * 1024 - 2))

        report = PITRValidator.audit(tmpdir, expected_size_mb=1)
        assert not report.is_continuous
        assert report.status == "GAPS_DETECTED"
        assert len(report.missing_segments) == 1
        assert report.missing_segments[0] == "000000010000000000000003"
        assert "missing WAL segments detected" in report.summary

        term_str = PITRValidator.format_terminal_report(report)
        assert "CHAIN BROKEN" in term_str
        assert "000000010000000000000003" in term_str


def test_audit_truncated_segment():
    with tempfile.TemporaryDirectory(prefix="wal_trunc_") as tmpdir:
        timeline = 1
        fname1 = PITRValidator.format_wal_filename(timeline, 0, 1)
        fname2 = PITRValidator.format_wal_filename(timeline, 0, 2)

        # Full 1MB file
        with open(os.path.join(tmpdir, fname1), "wb") as f:
            f.write(b"\x7f\xd0" + b"\x00" * (1024 * 1024 - 2))

        # Truncated 500 byte file
        with open(os.path.join(tmpdir, fname2), "wb") as f:
            f.write(b"\x7f\xd0" + b"\x00" * 498)

        report = PITRValidator.audit(tmpdir, expected_size_mb=1)
        assert not report.is_continuous
        assert report.status == "SIZE_MISMATCH"
        assert fname2 in report.invalid_size_segments


def test_cli_check_pitr_subcommand():
    with tempfile.TemporaryDirectory(prefix="cli_pitr_") as tmpdir:
        # Create continuous segments
        timeline = 1
        for seg in [1, 2, 3]:
            fname = PITRValidator.format_wal_filename(timeline, 0, seg)
            fpath = os.path.join(tmpdir, fname)
            with open(fpath, "wb") as f:
                f.write(b"\x7f\xd0" + b"\x00" * (1024 * 1024 - 2))

        # CLI execution with --wal-size-mb 1
        exit_code = main(["check-pitr", "--wal-dir", tmpdir, "--wal-size-mb", "1"])
        assert exit_code == 0

        # CLI execution with json
        exit_code_json = main(["check-pitr", "--wal-dir", tmpdir, "--wal-size-mb", "1", "--json"])
        assert exit_code_json == 0
