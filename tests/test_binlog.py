"""Unit and integration tests for MySQL / MariaDB Binary Log (binlog) Validator."""

import json
import os
import tempfile
import pytest

from drillops.engines.binlog_validator import BinlogValidator, BinlogReport, BinlogSegment
from drillops.cli import main


def test_parse_binlog_filename():
    # Standard 6-digit binlog naming
    parsed = BinlogValidator.parse_binlog_filename("mysql-bin.000001")
    assert parsed == ("mysql-bin", 1, 6)

    parsed = BinlogValidator.parse_binlog_filename("binlog.000042")
    assert parsed == ("binlog", 42, 6)

    # Gzip compressed binlog
    parsed = BinlogValidator.parse_binlog_filename("mariadb-bin.000100.gz")
    assert parsed == ("mariadb-bin", 100, 6)

    # Index file should be excluded
    assert BinlogValidator.parse_binlog_filename("mysql-bin.index") is None
    assert BinlogValidator.parse_binlog_filename("binlog.index") is None

    # Invalid names
    assert BinlogValidator.parse_binlog_filename("not_a_binlog.txt") is None
    assert BinlogValidator.parse_binlog_filename("binlog") is None


def test_format_binlog_filename():
    formatted = BinlogValidator.format_binlog_filename("mysql-bin", 1)
    assert formatted == "mysql-bin.000001"

    formatted = BinlogValidator.format_binlog_filename("binlog", 999, width=6)
    assert formatted == "binlog.000999"


def test_inspect_file():
    with tempfile.TemporaryDirectory(prefix="binlog_inspect_") as tmpdir:
        # Valid binlog file with 0xfe 'b' 'i' 'n' magic
        valid_file = os.path.join(tmpdir, "binlog.000001")
        with open(valid_file, "wb") as f:
            f.write(b"\xfebin" + b"\x00" * 120)

        seg = BinlogValidator.inspect_file(valid_file)
        assert seg is not None
        assert seg.prefix == "binlog"
        assert seg.sequence_num == 1
        assert seg.has_valid_header
        assert seg.is_valid_size
        assert "MySQL/MariaDB binlog" in seg.magic_header

        # Invalid magic bytes file
        invalid_file = os.path.join(tmpdir, "binlog.000002")
        with open(invalid_file, "wb") as f:
            f.write(b"CORR" + b"\x00" * 120)

        seg_inv = BinlogValidator.inspect_file(invalid_file)
        assert seg_inv is not None
        assert not seg_inv.has_valid_header


def test_parse_index_file():
    with tempfile.TemporaryDirectory(prefix="binlog_idx_") as tmpdir:
        idx_path = os.path.join(tmpdir, "mysql-bin.index")
        with open(idx_path, "w", encoding="utf-8") as f:
            f.write("./mysql-bin.000001\n")
            f.write("./mysql-bin.000002\n")
            f.write("/var/log/mysql/mysql-bin.000003\n")

        entries = BinlogValidator.parse_index_file(idx_path)
        assert entries == ["mysql-bin.000001", "mysql-bin.000002", "mysql-bin.000003"]


def test_audit_nonexistent_and_empty():
    report = BinlogValidator.audit("/nonexistent/binlog/directory")
    assert report.status == "NO_BINLOG_FILES"
    assert not report.is_continuous

    with tempfile.TemporaryDirectory(prefix="empty_binlog_") as tmpdir:
        report = BinlogValidator.audit(tmpdir)
        assert report.status == "NO_BINLOG_FILES"
        assert not report.is_continuous


def test_audit_continuous_unbroken_sequence():
    with tempfile.TemporaryDirectory(prefix="binlog_cont_") as tmpdir:
        prefix = "mysql-bin"
        # Create 5 continuous binlog files: 000001 through 000005
        for i in range(1, 6):
            fname = BinlogValidator.format_binlog_filename(prefix, i)
            with open(os.path.join(tmpdir, fname), "wb") as f:
                f.write(b"\xfebin" + b"\x00" * 256)

        # Create matching index file
        with open(os.path.join(tmpdir, f"{prefix}.index"), "w", encoding="utf-8") as f:
            for i in range(1, 6):
                f.write(f"./{BinlogValidator.format_binlog_filename(prefix, i)}\n")

        report = BinlogValidator.audit(tmpdir, prefix=prefix)
        assert report.is_continuous
        assert report.status == "CONTINUOUS"
        assert report.total_segments == 5
        assert report.start_segment == "mysql-bin.000001"
        assert report.end_segment == "mysql-bin.000005"
        assert len(report.missing_segments) == 0
        assert report.index_file_found
        assert report.index_file_matches

        # Terminal report output verification
        term = BinlogValidator.format_terminal_report(report)
        assert "CONTINUOUS" in term
        assert "UNBROKEN SEQUENCE" in term


def test_audit_gap_detection():
    with tempfile.TemporaryDirectory(prefix="binlog_gap_") as tmpdir:
        prefix = "binlog"
        # Create sequence with gap: 000001, 000002, 000004 (missing 000003)
        for i in (1, 2, 4):
            fname = BinlogValidator.format_binlog_filename(prefix, i)
            with open(os.path.join(tmpdir, fname), "wb") as f:
                f.write(b"\xfebin" + b"\x00" * 256)

        report = BinlogValidator.audit(tmpdir, prefix=prefix, check_index_file=False)
        assert not report.is_continuous
        assert report.status == "GAPS_DETECTED"
        assert len(report.missing_segments) == 1
        assert report.missing_segments[0] == "binlog.000003"
        assert "missing segments detected" in report.summary

        term = BinlogValidator.format_terminal_report(report)
        assert "CHAIN BROKEN" in term
        assert "binlog.000003" in term


def test_audit_corrupted_header():
    with tempfile.TemporaryDirectory(prefix="binlog_corrupt_") as tmpdir:
        prefix = "binlog"
        fname1 = BinlogValidator.format_binlog_filename(prefix, 1)
        fname2 = BinlogValidator.format_binlog_filename(prefix, 2)

        with open(os.path.join(tmpdir, fname1), "wb") as f:
            f.write(b"\xfebin" + b"\x00" * 256)

        # Corrupt header in segment 2
        with open(os.path.join(tmpdir, fname2), "wb") as f:
            f.write(b"BAD_HEADER_MAGIC" + b"\x00" * 100)

        report = BinlogValidator.audit(tmpdir, prefix=prefix, check_index_file=False)
        assert not report.is_continuous
        assert report.status == "HEADER_CORRUPT"
        assert fname2 in report.invalid_size_segments


def test_audit_index_mismatch():
    with tempfile.TemporaryDirectory(prefix="binlog_idx_mismatch_") as tmpdir:
        prefix = "mysql-bin"
        # Only segment 1 exists on disk
        fname1 = BinlogValidator.format_binlog_filename(prefix, 1)
        with open(os.path.join(tmpdir, fname1), "wb") as f:
            f.write(b"\xfebin" + b"\x00" * 256)

        # But index file registers both 000001 and 000002
        with open(os.path.join(tmpdir, f"{prefix}.index"), "w", encoding="utf-8") as f:
            f.write("./mysql-bin.000001\n")
            f.write("./mysql-bin.000002\n")

        report = BinlogValidator.audit(tmpdir, prefix=prefix, check_index_file=True)
        assert not report.is_continuous
        assert report.status == "INDEX_MISMATCH"
        assert not report.index_file_matches


def test_cli_check_binlog_subcommand():
    with tempfile.TemporaryDirectory(prefix="cli_binlog_") as tmpdir:
        prefix = "binlog"
        for i in range(1, 4):
            fname = BinlogValidator.format_binlog_filename(prefix, i)
            with open(os.path.join(tmpdir, fname), "wb") as f:
                f.write(b"\xfebin" + b"\x00" * 256)

        # Terminal run
        code = main(["check-binlog", "--binlog-dir", tmpdir, "--prefix", prefix])
        assert code == 0

        # JSON run
        code_json = main(["check-binlog", "--binlog-dir", tmpdir, "--json"])
        assert code_json == 0
