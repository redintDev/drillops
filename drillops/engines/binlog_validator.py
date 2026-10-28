"""MySQL and MariaDB Binary Log (binlog) Continuity & Integrity Validator.

Validates that continuous MySQL/MariaDB binlog sequences stored on disk or cloud storage
are unbroken, uncorrupted, and continuous from base backup checkpoint to target restore point.
"""

from dataclasses import dataclass, field
import os
import re
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class BinlogSegment:
    """Represents an evaluated MySQL binary log file segment."""
    filename: str
    filepath: str
    prefix: str
    sequence_num: int
    size_bytes: int
    is_valid_size: bool
    has_valid_header: bool
    magic_header: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "filepath": self.filepath,
            "prefix": self.prefix,
            "sequence_num": self.sequence_num,
            "size_bytes": self.size_bytes,
            "is_valid_size": self.is_valid_size,
            "has_valid_header": self.has_valid_header,
            "magic_header": self.magic_header,
        }


@dataclass
class BinlogReport:
    """Audit report for MySQL binary log archive continuity."""
    binlog_directory: str
    total_segments: int
    prefix: str
    start_segment: Optional[str]
    end_segment: Optional[str]
    missing_segments: List[str]
    invalid_size_segments: List[str]
    index_file_found: bool
    index_file_matches: bool
    is_continuous: bool
    status: str  # 'CONTINUOUS', 'GAPS_DETECTED', 'HEADER_CORRUPT', 'INDEX_MISMATCH', 'NO_BINLOG_FILES'
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "binlog_directory": self.binlog_directory,
            "total_segments": self.total_segments,
            "prefix": self.prefix,
            "start_segment": self.start_segment,
            "end_segment": self.end_segment,
            "missing_segments": self.missing_segments,
            "invalid_size_segments": self.invalid_size_segments,
            "index_file_found": self.index_file_found,
            "index_file_matches": self.index_file_matches,
            "is_continuous": self.is_continuous,
            "status": self.status,
            "summary": self.summary,
        }


class BinlogValidator:
    """
    Validates MySQL / MariaDB binary log archive sequences for Point-in-Time Recovery (PITR).
    """

    # MySQL binlog pattern: e.g. mysql-bin.000001 or binlog.000042
    BINLOG_PATTERN = re.compile(r"^([a-zA-Z0-9_\-]+)\.(\d+)$")

    # Standard MySQL binlog magic bytes: 0xfe 'b' 'i' 'n'
    MYSQL_BINLOG_MAGIC = b"\xfebin"

    @classmethod
    def parse_binlog_filename(cls, filename: str) -> Optional[Tuple[str, int, int]]:
        """
        Parses a binlog filename into (prefix, sequence_number, digit_width).
        Returns None if filename is not a standard binlog segment name.
        """
        clean = filename
        if clean.endswith(".gz"):
            clean = clean[:-3]

        # Ignore .index files
        if clean.endswith(".index"):
            return None

        match = cls.BINLOG_PATTERN.match(clean)
        if not match:
            return None

        prefix = match.group(1)
        digits_str = match.group(2)
        seq_num = int(digits_str)
        width = len(digits_str)
        return prefix, seq_num, width

    @classmethod
    def format_binlog_filename(cls, prefix: str, seq_num: int, width: int = 6) -> str:
        """Formats prefix and sequence number into standard binlog filename (e.g. binlog.000001)."""
        return f"{prefix}.{seq_num:0{width}d}"

    @classmethod
    def inspect_file(cls, filepath: str) -> Optional[BinlogSegment]:
        """Inspects an individual binlog file for sizing, sequence index, and magic header."""
        if not os.path.isfile(filepath):
            return None

        filename = os.path.basename(filepath)
        parsed = cls.parse_binlog_filename(filename)
        if not parsed:
            return None

        prefix, seq_num, _ = parsed
        size = os.path.getsize(filepath)
        is_gz = filename.endswith(".gz")

        # Binlog header check: uncompressed files must have size >= 4 and start with \xfebin
        has_valid_header = False
        magic_name = None

        if not is_gz:
            if size >= 4:
                try:
                    with open(filepath, "rb") as f:
                        header = f.read(4)
                    if header == cls.MYSQL_BINLOG_MAGIC:
                        has_valid_header = True
                        magic_name = "0xFE62696E (MySQL/MariaDB binlog)"
                    else:
                        magic_name = f"Invalid magic: {header.hex()}"
                except Exception:
                    pass
            is_valid_size = size >= 4
        else:
            # Gzip compressed binlog
            has_valid_header = size >= 2
            magic_name = "gzip-compressed binlog"
            is_valid_size = size > 0

        return BinlogSegment(
            filename=filename,
            filepath=filepath,
            prefix=prefix,
            sequence_num=seq_num,
            size_bytes=size,
            is_valid_size=is_valid_size,
            has_valid_header=has_valid_header,
            magic_header=magic_name,
        )

    @classmethod
    def parse_index_file(cls, index_path: str) -> List[str]:
        """Parses a MySQL binlog index file (.index) into a list of registered filenames."""
        if not os.path.isfile(index_path):
            return []
        registered = []
        try:
            with open(index_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    entry = line.strip()
                    if entry:
                        registered.append(os.path.basename(entry))
        except Exception:
            pass
        return registered

    @classmethod
    def audit(
        cls,
        binlog_directory: str,
        prefix: Optional[str] = None,
        check_index_file: bool = True,
        max_reported_gaps: int = 20,
    ) -> BinlogReport:
        """
        Audits a MySQL/MariaDB binlog directory for sequence continuity, corruption, and index tracking.
        """
        if not os.path.isdir(binlog_directory):
            return BinlogReport(
                binlog_directory=binlog_directory,
                total_segments=0,
                prefix=prefix or "unknown",
                start_segment=None,
                end_segment=None,
                missing_segments=[],
                invalid_size_segments=[],
                index_file_found=False,
                index_file_matches=True,
                is_continuous=False,
                status="NO_BINLOG_FILES",
                summary=f"Binary log directory does not exist: {binlog_directory}",
            )

        all_files = sorted(os.listdir(binlog_directory))
        segments: List[BinlogSegment] = []
        index_files: List[str] = []

        for fname in all_files:
            fpath = os.path.join(binlog_directory, fname)
            if fname.endswith(".index") and os.path.isfile(fpath):
                index_files.append(fpath)
                continue

            seg = cls.inspect_file(fpath)
            if seg:
                if prefix is None or seg.prefix == prefix:
                    segments.append(seg)

        if not segments:
            return BinlogReport(
                binlog_directory=binlog_directory,
                total_segments=0,
                prefix=prefix or "unknown",
                start_segment=None,
                end_segment=None,
                missing_segments=[],
                invalid_size_segments=[],
                index_file_found=len(index_files) > 0,
                index_file_matches=True,
                is_continuous=False,
                status="NO_BINLOG_FILES",
                summary=f"No valid MySQL/MariaDB binary logs found in: {binlog_directory}",
            )

        # Detect active prefix
        by_prefix: Dict[str, List[BinlogSegment]] = {}
        for s in segments:
            by_prefix.setdefault(s.prefix, []).append(s)

        chosen_prefix = prefix or max(by_prefix.keys(), key=lambda p: len(by_prefix[p]))
        prefix_segments = sorted(by_prefix[chosen_prefix], key=lambda s: s.sequence_num)

        start_seg = prefix_segments[0].filename
        end_seg = prefix_segments[-1].filename

        # Detect corrupt / invalid headers or sizes
        invalid_size = [s.filename for s in prefix_segments if not s.is_valid_size or not s.has_valid_header]

        # Detect sequence continuity gaps
        missing: List[str] = []
        for i in range(len(prefix_segments) - 1):
            curr_seq = prefix_segments[i].sequence_num
            next_seq = prefix_segments[i + 1].sequence_num

            if next_seq > curr_seq + 1:
                gap_start = curr_seq + 1
                gap_end = next_seq
                for missing_seq in range(gap_start, gap_end):
                    if len(missing) >= max_reported_gaps:
                        break
                    missing.append(cls.format_binlog_filename(chosen_prefix, missing_seq))

        # Check against index file if present
        index_found = False
        index_matches = True
        if check_index_file and index_files:
            index_found = True
            # Check primary index file matching chosen prefix
            matching_index = next((f for f in index_files if os.path.basename(f).startswith(chosen_prefix)), index_files[0])
            registered_names = set(cls.parse_index_file(matching_index))
            disk_names = {s.filename for s in prefix_segments}
            # All registered in index must exist on disk
            if registered_names and not registered_names.issubset(disk_names):
                index_matches = False

        is_continuous = (len(missing) == 0) and (len(invalid_size) == 0) and index_matches

        if len(missing) > 0:
            status = "GAPS_DETECTED"
            summary = (
                f"MySQL binlog sequence broken: {len(missing)} missing segments detected "
                f"between {start_seg} and {end_seg}."
            )
        elif len(invalid_size) > 0:
            status = "HEADER_CORRUPT"
            summary = (
                f"MySQL binlog corruption: {len(invalid_size)} segments have invalid magic headers or truncated sizes."
            )
        elif not index_matches:
            status = "INDEX_MISMATCH"
            summary = (
                "MySQL binlog index mismatch: index file contains references to segments missing on disk."
            )
        else:
            status = "CONTINUOUS"
            summary = (
                f"Unbroken MySQL binlog recovery chain verified: {len(prefix_segments)} continuous segments "
                f"from {start_seg} to {end_seg} (Prefix: {chosen_prefix})."
            )

        return BinlogReport(
            binlog_directory=binlog_directory,
            total_segments=len(prefix_segments),
            prefix=chosen_prefix,
            start_segment=start_seg,
            end_segment=end_seg,
            missing_segments=missing,
            invalid_size_segments=invalid_size,
            index_file_found=index_found,
            index_file_matches=index_matches,
            is_continuous=is_continuous,
            status=status,
            summary=summary,
        )

    @classmethod
    def format_terminal_report(cls, report: BinlogReport) -> str:
        """Renders formatted ANSI summary for CLI operators."""
        status_tag = "✅ CONTINUOUS" if report.is_continuous else "🔴 CHAIN BROKEN"
        lines = [
            "\n" + "=" * 64,
            f" 🛡️  DrillOps MySQL Binary Log (binlog) PITR Audit: {status_tag}",
            "=" * 64,
            f"Directory:       {report.binlog_directory}",
            f"Prefix:          {report.prefix}",
            f"Total Segments:  {report.total_segments}",
            f"Start Segment:   {report.start_segment or 'N/A'}",
            f"End Segment:     {report.end_segment or 'N/A'}",
            f"Index File:      {'✅ Present & Verified' if (report.index_file_found and report.index_file_matches) else ('⚠️ Mismatch / Missing' if report.index_file_found else 'None found')}",
            f"Chain Status:    {'✅ UNBROKEN SEQUENCE' if report.is_continuous else '❌ GAPS / ERRORS DETECTED'}",
        ]

        if report.missing_segments:
            lines.append("----------------------------------------------------------------")
            lines.append(f"❌ Missing Binlog Segments ({len(report.missing_segments)}):")
            for m in report.missing_segments[:8]:
                lines.append(f"   - {m}")
            if len(report.missing_segments) > 8:
                lines.append(f"   ... and {len(report.missing_segments) - 8} more")

        if report.invalid_size_segments:
            lines.append("----------------------------------------------------------------")
            lines.append(f"⚠️ Corrupted / Invalid Header Segments ({len(report.invalid_size_segments)}):")
            for inv in report.invalid_size_segments[:5]:
                lines.append(f"   - {inv}")

        lines.extend([
            "----------------------------------------------------------------",
            f"Summary:         {report.summary}",
            "=" * 64 + "\n",
        ])
        return "\n".join(lines)
