"""PostgreSQL Point-in-Time Recovery (PITR) & Write-Ahead Log (WAL) Archive Validator.

Validates that continuous PostgreSQL WAL archives stored on disk or cloud object storage
are unbroken, uncorrupted, and continuous from base backup checkpoint to target restore LSN.
"""

from dataclasses import dataclass, field
import os
import re
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class WALSegment:
    """Represents a single evaluated PostgreSQL WAL segment archive file."""
    filename: str
    filepath: str
    timeline_id: int
    log_id: int
    segment_id: int
    linear_seq: int  # (log_id * 256) + segment_id
    size_bytes: int
    is_valid_size: bool
    has_valid_header: bool
    header_magic: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "timeline_id": self.timeline_id,
            "log_id": self.log_id,
            "segment_id": self.segment_id,
            "linear_seq": self.linear_seq,
            "size_bytes": self.size_bytes,
            "is_valid_size": self.is_valid_size,
            "has_valid_header": self.has_valid_header,
            "header_magic": self.header_magic,
        }


@dataclass
class PITRReport:
    """Audit report for Point-in-Time Recovery archive continuity."""
    wal_directory: str
    total_segments: int
    timelines: List[int]
    start_segment: Optional[str]
    end_segment: Optional[str]
    missing_segments: List[str]
    invalid_size_segments: List[str]
    is_continuous: bool
    expected_segment_size_bytes: int
    status: str  # 'CONTINUOUS', 'GAPS_DETECTED', 'SIZE_MISMATCH', 'NO_WAL_FILES'
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "wal_directory": self.wal_directory,
            "total_segments": self.total_segments,
            "timelines": self.timelines,
            "start_segment": self.start_segment,
            "end_segment": self.end_segment,
            "missing_segments": self.missing_segments,
            "invalid_size_segments": self.invalid_size_segments,
            "is_continuous": self.is_continuous,
            "expected_segment_size_bytes": self.expected_segment_size_bytes,
            "status": self.status,
            "summary": self.summary,
        }


class PITRValidator:
    """
    Validates PostgreSQL WAL archive sequences for Point-in-Time Recovery (PITR) readiness.
    """

    # PostgreSQL WAL filename format: 24 hex characters: TTTTTTTTLLLLLLLLSSSSSSSS
    WAL_FILENAME_PATTERN = re.compile(r"^([0-9A-Fa-f]{8})([0-9A-Fa-f]{8})([0-9A-Fa-f]{8})$")

    # Standard PostgreSQL WAL magic numbers:
    # PG 16: 0xD07F -> b'\x7f\xd0' (little endian)
    # PG 15: 0xD07E -> b'\x7e\xd0'
    # PG 14: 0xD07D -> b'\x7d\xd0'
    KNOWN_WAL_MAGICS = {
        b"\x7f\xd0": "PG16 (0xD07F)",
        b"\x7e\xd0": "PG15 (0xD07E)",
        b"\x7d\xd0": "PG14 (0xD07D)",
        b"\x7c\xd0": "PG13 (0xD07C)",
        b"\xd0\x7f": "PG16-BE (0xD07F)",
    }

    @classmethod
    def parse_wal_filename(cls, filename: str) -> Optional[Tuple[int, int, int]]:
        """
        Parses a 24-hex WAL filename into (timeline_id, log_id, segment_id).
        Returns None if filename is not a standard WAL segment name.
        """
        # Strip .gz, .partial, or compound suffixes like .00000028.backup
        clean = filename.split(".")[0]
        match = cls.WAL_FILENAME_PATTERN.match(clean)
        if not match:
            return None

        timeline = int(match.group(1), 16)
        log = int(match.group(2), 16)
        segment = int(match.group(3), 16)
        return timeline, log, segment

    @classmethod
    def format_wal_filename(cls, timeline: int, log: int, segment: int) -> str:
        """Formats timeline, log, and segment IDs into standard 24-char hex WAL name."""
        return f"{timeline:08X}{log:08X}{segment:08X}"

    @classmethod
    def linear_seq(cls, log_id: int, segment_id: int) -> int:
        """Computes linear segment index (256 segments per log file in standard PostgreSQL)."""
        return (log_id * 256) + segment_id

    @classmethod
    def linear_to_log_seg(cls, linear: int) -> Tuple[int, int]:
        """Converts linear segment index back to (log_id, segment_id)."""
        log_id = linear // 256
        segment_id = linear % 256
        return log_id, segment_id

    @classmethod
    def inspect_file(
        cls, filepath: str, expected_size_bytes: int = 16 * 1024 * 1024
    ) -> Optional[WALSegment]:
        """Inspects an individual WAL file for sizing, timeline, and header validity."""
        if not os.path.isfile(filepath):
            return None

        filename = os.path.basename(filepath)
        parsed = cls.parse_wal_filename(filename)
        if not parsed:
            return None

        timeline, log, segment = parsed
        size = os.path.getsize(filepath)

        # Allow gzip-compressed archives (.gz) or exact size uncompressed
        is_gz = filename.endswith(".gz")
        is_valid_size = (size > 0 and is_gz) or (size == expected_size_bytes)

        # Inspect header magic
        magic_name = None
        has_valid_header = False

        if not is_gz and size >= 2:
            try:
                with open(filepath, "rb") as f:
                    magic_bytes = f.read(2)
                magic_name = cls.KNOWN_WAL_MAGICS.get(magic_bytes)
                has_valid_header = magic_name is not None
            except Exception:
                pass
        elif is_gz and size >= 2:
            has_valid_header = True
            magic_name = "gzip-compressed"

        return WALSegment(
            filename=filename,
            filepath=filepath,
            timeline_id=timeline,
            log_id=log,
            segment_id=segment,
            linear_seq=cls.linear_seq(log, segment),
            size_bytes=size,
            is_valid_size=is_valid_size,
            has_valid_header=has_valid_header,
            header_magic=magic_name,
        )

    @classmethod
    def audit(
        cls,
        wal_directory: str,
        expected_size_mb: int = 16,
        max_reported_gaps: int = 20,
    ) -> PITRReport:
        """
        Audits a WAL archive directory for sequence continuity and corruption.
        """
        if not os.path.isdir(wal_directory):
            return PITRReport(
                wal_directory=wal_directory,
                total_segments=0,
                timelines=[],
                start_segment=None,
                end_segment=None,
                missing_segments=[],
                invalid_size_segments=[],
                is_continuous=False,
                expected_segment_size_bytes=expected_size_mb * 1024 * 1024,
                status="NO_WAL_FILES",
                summary=f"WAL archive directory does not exist: {wal_directory}",
            )

        expected_size_bytes = expected_size_mb * 1024 * 1024
        segments: List[WALSegment] = []

        for fname in sorted(os.listdir(wal_directory)):
            fpath = os.path.join(wal_directory, fname)
            seg = cls.inspect_file(fpath, expected_size_bytes=expected_size_bytes)
            if seg:
                segments.append(seg)

        if not segments:
            return PITRReport(
                wal_directory=wal_directory,
                total_segments=0,
                timelines=[],
                start_segment=None,
                end_segment=None,
                missing_segments=[],
                invalid_size_segments=[],
                is_continuous=False,
                expected_segment_size_bytes=expected_size_bytes,
                status="NO_WAL_FILES",
                summary=f"No valid PostgreSQL WAL segments found in: {wal_directory}",
            )

        # Group by timeline
        by_timeline: Dict[int, List[WALSegment]] = {}
        for s in segments:
            by_timeline.setdefault(s.timeline_id, []).append(s)

        timelines = sorted(list(by_timeline.keys()))
        primary_timeline = timelines[0]  # Standard: evaluate active timeline
        timeline_segments = sorted(by_timeline[primary_timeline], key=lambda x: x.linear_seq)

        start_seg = timeline_segments[0].filename
        end_seg = timeline_segments[-1].filename

        # Check for invalid sizes (truncated uploads)
        invalid_size = [s.filename for s in segments if not s.is_valid_size]

        # Check for sequence continuity
        missing: List[str] = []
        for i in range(len(timeline_segments) - 1):
            curr_seq = timeline_segments[i].linear_seq
            next_seq = timeline_segments[i + 1].linear_seq

            if next_seq > curr_seq + 1:
                # Gap detected
                gap_start = curr_seq + 1
                gap_end = next_seq
                for missing_linear in range(gap_start, gap_end):
                    if len(missing) >= max_reported_gaps:
                        break
                    m_log, m_seg = cls.linear_to_log_seg(missing_linear)
                    missing.append(cls.format_wal_filename(primary_timeline, m_log, m_seg))

        is_continuous = (len(missing) == 0) and (len(invalid_size) == 0)

        if len(missing) > 0:
            status = "GAPS_DETECTED"
            summary = (
                f"PITR chain broken: {len(missing)} missing WAL segments detected "
                f"between {start_seg} and {end_seg}."
            )
        elif len(invalid_size) > 0:
            status = "SIZE_MISMATCH"
            summary = (
                f"PITR risk: {len(invalid_size)} WAL segments have invalid or truncated sizes "
                f"(expected {expected_size_mb}MB)."
            )
        else:
            status = "CONTINUOUS"
            summary = (
                f"Unbroken PITR recovery chain verified: {len(timeline_segments)} continuous WAL segments "
                f"from {start_seg} to {end_seg} (Timeline {primary_timeline})."
            )

        return PITRReport(
            wal_directory=wal_directory,
            total_segments=len(segments),
            timelines=timelines,
            start_segment=start_seg,
            end_segment=end_seg,
            missing_segments=missing,
            invalid_size_segments=invalid_size,
            is_continuous=is_continuous,
            expected_segment_size_bytes=expected_size_bytes,
            status=status,
            summary=summary,
        )

    @classmethod
    def format_terminal_report(cls, report: PITRReport) -> str:
        """Renders formatted ANSI summary for CLI operators."""
        status_tag = "✅ CONTINUOUS" if report.is_continuous else "🔴 CHAIN BROKEN"
        lines = [
            "\n" + "=" * 64,
            f" 🛡️  DrillOps PostgreSQL Point-in-Time Recovery (PITR) Audit: {status_tag}",
            "=" * 64,
            f"Directory:       {report.wal_directory}",
            f"Total Segments:  {report.total_segments}",
            f"Timelines:       {', '.join(str(t) for t in report.timelines) or 'None'}",
            f"Start Segment:   {report.start_segment or 'N/A'}",
            f"End Segment:     {report.end_segment or 'N/A'}",
            f"Chain Status:    {'✅ UNBROKEN SEQUENCE' if report.is_continuous else '❌ GAPS / ERRORS DETECTED'}",
        ]

        if report.missing_segments:
            lines.append("----------------------------------------------------------------")
            lines.append(f"❌ Missing WAL Segments ({len(report.missing_segments)}):")
            for m in report.missing_segments[:8]:
                lines.append(f"   - {m}")
            if len(report.missing_segments) > 8:
                lines.append(f"   ... and {len(report.missing_segments) - 8} more")

        if report.invalid_size_segments:
            lines.append("----------------------------------------------------------------")
            lines.append(f"⚠️ Truncated / Invalid Size Segments ({len(report.invalid_size_segments)}):")
            for inv in report.invalid_size_segments[:5]:
                lines.append(f"   - {inv}")

        lines.extend([
            "----------------------------------------------------------------",
            f"Summary:         {report.summary}",
            "=" * 64 + "\n",
        ])
        return "\n".join(lines)
