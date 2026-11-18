"""SQL migration parser with line number preservation."""

import re
from typing import List, Tuple


class ParsedStatement:
    def __init__(self, sql: str, line_number: int, raw_sql: str):
        self.sql = sql.strip()
        self.line_number = line_number
        self.raw_sql = raw_sql.strip()

    def __repr__(self) -> str:
        return f"ParsedStatement(line={self.line_number}, sql={self.sql[:40]}...)"


class MigrationParser:
    """Extracts SQL DDL statements with line numbers while stripping comments."""

    @staticmethod
    def parse_sql(content: str) -> List[ParsedStatement]:
        statements: List[ParsedStatement] = []
        lines = content.splitlines()
        
        current_stmt_lines: List[str] = []
        current_raw_lines: List[str] = []
        stmt_start_line = 1
        in_block_comment = False

        for line_idx, line in enumerate(lines, start=1):
            stripped_line = line.strip()
            
            # Handle block comments /* ... */
            if in_block_comment:
                if "*/" in line:
                    in_block_comment = False
                    post_comment = line.split("*/", 1)[1]
                    stripped_line = post_comment.strip()
                else:
                    continue

            if "/*" in stripped_line:
                pre_comment, _, remainder = stripped_line.partition("/*")
                if "*/" in remainder:
                    # Single-line block comment
                    post_comment = remainder.split("*/", 1)[1]
                    stripped_line = (pre_comment + " " + post_comment).strip()
                else:
                    in_block_comment = True
                    stripped_line = pre_comment.strip()

            # Handle line comments -- ...
            if "--" in stripped_line:
                stripped_line = stripped_line.split("--", 1)[0].strip()

            if not stripped_line:
                continue

            if not current_stmt_lines:
                stmt_start_line = line_idx

            current_stmt_lines.append(stripped_line)
            current_raw_lines.append(line)

            # Check for statement terminator ';'
            if stripped_line.endswith(";"):
                full_stmt = " ".join(current_stmt_lines)
                raw_stmt = "\n".join(current_raw_lines)
                statements.append(ParsedStatement(sql=full_stmt, line_number=stmt_start_line, raw_sql=raw_stmt))
                current_stmt_lines = []
                current_raw_lines = []

        # Trailing statement without semicolon
        if current_stmt_lines:
            full_stmt = " ".join(current_stmt_lines)
            raw_stmt = "\n".join(current_raw_lines)
            statements.append(ParsedStatement(sql=full_stmt, line_number=stmt_start_line, raw_sql=raw_stmt))

        return statements
