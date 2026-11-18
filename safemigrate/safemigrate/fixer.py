"""Auto-fixer engine for SafeMigrate.

Automatically rewrites dangerous blocking DDL migrations into zero-downtime,
non-blocking SQL statements for PostgreSQL and MySQL/MariaDB.
"""

from dataclasses import dataclass, field
import difflib
import os
from pathlib import Path
import re
from typing import List, Tuple

from safemigrate.linter import SafeMigrateLinter
from safemigrate.models import Dialect, Severity


@dataclass
class FixResult:
    """Result of an automated migration remediation rewrite."""
    original_sql: str
    fixed_sql: str
    changes_made: List[str] = field(default_factory=list)
    fixes_applied: int = 0
    passed: bool = True


class MigrationFixer:
    """Transforms hazardous SQL migrations into non-blocking DDL."""

    def __init__(self, dialect: Dialect = Dialect.POSTGRESQL):
        self.dialect = dialect
        self.linter = SafeMigrateLinter(dialect=dialect)

    def generate_diff(self, original_sql: str, fixed_sql: str, file_path: str = "migration.sql") -> str:
        """Generates a standard unified diff between original and fixed SQL."""
        if original_sql == fixed_sql:
            return ""
        orig_lines = original_sql.splitlines(keepends=True)
        fixed_lines = fixed_sql.splitlines(keepends=True)
        diff = difflib.unified_diff(
            orig_lines,
            fixed_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
        )
        return "".join(diff)

    def fix_file(self, file_path: str, in_place: bool = False, out_path: str = None) -> Tuple[FixResult, str]:
        """Fixes a SQL file and optionally writes it in-place or to out_path. Returns (FixResult, diff)."""
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        result = self.fix_string(content)
        diff = self.generate_diff(content, result.fixed_sql, file_path=file_path)

        if in_place and result.fixes_applied > 0:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(result.fixed_sql)
        elif out_path:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(result.fixed_sql)

        return result, diff

    def fix_directory(self, dir_path: str, in_place: bool = False) -> List[Tuple[str, FixResult, str]]:
        """Scans a directory for .sql files and fixes each one."""
        p = Path(dir_path)
        if not p.is_dir():
            raise NotADirectoryError(f"'{dir_path}' is not a directory.")

        results = []
        for sql_file in sorted(p.rglob("*.sql")):
            res, diff = self.fix_file(str(sql_file), in_place=in_place)
            results.append((str(sql_file), res, diff))

        return results

    def fix_string(self, sql_content: str) -> FixResult:
        """Fixes migration SQL string and returns FixResult."""
        lint_result = self.linter.lint_string(sql_content, file_path="<memory>")
        if lint_result.passed and lint_result.low_count == 0 and lint_result.medium_count == 0:
            return FixResult(
                original_sql=sql_content,
                fixed_sql=sql_content,
                changes_made=[],
                fixes_applied=0,
                passed=True,
            )

        changes = []
        fixed_lines = []

        if self.dialect == Dialect.POSTGRESQL:
            fixed_sql, changes = self._fix_postgresql(sql_content, lint_result)
        else:
            fixed_sql, changes = self._fix_mysql(sql_content, lint_result)

        # Validate that the fixed SQL is safe
        verification = self.linter.lint_string(fixed_sql, file_path="<fixed>")
        is_safe = verification.passed

        return FixResult(
            original_sql=sql_content,
            fixed_sql=fixed_sql,
            changes_made=changes,
            fixes_applied=len(changes),
            passed=is_safe,
        )

    def _fix_postgresql(self, sql: str, lint_result) -> Tuple[str, List[str]]:
        changes = []
        statements = sql.strip().split(";")
        output_statements = []

        # Check if lock_timeout is already present
        has_lock_timeout = any("LOCK_TIMEOUT" in s.upper() for s in statements)
        if not has_lock_timeout:
            output_statements.append("-- [SafeMigrate] Strict lock timeout to prevent queue starvation\nSET lock_timeout = '2s'")
            changes.append("Prepended strict lock_timeout ('2s') to prevent connection queue saturation (SM-06)")

        for stmt in statements:
            raw = stmt.strip()
            if not raw:
                continue

            sql_upper = raw.upper()

            # Rule SM-02: CREATE INDEX without CONCURRENTLY
            if ("CREATE INDEX" in sql_upper or "CREATE UNIQUE INDEX" in sql_upper) and "CONCURRENTLY" not in sql_upper:
                # Replace CREATE [UNIQUE] INDEX with CREATE [UNIQUE] INDEX CONCURRENTLY
                fixed_stmt = re.sub(
                    r"CREATE\s+(UNIQUE\s+)?INDEX\b",
                    r"CREATE \1INDEX CONCURRENTLY IF NOT EXISTS",
                    raw,
                    flags=re.IGNORECASE,
                )
                # Clean any double spaces
                fixed_stmt = re.sub(r"\s+", " ", fixed_stmt)
                output_statements.append(f"-- [SafeMigrate] Non-blocking index creation\n{fixed_stmt}")
                changes.append("Transformed CREATE INDEX to use CONCURRENTLY IF NOT EXISTS (SM-02)")
                continue

            # Rule SM-03: ADD CONSTRAINT ... FOREIGN KEY without NOT VALID
            if "FOREIGN KEY" in sql_upper and "NOT VALID" not in sql_upper and "ALTER TABLE" in sql_upper:
                match = re.search(
                    r"ALTER\s+TABLE\s+(?:ONLY\s+)?([^\s;]+)\s+ADD\s+(?:CONSTRAINT\s+([^\s;]+)\s+)?FOREIGN\s+KEY\s*\(([^\)]+)\)\s*REFERENCES\s+([^\s;(]+)\s*\(([^\)]+)\)",
                    raw,
                    re.IGNORECASE,
                )
                if match:
                    tbl, constraint, cols, ref_tbl, ref_cols = match.groups()
                    c_name = constraint or f"fk_{tbl}_{cols.replace(' ', '').replace(',', '_')}"
                    step1 = f"ALTER TABLE {tbl} ADD CONSTRAINT {c_name} FOREIGN KEY ({cols}) REFERENCES {ref_tbl}({ref_cols}) NOT VALID"
                    step2 = f"ALTER TABLE {tbl} VALIDATE CONSTRAINT {c_name}"
                    output_statements.append(f"-- [SafeMigrate] 2-step non-blocking foreign key addition\n{step1};\n{step2}")
                    changes.append(f"Split FOREIGN KEY on '{tbl}' into NOT VALID + VALIDATE CONSTRAINT (SM-03)")
                    continue

            # Rule SM-01: ADD COLUMN ... DEFAULT <volatile>
            if "ALTER TABLE" in sql_upper and "ADD" in sql_upper and "DEFAULT" in sql_upper:
                volatile_indicators = ["gen_random_uuid()", "random()", "uuid_generate_", "clock_timestamp()"]
                if any(vi in raw.lower() for vi in volatile_indicators):
                    match = re.search(
                        r"ALTER\s+TABLE\s+(?:ONLY\s+)?([^\s;]+)\s+ADD\s+(?:COLUMN\s+)?([^\s;]+)\s+([^;]+?)\s+DEFAULT\s+([^;,]+)",
                        raw,
                        re.IGNORECASE,
                    )
                    if match:
                        tbl, col, col_type, default_val = match.groups()
                        step1 = f"ALTER TABLE {tbl} ADD COLUMN {col} {col_type}"
                        step2 = f"ALTER TABLE {tbl} ALTER COLUMN {col} SET DEFAULT {default_val.strip()}"
                        comment3 = f"-- Step 3 (Run outside migration transaction in batches):\n-- UPDATE {tbl} SET {col} = {default_val.strip()} WHERE {col} IS NULL;"
                        output_statements.append(f"-- [SafeMigrate] Zero-downtime 3-step column addition\n{step1};\n{step2};\n{comment3}")
                        changes.append(f"Rewrote volatile DEFAULT on '{col}' to prevent full table rewrite (SM-01)")
                        continue

            output_statements.append(raw)

        fixed_sql = ";\n\n".join(output_statements) + ";\n"
        return fixed_sql, changes

    def _fix_mysql(self, sql: str, lint_result) -> Tuple[str, List[str]]:
        changes = []
        statements = sql.strip().split(";")
        output_statements = []

        # Check if lock_wait_timeout is already present
        has_timeout = any("LOCK_WAIT_TIMEOUT" in s.upper() for s in statements)
        if not has_timeout:
            output_statements.append("-- [SafeMigrate] Enforce short metadata lock timeout\nSET SESSION lock_wait_timeout = 5")
            changes.append("Prepended SET SESSION lock_wait_timeout = 5 to prevent metadata lock starvation (SM-MY-05)")

        for stmt in statements:
            raw = stmt.strip()
            if not raw:
                continue

            sql_upper = raw.upper()

            # Rule SM-MY-01 & SM-MY-02: ALTER TABLE lacking ALGORITHM or LOCK clauses
            if "ALTER TABLE" in sql_upper and ("ADD" in sql_upper or "DROP" in sql_upper or "MODIFY" in sql_upper):
                needs_algorithm = "ALGORITHM" not in sql_upper
                needs_lock = "LOCK=" not in sql_upper and "LOCK " not in sql_upper

                clauses = []
                if needs_algorithm:
                    clauses.append("ALGORITHM=INPLACE")
                if needs_lock:
                    clauses.append("LOCK=NONE")

                if clauses:
                    clause_str = ", " + ", ".join(clauses)
                    fixed_stmt = raw + clause_str
                    output_statements.append(f"-- [SafeMigrate] Enforce online non-blocking DDL\n{fixed_stmt}")
                    changes.append(f"Appended {', '.join(clauses)} to ALTER TABLE (SM-MY-01/02)")
                    continue

            output_statements.append(raw)

        fixed_sql = ";\n\n".join(output_statements) + ";\n"
        return fixed_sql, changes
