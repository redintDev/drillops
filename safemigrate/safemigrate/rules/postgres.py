"""PostgreSQL DDL safety and zero-downtime migration rules."""

import re
from typing import List, Optional

from safemigrate.models import Dialect, Remediation, Severity, Violation
from safemigrate.parser import ParsedStatement
from safemigrate.rules.base import BaseRule


class RuleSM01AddColumnVolatileDefault(BaseRule):
    """Detects adding a column with a volatile or non-constant default value."""
    rule_id = "SM-01"
    name = "add-column-volatile-default"
    description = "Adding a column with a volatile default forces a full table rewrite holding AccessExclusiveLock."
    dialect = Dialect.POSTGRESQL

    # Matches ALTER TABLE ... ADD [COLUMN] ... DEFAULT <expr>
    PATTERN = re.compile(
        r"ALTER\s+TABLE\s+(?:ONLY\s+)?([^\s;]+)\s+ADD\s+(?:COLUMN\s+)?([^\s;]+)\s+([^;]+?)\s+DEFAULT\s+([^;,]+)",
        re.IGNORECASE
    )

    # Volatile functions in Postgres that prevent instant metadata-only default addition
    VOLATILE_INDICATORS = [
        "random()", "gen_random_uuid()", "uuid_generate_", "clock_timestamp()",
        "timeofday()", "statement_timestamp()"
    ]

    def evaluate(self, statement: ParsedStatement, all_statements: List[ParsedStatement]) -> Optional[Violation]:
        match = self.PATTERN.search(statement.sql)
        if not match:
            return None

        table_name, col_name, col_type, default_val = match.groups()
        default_val_lower = default_val.strip().lower()

        is_volatile = any(fn in default_val_lower for fn in self.VOLATILE_INDICATORS)
        is_function_call = bool(re.search(r"\w+\s*\(.*?\)", default_val_lower)) and not default_val_lower.startswith("'")

        if is_volatile or is_function_call:
            remediation = Remediation(
                title=f"Zero-Downtime Column Addition for '{col_name}'",
                description="Add the column without a volatile default, backfill existing rows in batches, then attach the default for new rows.",
                steps=[
                    f"-- Step 1: Add column without volatile default (instant metadata lock)",
                    f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type};",
                    f"-- Step 2: Set the default for future inserts",
                    f"ALTER TABLE {table_name} ALTER COLUMN {col_name} SET DEFAULT {default_val.strip()};",
                    f"-- Step 3: Backfill existing rows in batches outside the migration transaction",
                    f"UPDATE {table_name} SET {col_name} = {default_val.strip()} WHERE {col_name} IS NULL;"
                ]
            )
            return Violation(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=Severity.CRITICAL,
                message=f"Table '{table_name}': Adding column '{col_name}' with volatile default '{default_val.strip()}' triggers a full table rewrite.",
                line_number=statement.line_number,
                statement=statement.raw_sql,
                remediation=remediation
            )
        return None


class RuleSM02CreateIndexWithoutConcurrently(BaseRule):
    """Detects index creation without the CONCURRENTLY keyword."""
    rule_id = "SM-02"
    name = "create-index-without-concurrently"
    description = "Creating an index without CONCURRENTLY takes a ShareLock that blocks all writes (INSERT/UPDATE/DELETE)."
    dialect = Dialect.POSTGRESQL

    PATTERN = re.compile(
        r"CREATE\s+(UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?([^\s;]+)\s+ON\s+([^\s;(]+)",
        re.IGNORECASE
    )

    def evaluate(self, statement: ParsedStatement, all_statements: List[ParsedStatement]) -> Optional[Violation]:
        sql_upper = statement.sql.upper()
        if "CREATE INDEX" in sql_upper or "CREATE UNIQUE INDEX" in sql_upper:
            if "CONCURRENTLY" not in sql_upper:
                match = self.PATTERN.search(statement.sql)
                idx_name = match.group(2) if match else "idx_name"
                tbl_name = match.group(3) if match else "table_name"

                # Extract everything after ON table_name
                remainder = ""
                if match:
                    remainder = statement.sql[match.end():].rstrip(";").strip()

                is_unique = "UNIQUE " if "UNIQUE" in sql_upper else ""
                remediation = Remediation(
                    title=f"Non-Blocking Index Creation with CONCURRENTLY",
                    description="Run index creation with CONCURRENTLY. Note: CONCURRENTLY cannot run inside a multi-statement transaction block.",
                    steps=[
                        f"-- Run outside a transaction block (autocommit mode)",
                        f"CREATE {is_unique}INDEX CONCURRENTLY IF NOT EXISTS {idx_name} ON {tbl_name} {remainder};"
                    ]
                )
                return Violation(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    severity=Severity.HIGH,
                    message=f"Index '{idx_name}' created without CONCURRENTLY. This blocks concurrent writes on table '{tbl_name}'.",
                    line_number=statement.line_number,
                    statement=statement.raw_sql,
                    remediation=remediation
                )
        return None


class RuleSM03AddForeignKeyWithoutNotValid(BaseRule):
    """Detects adding a foreign key constraint without NOT VALID."""
    rule_id = "SM-03"
    name = "add-foreign-key-without-not-valid"
    description = "Adding a foreign key without NOT VALID scans the entire table under a strong lock to check referential integrity."
    dialect = Dialect.POSTGRESQL

    PATTERN = re.compile(
        r"ALTER\s+TABLE\s+(?:ONLY\s+)?([^\s;]+)\s+ADD\s+(?:CONSTRAINT\s+([^\s;]+)\s+)?FOREIGN\s+KEY\s*\(([^\)]+)\)\s*REFERENCES\s+([^\s;(]+)\s*\(([^\)]+)\)",
        re.IGNORECASE
    )

    def evaluate(self, statement: ParsedStatement, all_statements: List[ParsedStatement]) -> Optional[Violation]:
        match = self.PATTERN.search(statement.sql)
        if match:
            sql_upper = statement.sql.upper()
            if "NOT VALID" not in sql_upper:
                tbl_name, constraint_name, cols, ref_tbl, ref_cols = match.groups()
                c_name = constraint_name or f"fk_{tbl_name}_{cols.replace(' ', '').replace(',', '_')}"
                remediation = Remediation(
                    title=f"Zero-Downtime Foreign Key Constraint Addition",
                    description="Add the constraint with NOT VALID (instant metadata lock), then validate it in a separate step without blocking writes.",
                    steps=[
                        f"-- Step 1: Add constraint without validating existing rows (instant)",
                        f"ALTER TABLE {tbl_name} ADD CONSTRAINT {c_name} FOREIGN KEY ({cols}) REFERENCES {ref_tbl}({ref_cols}) NOT VALID;",
                        f"-- Step 2: Validate the constraint concurrently without blocking writes",
                        f"ALTER TABLE {tbl_name} VALIDATE CONSTRAINT {c_name};"
                    ]
                )
                return Violation(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    severity=Severity.HIGH,
                    message=f"Table '{tbl_name}': Adding FOREIGN KEY constraint without NOT VALID locks table for full validation scan.",
                    line_number=statement.line_number,
                    statement=statement.raw_sql,
                    remediation=remediation
                )
        return None


class RuleSM04AlterColumnType(BaseRule):
    """Detects altering a column type which requires a full table rewrite."""
    rule_id = "SM-04"
    name = "alter-column-type"
    description = "Altering a column data type frequently requires a full table rewrite holding AccessExclusiveLock."
    dialect = Dialect.POSTGRESQL

    PATTERN = re.compile(
        r"ALTER\s+TABLE\s+(?:ONLY\s+)?([^\s;]+)\s+ALTER\s+(?:COLUMN\s+)?([^\s;]+)\s+(?:SET\s+DATA\s+)?TYPE\s+([^;]+)",
        re.IGNORECASE
    )

    def evaluate(self, statement: ParsedStatement, all_statements: List[ParsedStatement]) -> Optional[Violation]:
        match = self.PATTERN.search(statement.sql)
        if match:
            tbl_name, col_name, new_type = match.groups()
            remediation = Remediation(
                title=f"Zero-Downtime Column Type Migration for '{col_name}'",
                description="Create a new column with the target type, dual-write to both columns via triggers or application, backfill, and swap.",
                steps=[
                    f"-- Step 1: Add new column with the desired type",
                    f"ALTER TABLE {tbl_name} ADD COLUMN {col_name}_new {new_type.strip()};",
                    f"-- Step 2: Set up dual-write trigger or update application logic to write to both",
                    f"-- Step 3: Backfill existing rows in batches (e.g. UPDATE {tbl_name} SET {col_name}_new = {col_name} WHERE ...)",
                    f"-- Step 4: Swap columns via transaction after backfill completes:",
                    f"BEGIN;",
                    f"  SET LOCAL lock_timeout = '2s';",
                    f"  ALTER TABLE {tbl_name} RENAME COLUMN {col_name} TO {col_name}_old;",
                    f"  ALTER TABLE {tbl_name} RENAME COLUMN {col_name}_new TO {col_name};",
                    f"COMMIT;"
                ]
            )
            return Violation(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=Severity.CRITICAL,
                message=f"Table '{tbl_name}': Changing type of column '{col_name}' to '{new_type.strip()}' rewrites table under AccessExclusiveLock.",
                line_number=statement.line_number,
                statement=statement.raw_sql,
                remediation=remediation
            )
        return None


class RuleSM05DropColumnWithoutLockTimeout(BaseRule):
    """Detects dropping a column without prior lock_timeout protection."""
    rule_id = "SM-05"
    name = "drop-column-lock-risk"
    description = "Dropping a column requires AccessExclusiveLock and can block connection pools if blocked behind long-running queries."
    dialect = Dialect.POSTGRESQL

    PATTERN = re.compile(
        r"ALTER\s+TABLE\s+(?:ONLY\s+)?([^\s;]+)\s+DROP\s+(?:COLUMN\s+)?([^\s;]+)",
        re.IGNORECASE
    )

    def evaluate(self, statement: ParsedStatement, all_statements: List[ParsedStatement]) -> Optional[Violation]:
        match = self.PATTERN.search(statement.sql)
        if match:
            tbl_name, col_name = match.groups()
            # Check if any prior statement set lock_timeout
            has_lock_timeout = any("LOCK_TIMEOUT" in s.sql.upper() for s in all_statements)
            if not has_lock_timeout:
                remediation = Remediation(
                    title=f"Safely Dropping Column '{col_name}'",
                    description="Ensure application code no longer queries this column, and enforce a strict lock_timeout to prevent queue starvation.",
                    steps=[
                        f"-- Step 1: Ensure application code has ignored/removed '{col_name}' in previous deployment",
                        f"-- Step 2: Set strict lock_timeout before dropping",
                        f"SET lock_timeout = '2s';",
                        f"ALTER TABLE {tbl_name} DROP COLUMN {col_name};"
                    ]
                )
                return Violation(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    severity=Severity.MEDIUM,
                    message=f"Table '{tbl_name}': Dropping column '{col_name}' requires AccessExclusiveLock without lock_timeout protection.",
                    line_number=statement.line_number,
                    statement=statement.raw_sql,
                    remediation=remediation
                )
        return None


class RuleSM06MissingLockTimeout(BaseRule):
    """Warns if a migration contains DDL statements but sets no lock_timeout."""
    rule_id = "SM-06"
    name = "missing-lock-timeout"
    description = "DDL migrations should specify a short lock_timeout to fail fast rather than stalling application connection pools."
    dialect = Dialect.POSTGRESQL

    DDL_INDICATORS = ["ALTER TABLE", "DROP TABLE", "CREATE TABLE", "TRUNCATE", "DROP INDEX"]

    def evaluate(self, statement: ParsedStatement, all_statements: List[ParsedStatement]) -> Optional[Violation]:
        # Only evaluate on the first DDL statement in the file
        is_ddl = any(ind in statement.sql.upper() for ind in self.DDL_INDICATORS)
        if not is_ddl:
            return None

        # Check if this is the first DDL statement
        first_ddl = None
        for s in all_statements:
            if any(ind in s.sql.upper() for ind in self.DDL_INDICATORS):
                first_ddl = s
                break

        if statement != first_ddl:
            return None

        # Check if lock_timeout was set in any statement
        has_lock_timeout = any("LOCK_TIMEOUT" in s.sql.upper() for s in all_statements)
        if not has_lock_timeout:
            remediation = Remediation(
                title="Add Lock Timeout Safeguard",
                description="Set a short lock_timeout (e.g. 2s or 5s) at the start of your migration script.",
                steps=[
                    "-- Add at the very beginning of the migration file:",
                    "SET lock_timeout = '3s';"
                ]
            )
            return Violation(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=Severity.LOW,
                message="Migration performs DDL operations without setting 'lock_timeout'. Risk of lock queue starvation.",
                line_number=statement.line_number,
                statement=statement.raw_sql,
                remediation=remediation
            )
        return None


ALL_POSTGRES_RULES = [
    RuleSM01AddColumnVolatileDefault(),
    RuleSM02CreateIndexWithoutConcurrently(),
    RuleSM03AddForeignKeyWithoutNotValid(),
    RuleSM04AlterColumnType(),
    RuleSM05DropColumnWithoutLockTimeout(),
    RuleSM06MissingLockTimeout(),
]
