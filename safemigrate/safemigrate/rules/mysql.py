"""MySQL / MariaDB DDL safety and zero-downtime migration rules."""

import re
from typing import List, Optional

from safemigrate.models import Dialect, Remediation, Severity, Violation
from safemigrate.parser import ParsedStatement
from safemigrate.rules.base import BaseRule


class RuleSMMY01MissingOnlineAlgorithm(BaseRule):
    """Detects ALTER TABLE without explicit ALGORITHM=INPLACE or ALGORITHM=INSTANT."""
    rule_id = "SM-MY-01"
    name = "mysql-missing-online-algorithm"
    description = "ALTER TABLE without explicit ALGORITHM=INSTANT or ALGORITHM=INPLACE risks falling back to ALGORITHM=COPY (full table copy under lock)."
    dialect = Dialect.MYSQL

    ALTER_PATTERN = re.compile(
        r"ALTER\s+TABLE\s+([^\s;]+)\s+(ADD|DROP|MODIFY|CHANGE|RENAME)",
        re.IGNORECASE
    )

    def evaluate(self, statement: ParsedStatement, all_statements: List[ParsedStatement]) -> Optional[Violation]:
        sql_upper = statement.sql.upper()
        if "ALTER TABLE" not in sql_upper:
            return None

        match = self.ALTER_PATTERN.search(statement.sql)
        if not match:
            return None

        table_name = match.group(1)

        # Check if explicit ALGORITHM is specified
        if "ALGORITHM" not in sql_upper:
            remediation = Remediation(
                title=f"Enforce Online DDL Algorithm on Table '{table_name}'",
                description="Explicitly set ALGORITHM=INSTANT or ALGORITHM=INPLACE to prevent MySQL from copying table data on disk.",
                steps=[
                    f"-- Preferred: instant metadata-only update (MySQL 8.0+)",
                    f"ALTER TABLE {table_name} {match.group(2)} ..., ALGORITHM=INSTANT;",
                    f"-- Fallback: in-place rebuild without table copy",
                    f"ALTER TABLE {table_name} {match.group(2)} ..., ALGORITHM=INPLACE, LOCK=NONE;"
                ]
            )
            return Violation(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=Severity.HIGH,
                message=f"Table '{table_name}': ALTER TABLE lacks explicit ALGORITHM clause. Omitting it risks silent fallback to ALGORITHM=COPY, taking an exclusive lock.",
                line_number=statement.line_number,
                statement=statement.raw_sql,
                remediation=remediation
            )
        return None


class RuleSMMY02MissingLockClause(BaseRule):
    """Detects ALTER TABLE or CREATE INDEX without explicit LOCK=NONE clause."""
    rule_id = "SM-MY-02"
    name = "mysql-missing-lock-clause"
    description = "DDL operations without explicit LOCK=NONE risk blocking concurrent write operations during schema modifications."
    dialect = Dialect.MYSQL

    ALTER_PATTERN = re.compile(
        r"ALTER\s+TABLE\s+([^\s;]+)\s+(ADD\s+COLUMN|DROP\s+COLUMN|ADD\s+INDEX|CREATE\s+INDEX)",
        re.IGNORECASE
    )

    def evaluate(self, statement: ParsedStatement, all_statements: List[ParsedStatement]) -> Optional[Violation]:
        sql_upper = statement.sql.upper()
        if "ALTER TABLE" in sql_upper and "ADD" in sql_upper:
            if "LOCK=" not in sql_upper and "LOCK " not in sql_upper:
                match = self.ALTER_PATTERN.search(statement.sql)
                tbl_name = match.group(1) if match else "table_name"
                remediation = Remediation(
                    title=f"Guarantee Non-Blocking Concurrent Operations",
                    description="Specify LOCK=NONE to ensure concurrent INSERT, UPDATE, and DELETE operations continue during DDL.",
                    steps=[
                        f"ALTER TABLE {tbl_name} ... LOCK=NONE;"
                    ]
                )
                return Violation(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    severity=Severity.MEDIUM,
                    message=f"Table '{tbl_name}': DDL lacks explicit LOCK=NONE clause. Without it, MySQL may acquire LOCK=SHARED or LOCK=EXCLUSIVE.",
                    line_number=statement.line_number,
                    statement=statement.raw_sql,
                    remediation=remediation
                )
        return None


class RuleSMMY03ForeignKeyWriteLock(BaseRule):
    """Detects adding foreign key constraints in MySQL which always take a shared lock."""
    rule_id = "SM-MY-03"
    name = "mysql-foreign-key-write-lock"
    description = "Adding a foreign key constraint in MySQL requires LOCK=SHARED, blocking all writes on both child and parent tables."
    dialect = Dialect.MYSQL

    FK_PATTERN = re.compile(
        r"ALTER\s+TABLE\s+([^\s;]+)\s+ADD\s+(?:CONSTRAINT\s+[^\s;]+\s+)?FOREIGN\s+KEY\s*\(([^)]+)\)\s*REFERENCES\s+([^\s;(]+)",
        re.IGNORECASE
    )

    def evaluate(self, statement: ParsedStatement, all_statements: List[ParsedStatement]) -> Optional[Violation]:
        sql_upper = statement.sql.upper()
        if "FOREIGN KEY" in sql_upper and "ADD" in sql_upper:
            match = self.FK_PATTERN.search(statement.sql)
            if match:
                table_name, col_name, ref_table = match.groups()
                remediation = Remediation(
                    title=f"Mitigate Foreign Key Write Block between '{table_name}' and '{ref_table}'",
                    description="Foreign key additions in MySQL cannot use LOCK=NONE. Use explicit LOCK=SHARED with a tight lock_wait_timeout, or validate via trigger/application logic.",
                    steps=[
                        f"-- Step 1: Set a tight lock timeout to avoid queue pileups",
                        f"SET SESSION lock_wait_timeout = 2;",
                        f"-- Step 2: Ensure index exists on child table first with ALGORITHM=INPLACE, LOCK=NONE",
                        f"ALTER TABLE {table_name} ADD INDEX idx_{col_name.strip()} ({col_name.strip()}), ALGORITHM=INPLACE, LOCK=NONE;",
                        f"-- Step 3: Add foreign key with explicit algorithm and shared lock",
                        f"ALTER TABLE {table_name} ADD CONSTRAINT fk_{table_name}_{col_name.strip()} FOREIGN KEY ({col_name.strip()}) REFERENCES {ref_table.strip()} (id), ALGORITHM=INPLACE, LOCK=SHARED;"
                    ]
                )
                return Violation(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    severity=Severity.HIGH,
                    message=f"Table '{table_name}': Adding foreign key referencing '{ref_table}' takes LOCK=SHARED, blocking concurrent writes on both tables.",
                    line_number=statement.line_number,
                    statement=statement.raw_sql,
                    remediation=remediation
                )
        return None


class RuleSMMY04ColumnTypeRebuild(BaseRule):
    """Detects MODIFY COLUMN or CHANGE COLUMN type alterations that trigger full table rebuilds."""
    rule_id = "SM-MY-04"
    name = "mysql-column-type-rebuild"
    description = "Changing column data types in MySQL requires ALGORITHM=COPY or an in-place table rebuild, blocking applications."
    dialect = Dialect.MYSQL

    MODIFY_PATTERN = re.compile(
        r"ALTER\s+TABLE\s+([^\s;]+)\s+(?:MODIFY|CHANGE)\s+(?:COLUMN\s+)?([^\s;]+)\s+([^\s;,]+)",
        re.IGNORECASE
    )

    def evaluate(self, statement: ParsedStatement, all_statements: List[ParsedStatement]) -> Optional[Violation]:
        sql_upper = statement.sql.upper()
        if "MODIFY" in sql_upper or "CHANGE" in sql_upper:
            match = self.MODIFY_PATTERN.search(statement.sql)
            if match:
                table_name, col_name, new_type = match.groups()
                remediation = Remediation(
                    title=f"Zero-Downtime Column Type Migration for '{col_name}'",
                    description="Use shadow column pattern or gh-ost / pt-online-schema-change to avoid table rebuild downtime.",
                    steps=[
                        f"-- Step 1: Add shadow column with new type (ALGORITHM=INSTANT or INPLACE)",
                        f"ALTER TABLE {table_name} ADD COLUMN {col_name}_new {new_type}, ALGORITHM=INPLACE, LOCK=NONE;",
                        f"-- Step 2: Dual-write in application code to both columns",
                        f"-- Step 3: Backfill historical rows in small batches",
                        f"-- Step 4: Swap columns or use pt-online-schema-change for seamless transition"
                    ]
                )
                return Violation(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    severity=Severity.CRITICAL,
                    message=f"Table '{table_name}': Modifying column '{col_name}' to type '{new_type}' forces a full table rewrite.",
                    line_number=statement.line_number,
                    statement=statement.raw_sql,
                    remediation=remediation
                )
        return None


class RuleSMMY05MissingLockWaitTimeout(BaseRule):
    """Detects DDL migration scripts without an explicit lock_wait_timeout setting."""
    rule_id = "SM-MY-05"
    name = "mysql-missing-lock-wait-timeout"
    description = "MySQL default lock_wait_timeout is 31,536,000s (1 year). DDL waiting for metadata locks can freeze traffic indefinitely."
    dialect = Dialect.MYSQL

    def evaluate(self, statement: ParsedStatement, all_statements: List[ParsedStatement]) -> Optional[Violation]:
        # Only evaluate on the first DDL statement in the file
        is_first_ddl = False
        for s in all_statements:
            s_upper = s.sql.upper()
            if any(kw in s_upper for kw in ["ALTER TABLE", "CREATE TABLE", "DROP TABLE"]):
                if s.line_number == statement.line_number:
                    is_first_ddl = True
                break

        if not is_first_ddl:
            return None

        # Check if any prior or current statement sets lock_wait_timeout
        has_timeout = False
        for s in all_statements:
            s_upper = s.sql.upper()
            if "LOCK_WAIT_TIMEOUT" in s_upper and "SET" in s_upper:
                has_timeout = True
                break

        if not has_timeout:
            remediation = Remediation(
                title="Configure Fail-Safe Metadata Lock Wait Timeout",
                description="Set lock_wait_timeout at the top of the migration script so blocked migrations fail fast rather than stalling all database connections.",
                steps=[
                    "-- Add at the top of the MySQL migration file:",
                    "SET SESSION lock_wait_timeout = 2;"
                ]
            )
            return Violation(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=Severity.LOW,
                message="DDL migration lacks 'SET SESSION lock_wait_timeout'. MySQL default is 1 year (31,536,000s), which can cause catastrophic connection pool lockups.",
                line_number=statement.line_number,
                statement=statement.raw_sql,
                remediation=remediation
            )
        return None


ALL_MYSQL_RULES = [
    RuleSMMY01MissingOnlineAlgorithm(),
    RuleSMMY02MissingLockClause(),
    RuleSMMY03ForeignKeyWriteLock(),
    RuleSMMY04ColumnTypeRebuild(),
    RuleSMMY05MissingLockWaitTimeout(),
]
