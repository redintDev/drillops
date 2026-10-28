"""Schema drift detector for comparing restored database structure against expected baseline."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from drillops.engines.base import BaseRestoreEngine
from drillops.models import AssertionResult


@dataclass
class ColumnDefinition:
    name: str
    data_type: str
    nullable: bool = True
    is_primary_key: bool = False


@dataclass
class TableDefinition:
    name: str
    columns: Dict[str, ColumnDefinition] = field(default_factory=dict)


@dataclass
class SchemaContract:
    tables: Dict[str, TableDefinition] = field(default_factory=dict)


class SchemaDriftDetector:
    """Inspects restored database schema and reports missing columns, altered types, or dropped tables."""

    def __init__(self, engine: BaseRestoreEngine):
        self.engine = engine

    def introspect_sqlite_table(self, table_name: str) -> TableDefinition:
        """Extract columns and types for SQLite table."""
        rows = self.engine.execute_query(f"PRAGMA table_info({table_name});")
        table_def = TableDefinition(name=table_name)
        if isinstance(rows, list):
            for r in rows:
                col_name = r["name"]
                data_type = r["type"].upper()
                notnull = bool(r["notnull"])
                pk = bool(r["pk"])
                table_def.columns[col_name] = ColumnDefinition(
                    name=col_name,
                    data_type=data_type,
                    nullable=not notnull,
                    is_primary_key=pk,
                )
        return table_def

    def detect_drift(self, expected_schema: SchemaContract) -> List[AssertionResult]:
        """Compares restored database tables against the expected schema contract."""
        results = []
        actual_tables = set(self.engine.list_tables())

        for table_name, expected_table in expected_schema.tables.items():
            if table_name not in actual_tables:
                results.append(
                    AssertionResult(
                        rule_name=f"schema_drift_table_{table_name}",
                        passed=False,
                        actual_value="table_missing",
                        expected_value="table_present",
                        execution_time_ms=0.0,
                        critical=True,
                        error=f"Table '{table_name}' is defined in schema contract but missing in restored backup",
                    )
                )
                continue

            # Table exists; introspect columns
            try:
                actual_table_def = self.introspect_sqlite_table(table_name)
                for col_name, expected_col in expected_table.columns.items():
                    if col_name not in actual_table_def.columns:
                        results.append(
                            AssertionResult(
                                rule_name=f"schema_drift_{table_name}_{col_name}",
                                passed=False,
                                actual_value="column_missing",
                                expected_value=f"column_{expected_col.data_type}",
                                execution_time_ms=0.1,
                                critical=True,
                                error=f"Column '{col_name}' missing from table '{table_name}'",
                            )
                        )
                    else:
                        actual_col = actual_table_def.columns[col_name]
                        # Type match check (case-insensitive substring or exact)
                        type_match = expected_col.data_type.upper() in actual_col.data_type.upper()
                        results.append(
                            AssertionResult(
                                rule_name=f"schema_drift_{table_name}_{col_name}",
                                passed=type_match,
                                actual_value=actual_col.data_type,
                                expected_value=expected_col.data_type,
                                execution_time_ms=0.1,
                                critical=False,
                                error=None if type_match else f"Column '{col_name}' type mismatch: actual '{actual_col.data_type}' vs expected '{expected_col.data_type}'",
                            )
                        )
            except Exception as e:
                results.append(
                    AssertionResult(
                        rule_name=f"schema_introspection_{table_name}",
                        passed=False,
                        actual_value="error",
                        expected_value="ok",
                        execution_time_ms=0.0,
                        critical=True,
                        error=f"Failed to introspect table {table_name}: {str(e)}",
                    )
                )

        return results
