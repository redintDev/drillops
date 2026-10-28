"""Tests for schema drift detection."""

import pytest
from drillops.assertions.schema_drift import (
    ColumnDefinition,
    SchemaContract,
    SchemaDriftDetector,
    TableDefinition,
)
from drillops.engines.sqlite_engine import SQLiteRestoreEngine


def test_schema_drift_detection(tmp_path):
    db_file = str(tmp_path / "test_schema.sqlite")
    engine = SQLiteRestoreEngine(db_path=db_file)
    engine.setup_ephemeral_db()

    # Create table with columns: id, email, is_active
    engine.conn.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            email TEXT NOT NULL,
            is_active INTEGER DEFAULT 1
        );
    """)

    detector = SchemaDriftDetector(engine)

    # 1. Test Matching Schema Contract
    expected_valid = SchemaContract(
        tables={
            "users": TableDefinition(
                name="users",
                columns={
                    "id": ColumnDefinition(name="id", data_type="INTEGER"),
                    "email": ColumnDefinition(name="email", data_type="TEXT"),
                    "is_active": ColumnDefinition(name="is_active", data_type="INTEGER"),
                },
            )
        }
    )
    drift_results = detector.detect_drift(expected_valid)
    assert len(drift_results) == 3
    assert all(r.passed for r in drift_results)

    # 2. Test Missing Column
    expected_with_missing_col = SchemaContract(
        tables={
            "users": TableDefinition(
                name="users",
                columns={
                    "id": ColumnDefinition(name="id", data_type="INTEGER"),
                    "billing_address": ColumnDefinition(name="billing_address", data_type="TEXT"),
                },
            )
        }
    )
    drift_missing = detector.detect_drift(expected_with_missing_col)
    assert len(drift_missing) == 2
    failed_col = [r for r in drift_missing if not r.passed]
    assert len(failed_col) == 1
    assert "billing_address" in failed_col[0].error

    # 3. Test Missing Entire Table
    expected_missing_table = SchemaContract(
        tables={
            "subscriptions": TableDefinition(
                name="subscriptions",
                columns={"id": ColumnDefinition(name="id", data_type="INTEGER")},
            )
        }
    )
    drift_table = detector.detect_drift(expected_missing_table)
    assert len(drift_table) == 1
    assert not drift_table[0].passed
    assert "subscriptions" in drift_table[0].error

    engine.teardown()
