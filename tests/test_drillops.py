"""Unit and integration tests for DrillOps restore drill engine."""

import gzip
import json
import os
import tempfile
import pytest

from drillops.assertions import AssertionEvaluator
from drillops.certifier import CertificateGenerator
from drillops.core.runner import DrillRunner
from drillops.engines.sqlite_engine import SQLiteRestoreEngine
from drillops.models import AssertionRule, VerificationConfig
from drillops.storage.archive import ArchiveProcessor


@pytest.fixture
def sample_sql_dump(tmp_path):
    """Creates a realistic SQL dump file fixture."""
    dump_path = tmp_path / "production_backup.sql"
    sql_content = """
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        email TEXT NOT NULL,
        is_active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    INSERT INTO users (id, email, is_active) VALUES (1, 'alice@example.com', 1);
    INSERT INTO users (id, email, is_active) VALUES (2, 'bob@example.com', 1);
    INSERT INTO users (id, email, is_active) VALUES (3, 'charlie@example.com', 0);

    CREATE TABLE subscriptions (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        plan TEXT NOT NULL,
        amount_cents INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    INSERT INTO subscriptions (id, user_id, plan, amount_cents) VALUES (1, 1, 'pro', 4900);
    INSERT INTO subscriptions (id, user_id, plan, amount_cents) VALUES (2, 2, 'starter', 1900);
    """
    dump_path.write_text(sql_content, encoding="utf-8")
    return str(dump_path)


@pytest.fixture
def gzipped_sql_dump(sample_sql_dump, tmp_path):
    """Creates a gzipped version of the sample SQL dump."""
    gz_path = tmp_path / "production_backup.sql.gz"
    with open(sample_sql_dump, "rb") as f_in, gzip.open(gz_path, "wb") as f_out:
        f_out.write(f_in.read())
    return str(gz_path)


def test_archive_processor(sample_sql_dump):
    """Verifies archive inspection and checksum computation."""
    size, checksum = ArchiveProcessor.inspect_file(sample_sql_dump)
    assert size > 0
    assert len(checksum) == 64  # SHA-256 is 64 hex characters


def test_gzipped_archive_preparation(gzipped_sql_dump, tmp_path):
    """Verifies that .gz archives are properly unpacked."""
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    unpacked = ArchiveProcessor.prepare_archive(gzipped_sql_dump, str(work_dir))
    assert os.path.exists(unpacked)
    assert unpacked.endswith(".sql")
    assert not unpacked.endswith(".gz")


def test_successful_restore_drill_end_to_end(sample_sql_dump, tmp_path):
    """Full end-to-end restore drill test verifying table existence and custom SQL assertions."""
    out_dir = tmp_path / "certs"
    config = VerificationConfig(
        database_type="sqlite",
        backup_path=sample_sql_dump,
        expected_tables=["users", "subscriptions"],
        assertion_rules=[
            AssertionRule(
                name="active_users_threshold",
                query="SELECT count(*) FROM users WHERE is_active = 1;",
                operator=">=",
                expected_value=2,
            ),
            AssertionRule(
                name="total_revenue_volume",
                query="SELECT sum(amount_cents) FROM subscriptions;",
                operator="==",
                expected_value=6800,
            ),
        ],
    )

    runner = DrillRunner()
    summary, assertions, artifacts = runner.run_drill(config, output_dir=str(out_dir))

    assert summary.overall_status == "PASSED"
    assert summary.restore_duration_sec > 0.0
    assert summary.total_assertions == 4  # 2 table checks + 2 query rules
    assert summary.passed_assertions == 4
    assert summary.failed_assertions == 0
    assert len(summary.failure_reasons) == 0

    # Verify compliance certificates were generated
    assert "json" in artifacts and os.path.exists(artifacts["json"])
    assert "markdown" in artifacts and os.path.exists(artifacts["markdown"])

    # Verify JSON structure
    with open(artifacts["json"]) as f:
        cert_data = json.load(f)
    assert cert_data["overall_status"] == "PASSED"
    assert cert_data["target"]["backup_filename"] == "production_backup.sql"
    assert len(cert_data["assertions"]) == 4


def test_gzipped_dump_drill(gzipped_sql_dump, tmp_path):
    """Verifies restore drill against a compressed .sql.gz archive."""
    config = VerificationConfig(
        database_type="sqlite",
        backup_path=gzipped_sql_dump,
        expected_tables=["users"],
        assertion_rules=[
            AssertionRule(
                name="user_count",
                query="SELECT count(*) FROM users;",
                operator="==",
                expected_value=3,
            )
        ],
    )

    runner = DrillRunner()
    summary, assertions, artifacts = runner.run_drill(config, output_dir=str(tmp_path / "certs"))
    assert summary.overall_status == "PASSED"
    assert summary.passed_assertions == 2


def test_missing_table_detection(sample_sql_dump, tmp_path):
    """Verifies that missing critical tables fail the drill."""
    config = VerificationConfig(
        database_type="sqlite",
        backup_path=sample_sql_dump,
        expected_tables=["users", "billing_invoices"],  # billing_invoices does not exist
    )

    runner = DrillRunner()
    summary, assertions, artifacts = runner.run_drill(config, output_dir=str(tmp_path / "certs"))

    assert summary.overall_status == "FAILED"
    assert summary.failed_assertions == 1
    assert any("billing_invoices" in r for r in summary.failure_reasons)


def test_assertion_query_failure(sample_sql_dump, tmp_path):
    """Verifies that unmet SQL assertion thresholds trigger compliance deficit."""
    config = VerificationConfig(
        database_type="sqlite",
        backup_path=sample_sql_dump,
        assertion_rules=[
            AssertionRule(
                name="unrealistic_user_threshold",
                query="SELECT count(*) FROM users;",
                operator=">=",
                expected_value=1000,  # We only have 3 users
                critical=True,
            )
        ],
    )

    runner = DrillRunner()
    summary, assertions, artifacts = runner.run_drill(config, output_dir=str(tmp_path / "certs"))

    assert summary.overall_status == "FAILED"
    assert summary.failed_assertions == 1


def test_corrupted_backup_detection(tmp_path):
    """Verifies that syntactically corrupted dump files fail safely without crashing."""
    corrupted_dump = tmp_path / "corrupted.sql"
    corrupted_dump.write_text("THIS IS NOT VALID SQL SYNTAX %%% CORRUPTED DATA %%%", encoding="utf-8")

    config = VerificationConfig(
        database_type="sqlite",
        backup_path=str(corrupted_dump),
        expected_tables=["users"],
    )

    runner = DrillRunner()
    summary, assertions, artifacts = runner.run_drill(config, output_dir=str(tmp_path / "certs"))

    assert summary.overall_status == "FAILED"
    assert len(summary.failure_reasons) > 0


def test_assertion_operators():
    """Unit test for assertion comparison operators."""
    cmp = AssertionEvaluator._compare
    assert cmp(10, "==", 10)
    assert cmp(10, "!=", 5)
    assert cmp(10, ">", 5)
    assert cmp(10, ">=", 10)
    assert cmp(5, "<", 10)
    assert cmp(5, "<=", 5)
    assert cmp([1, 2], "not_empty", None)
    assert cmp("hello world", "contains", "world")
    assert not cmp(4, ">", 10)
