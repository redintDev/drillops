"""Unit and integration tests for Synthetic Data Generator and end-to-end drill verification."""

import gzip
import os
import sqlite3
import tempfile
import pytest

from drillops.core.runner import DrillRunner
from drillops.generator import SyntheticDataGenerator
from drillops.models import VerificationConfig


def test_generate_sqlite_valid():
    gen = SyntheticDataGenerator(seed=123)
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_synth.sqlite")
        meta = gen.generate_sqlite_file(db_path, num_records=50)

        assert os.path.isfile(db_path)
        assert meta["engine"] == "sqlite"
        assert meta["corrupt_mode"] == "none"
        assert meta["record_counts"]["users"] == 50
        assert meta["record_counts"]["transactions"] == 150

        # Verify tables and rows directly in sqlite
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM users")
        assert cur.fetchone()[0] == 50
        cur.execute("SELECT count(*) FROM organizations")
        assert cur.fetchone()[0] >= 2
        cur.execute("SELECT count(*) FROM transactions")
        assert cur.fetchone()[0] == 150
        conn.close()


def test_generate_sqlite_corrupt_truncate():
    gen = SyntheticDataGenerator(seed=123)
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_trunc.sqlite")
        meta = gen.generate_sqlite_file(db_path, num_records=50, corrupt_mode="truncate")

        assert os.path.isfile(db_path)
        assert meta["corrupt_mode"] == "truncate"


def test_generate_sqlite_corrupt_drop_table():
    gen = SyntheticDataGenerator(seed=123)
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_drift.sqlite")
        meta = gen.generate_sqlite_file(db_path, num_records=50, corrupt_mode="drop_table")

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
        conn.close()

        assert "transactions" not in tables
        assert "users" in tables


def test_generate_postgres_sql():
    gen = SyntheticDataGenerator(seed=123)
    with tempfile.TemporaryDirectory() as tmpdir:
        sql_path = os.path.join(tmpdir, "test_pg.sql")
        meta = gen.generate_postgres_sql(sql_path, num_records=30)

        assert os.path.isfile(sql_path)
        with open(sql_path, "r", encoding="utf-8") as f:
            content = f.read()

        assert "CREATE TABLE IF NOT EXISTS users" in content
        assert "INSERT INTO users" in content
        assert "INSERT INTO organizations" in content


def test_generate_postgres_gzip():
    gen = SyntheticDataGenerator(seed=123)
    with tempfile.TemporaryDirectory() as tmpdir:
        gz_path = os.path.join(tmpdir, "test_pg.sql.gz")
        meta = gen.generate_postgres_sql(gz_path, num_records=30, compress_gzip=True)

        assert os.path.isfile(meta["output_path"])
        with gzip.open(meta["output_path"], "rt", encoding="utf-8") as f:
            decompressed = f.read()

        assert "CREATE TABLE IF NOT EXISTS users" in decompressed


def test_end_to_end_drill_with_synthetic_sqlite():
    gen = SyntheticDataGenerator(seed=999)
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "synthetic_eval.sqlite")
        gen.generate_sqlite_file(db_path, num_records=40)

        config = VerificationConfig(
            database_type="sqlite",
            backup_path=db_path,
            expected_tables=["users", "organizations", "transactions", "audit_logs"],
        )

        runner = DrillRunner()
        summary, assertions, artifacts = runner.run_drill(config, output_dir=os.path.join(tmpdir, "certs"))

        assert summary.overall_status == "PASSED"
        assert summary.total_assertions >= 4
        assert summary.passed_assertions == summary.total_assertions
        assert summary.restore_duration_sec >= 0.0


def test_end_to_end_drill_with_corrupted_backup():
    gen = SyntheticDataGenerator(seed=999)
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "corrupted_eval.sqlite")
        # Generates with transactions table missing
        gen.generate_sqlite_file(db_path, num_records=40, corrupt_mode="drop_table")

        config = VerificationConfig(
            database_type="sqlite",
            backup_path=db_path,
            expected_tables=["users", "transactions"],  # transactions is missing
        )

        runner = DrillRunner()
        summary, assertions, artifacts = runner.run_drill(config, output_dir=os.path.join(tmpdir, "certs"))

        assert summary.overall_status == "FAILED"
        assert summary.failed_assertions >= 1
        assert any("table_exists_transactions" in str(r) for r in summary.failure_reasons)


def test_generate_mysql_sql():
    gen = SyntheticDataGenerator(seed=123)
    with tempfile.TemporaryDirectory() as tmpdir:
        sql_path = os.path.join(tmpdir, "test_mysql.sql")
        meta = gen.generate_mysql_sql(sql_path, num_records=30)

        assert os.path.isfile(sql_path)
        assert meta["engine"] == "mysql"
        with open(sql_path, "r", encoding="utf-8") as f:
            content = f.read()

        assert "CREATE TABLE IF NOT EXISTS `users`" in content
        assert "ENGINE=InnoDB" in content
        assert "INSERT INTO `users`" in content
        assert "INSERT INTO `organizations`" in content


def test_generate_mysql_gzip():
    gen = SyntheticDataGenerator(seed=123)
    with tempfile.TemporaryDirectory() as tmpdir:
        gz_path = os.path.join(tmpdir, "test_mysql.sql.gz")
        meta = gen.generate_mysql_sql(gz_path, num_records=30, compress_gzip=True)

        assert os.path.isfile(meta["output_path"])
        with gzip.open(meta["output_path"], "rt", encoding="utf-8") as f:
            decompressed = f.read()

        assert "CREATE TABLE IF NOT EXISTS `users`" in decompressed
        assert "ENGINE=InnoDB" in decompressed

