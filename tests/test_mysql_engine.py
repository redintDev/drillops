"""Unit and integration tests for MySQLRestoreEngine."""

import os
import tempfile
import pytest

from drillops.engines.mysql_engine import MySQLRestoreEngine
from drillops.generator.synthetic import SyntheticDataGenerator
from drillops.models import AssertionRule, VerificationConfig
from drillops.core.runner import DrillRunner


def is_mysql_available() -> bool:
    """Checks if a local MySQL / MariaDB server is reachable."""
    try:
        engine = MySQLRestoreEngine()
        out = engine._run_mysql_cmd("mysql", "SELECT 1;")
        return out.strip() == "1"
    except Exception:
        return False


MYSQL_AVAILABLE = is_mysql_available()


def test_mysql_engine_init():
    engine = MySQLRestoreEngine(host="127.0.0.1", port=3306, user="testuser")
    assert engine.host == "127.0.0.1"
    assert engine.port == 3306
    assert engine.user == "testuser"
    assert engine.temp_db_name.startswith("drillops_test_")


@pytest.mark.skipif(not MYSQL_AVAILABLE, reason="Local MySQL / MariaDB server not running")
def test_mysql_engine_lifecycle():
    engine = MySQLRestoreEngine()
    try:
        # Step 1: Setup ephemeral database
        engine.setup_ephemeral_db()

        # Step 2: Create table and insert records
        create_sql = (
            "CREATE TABLE employees ("
            "  id INT AUTO_INCREMENT PRIMARY KEY,"
            "  name VARCHAR(100) NOT NULL,"
            "  department VARCHAR(100) NOT NULL,"
            "  salary INT NOT NULL"
            ");"
        )
        engine._run_mysql_cmd(engine.temp_db_name, create_sql)

        insert_sql = (
            "INSERT INTO employees (name, department, salary) VALUES "
            "('Alice', 'Engineering', 120000), "
            "('Bob', 'Finance', 95000), "
            "('Charlie', 'Engineering', 110000);"
        )
        engine._run_mysql_cmd(engine.temp_db_name, insert_sql)

        # Step 3: Test table listing
        tables = engine.list_tables()
        assert "employees" in tables

        # Step 4: Test query execution (scalar count)
        count = engine.execute_query("SELECT COUNT(*) FROM employees;")
        assert count == 3

        # Step 5: Test query execution (string result)
        dept = engine.execute_query("SELECT department FROM employees WHERE name='Alice';")
        assert dept == "Engineering"

        # Step 6: Test query execution (multi-row / multi-col)
        rows = engine.execute_query("SELECT name, salary FROM employees ORDER BY id;")
        assert len(rows) == 3
        assert rows[0] == ["Alice", "120000"]
    finally:
        # Step 7: Teardown
        engine.teardown()

    # Confirm database was dropped
    with pytest.raises(Exception):
        engine._run_mysql_cmd(engine.temp_db_name, "SELECT 1;")


@pytest.mark.skipif(not MYSQL_AVAILABLE, reason="Local MySQL / MariaDB server not running")
def test_mysql_restore_dump():
    gen = SyntheticDataGenerator(seed=123)
    with tempfile.TemporaryDirectory(prefix="mysql_test_") as tmpdir:
        dump_path = os.path.join(tmpdir, "backup.sql")
        gen_meta = gen.generate_mysql_sql(dump_path, num_records=25)

        assert os.path.isfile(dump_path)
        assert gen_meta["engine"] == "mysql"

        engine = MySQLRestoreEngine()
        try:
            engine.setup_ephemeral_db()
            duration = engine.restore_dump(dump_path)
            assert duration > 0.0

            tables = engine.list_tables()
            assert "organizations" in tables
            assert "users" in tables
            assert "transactions" in tables
            assert "audit_logs" in tables

            user_count = engine.execute_query("SELECT COUNT(*) FROM users;")
            assert user_count == 25
        finally:
            engine.teardown()


@pytest.mark.skipif(not MYSQL_AVAILABLE, reason="Local MySQL / MariaDB server not running")
def test_drill_runner_mysql_e2e():
    gen = SyntheticDataGenerator(seed=456)
    with tempfile.TemporaryDirectory(prefix="mysql_e2e_") as tmpdir:
        backup_path = os.path.join(tmpdir, "mysql_backup.sql")
        gen.generate_mysql_sql(backup_path, num_records=30)

        rules = [
            AssertionRule(name="users_count", query="SELECT COUNT(*) FROM users;", operator=">=", expected_value=30),
            AssertionRule(name="orgs_exist", query="SELECT COUNT(*) FROM organizations;", operator=">", expected_value=0),
        ]

        config = VerificationConfig(
            database_type="mysql",
            backup_path=backup_path,
            expected_tables=["users", "organizations", "transactions", "audit_logs"],
            assertion_rules=rules,
        )

        runner = DrillRunner()
        summary, assertions, artifacts = runner.run_drill(config, output_dir=tmpdir)

        assert summary.overall_status == "PASSED"
        assert summary.database_type == "mysql"
        assert summary.total_assertions == 6  # 4 expected tables + 2 custom rules
        assert summary.passed_assertions == 6
        assert summary.failed_assertions == 0
        assert summary.restore_duration_sec > 0.0
        assert os.path.isfile(artifacts["json"])
        assert os.path.isfile(artifacts["markdown"])
        assert os.path.isfile(artifacts["html"])
