"""Integration tests for PostgreSQL restore drills using local PostgreSQL instance."""

import os
import subprocess
import pytest

from drillops.core.runner import DrillRunner
from drillops.models import AssertionRule, VerificationConfig


@pytest.fixture(scope="module")
def postgres_available():
    """Checks if local PostgreSQL service is running and accessible."""
    try:
        res = subprocess.run(
            ["psql", "-h", "localhost", "-U", "agyagent", "-d", "postgres", "-c", "SELECT 1;"],
            capture_output=True,
            text=True,
            env=dict(os.environ, PAGER="cat", PGPAGER="cat"),
            timeout=3,
        )
        return res.returncode == 0
    except Exception:
        return False


@pytest.fixture
def pg_sql_dump(tmp_path):
    """Generates a plain SQL PostgreSQL dump file."""
    dump_path = tmp_path / "pg_production.sql"
    content = """
    CREATE TABLE pg_users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    INSERT INTO pg_users (email, is_active) VALUES ('user1@corp.com', TRUE);
    INSERT INTO pg_users (email, is_active) VALUES ('user2@corp.com', TRUE);
    INSERT INTO pg_users (email, is_active) VALUES ('user3@corp.com', FALSE);

    CREATE TABLE pg_orders (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES pg_users(id),
        total_cents INT NOT NULL
    );
    INSERT INTO pg_orders (user_id, total_cents) VALUES (1, 15000);
    INSERT INTO pg_orders (user_id, total_cents) VALUES (2, 25000);
    """
    dump_path.write_text(content, encoding="utf-8")
    return str(dump_path)


@pytest.fixture
def pg_custom_dump(pg_sql_dump, tmp_path, postgres_available):
    """Generates a PostgreSQL custom binary dump (.dump) using pg_dump -Fc."""
    if not postgres_available:
        pytest.skip("PostgreSQL service is not running")

    # Create temporary seed db, load SQL, dump it with -Fc, then drop seed db
    seed_db = "drillops_seed_temp"
    env = dict(os.environ, PAGER="cat", PGPAGER="cat")
    subprocess.run(["createdb", "-h", "localhost", "-U", "agyagent", seed_db], env=env, check=True)
    subprocess.run(["psql", "-h", "localhost", "-U", "agyagent", "-d", seed_db, "-f", pg_sql_dump], env=env, check=True)

    custom_dump_path = str(tmp_path / "pg_production.dump")
    subprocess.run(["pg_dump", "-h", "localhost", "-U", "agyagent", "-Fc", "-d", seed_db, "-f", custom_dump_path], env=env, check=True)
    subprocess.run(["dropdb", "-h", "localhost", "-U", "agyagent", seed_db], env=env, check=True)

    return custom_dump_path


def test_postgres_plain_sql_drill(pg_sql_dump, tmp_path, postgres_available):
    """Executes a real restore drill against a plain SQL dump on PostgreSQL."""
    if not postgres_available:
        pytest.skip("PostgreSQL service is not running")

    out_dir = tmp_path / "certs"
    config = VerificationConfig(
        database_type="postgres",
        backup_path=pg_sql_dump,
        expected_tables=["pg_users", "pg_orders"],
        assertion_rules=[
            AssertionRule(
                name="min_active_users",
                query="SELECT count(*) FROM pg_users WHERE is_active = TRUE;",
                operator=">=",
                expected_value=2,
            ),
            AssertionRule(
                name="total_order_volume",
                query="SELECT sum(total_cents) FROM pg_orders;",
                operator="==",
                expected_value=40000,
            ),
        ],
        host="localhost",
        port=5432,
        user="agyagent",
    )

    runner = DrillRunner()
    summary, assertions, artifacts = runner.run_drill(config, output_dir=str(out_dir))

    assert summary.overall_status == "PASSED"
    assert summary.restore_duration_sec > 0.0
    assert summary.total_assertions == 4
    assert summary.passed_assertions == 4
    assert summary.failed_assertions == 0
    assert os.path.exists(artifacts["markdown"])
    assert os.path.exists(artifacts["json"])


def test_postgres_custom_format_pg_restore_drill(pg_custom_dump, tmp_path, postgres_available):
    """Executes a real restore drill against a binary custom (.dump) file using pg_restore."""
    if not postgres_available:
        pytest.skip("PostgreSQL service is not running")

    out_dir = tmp_path / "certs_custom"
    config = VerificationConfig(
        database_type="postgres",
        backup_path=pg_custom_dump,
        expected_tables=["pg_users"],
        assertion_rules=[
            AssertionRule(
                name="total_users",
                query="SELECT count(*) FROM pg_users;",
                operator="==",
                expected_value=3,
            )
        ],
        host="localhost",
        port=5432,
        user="agyagent",
    )

    runner = DrillRunner()
    summary, assertions, artifacts = runner.run_drill(config, output_dir=str(out_dir))

    assert summary.overall_status == "PASSED"
    assert summary.passed_assertions == 2
    assert summary.failed_assertions == 0
