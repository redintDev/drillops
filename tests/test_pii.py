"""Unit and integration tests for DrillOps PII & sensitive data leak detection."""

import json
import sqlite3
import pytest

from drillops.assertions.pii_scanner import PIIScanner, PIIFinding
from drillops.cli import main
from drillops.core.runner import DrillRunner
from drillops.engines.sqlite_engine import SQLiteRestoreEngine
from drillops.models import VerificationConfig


@pytest.fixture
def clean_db(tmp_path):
    """Creates a database with no sensitive data leaks."""
    db_file = tmp_path / "clean.sqlite"
    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            display_name TEXT,
            created_at TEXT
        );
    """)
    cur.execute("""
        CREATE TABLE products (
            sku TEXT PRIMARY KEY,
            price_cents INTEGER,
            stock INTEGER
        );
    """)
    cur.execute("INSERT INTO users VALUES (1, 'alice', 'Alice Smith', '2026-01-01');")
    cur.execute("INSERT INTO users VALUES (2, 'bob', 'Bob Jones', '2026-01-02');")
    cur.execute("INSERT INTO products VALUES ('SKU-100', 4999, 15);")
    conn.commit()
    conn.close()
    return str(db_file)


@pytest.fixture
def dirty_db(tmp_path):
    """Creates a database containing unmasked PII, credentials, and secrets."""
    db_file = tmp_path / "dirty.sqlite"
    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE customers (
            id INTEGER PRIMARY KEY,
            name TEXT,
            card_number TEXT,
            ssn TEXT,
            password TEXT
        );
    """)
    cur.execute("""
        CREATE TABLE api_keys (
            id INTEGER PRIMARY KEY,
            service TEXT,
            secret TEXT
        );
    """)
    # Valid Visa card (passes Luhn): 4532-0150-1234-5671
    cur.execute(
        "INSERT INTO customers VALUES (1, 'Eve Hacker', '4532-0150-1234-5671', '123-45-6789', 'admin123');"
    )
    # AWS Key in secret
    cur.execute(
        "INSERT INTO api_keys VALUES (1, 'cloud', 'AKIAIOSFODNN7EXAMPLE');"
    )
    conn.commit()
    conn.close()
    return str(db_file)


def test_luhn_checksum_algorithm():
    # Valid card numbers
    assert PIIScanner.luhn_checksum("4532-0150-1234-5671") is True
    assert PIIScanner.luhn_checksum("4532015012345671") is True
    # Invalid check digit
    assert PIIScanner.luhn_checksum("4532-0150-1234-5672") is False
    # Short length
    assert PIIScanner.luhn_checksum("123456") is False


def test_is_valid_ssn_rules():
    assert PIIScanner.is_valid_ssn("123-45-6789") is True
    # Area 000
    assert PIIScanner.is_valid_ssn("000-45-6789") is False
    # Area 666
    assert PIIScanner.is_valid_ssn("666-45-6789") is False
    # Area 900-999
    assert PIIScanner.is_valid_ssn("950-45-6789") is False
    # Group 00
    assert PIIScanner.is_valid_ssn("123-00-6789") is False
    # Serial 0000
    assert PIIScanner.is_valid_ssn("123-45-0000") is False


def test_scan_cell_credit_card():
    engine = SQLiteRestoreEngine(":memory:")
    scanner = PIIScanner(engine)

    finding = scanner.scan_cell("Customer card: 4532-0150-1234-5671 on file", "notes")
    assert finding is not None
    ftype, sev, redacted, desc = finding
    assert ftype == "credit_card"
    assert sev == "CRITICAL"
    assert redacted.endswith("5671")

    # Number that fails Luhn should not trigger
    no_finding = scanner.scan_cell("Random order 4532-0150-1234-5672 item", "notes")
    assert no_finding is None


def test_scan_cell_ssn():
    engine = SQLiteRestoreEngine(":memory:")
    scanner = PIIScanner(engine)

    finding = scanner.scan_cell("Tax ID: 123-45-6789", "tax_number")
    assert finding is not None
    ftype, sev, redacted, desc = finding
    assert ftype == "ssn"
    assert sev == "CRITICAL"
    assert redacted == "***-**-6789"


def test_scan_cell_credentials():
    engine = SQLiteRestoreEngine(":memory:")
    scanner = PIIScanner(engine)

    # AWS Access Key
    finding = scanner.scan_cell("AKIAIOSFODNN7EXAMPLE", "config_val")
    assert finding is not None
    assert finding[0] == "aws_access_key"

    # Private key
    finding_pk = scanner.scan_cell("-----BEGIN RSA PRIVATE KEY-----\nMIIE...", "key_data")
    assert finding_pk is not None
    assert finding_pk[0] == "private_key"


def test_scan_cell_plaintext_password():
    engine = SQLiteRestoreEngine(":memory:")
    scanner = PIIScanner(engine)

    # Plaintext password in password column
    finding = scanner.scan_cell("mySecretPassword1!", "password")
    assert finding is not None
    assert finding[0] == "plaintext_password"
    assert finding[1] == "HIGH"

    # Properly hashed password (bcrypt)
    hashed_bcrypt = "$2a$12$e8k8gR2/4V.YQx0b0eN8ue1m8uB9X2O4A8d8yP6Q7R8S9T0U1V2W3"
    assert scanner.scan_cell(hashed_bcrypt, "password") is None

    # Properly hashed password (sha256 hex)
    hex_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    assert scanner.scan_cell(hex_hash, "password") is None

    # Redacted value
    assert scanner.scan_cell("[REDACTED]", "password") is None


def test_scanner_on_clean_db(clean_db, tmp_path):
    sandbox_db = tmp_path / "clean_sandbox.db"
    engine = SQLiteRestoreEngine(str(sandbox_db))
    engine.setup_ephemeral_db()
    try:
        engine.restore_dump(clean_db)
        scanner = PIIScanner(engine)
        findings = scanner.scan_all_tables()
        assert len(findings) == 0

        assertions = scanner.evaluate_assertions()
        assert len(assertions) == 1
        assert assertions[0].rule_name == "soc2_cc6_1_pii_sanitization"
        assert assertions[0].passed is True
        assert assertions[0].actual_value == "0 leaks detected"
    finally:
        engine.teardown()


def test_scanner_on_dirty_db(dirty_db, tmp_path):
    sandbox_db = tmp_path / "dirty_sandbox.db"
    engine = SQLiteRestoreEngine(str(sandbox_db))
    engine.setup_ephemeral_db()
    try:
        engine.restore_dump(dirty_db)
        scanner = PIIScanner(engine)
        findings = scanner.scan_all_tables()
        assert len(findings) >= 3  # CC, SSN, password, AWS key

        types = {f.finding_type for f in findings}
        assert "credit_card" in types
        assert "ssn" in types
        assert "plaintext_password" in types
        assert "aws_access_key" in types

        assertions = scanner.evaluate_assertions()
        assert len(assertions) >= 4
        # Top-level SOC2 CC6.1 assertion failed
        soc2_rule = next(a for a in assertions if a.rule_name == "soc2_cc6_1_pii_sanitization")
        assert soc2_rule.passed is False
        assert soc2_rule.critical is True
    finally:
        engine.teardown()


def test_drillrunner_integration_with_pii_scan(clean_db, dirty_db):
    runner = DrillRunner()

    # Clean DB with scan_pii enabled
    clean_cfg = VerificationConfig(
        database_type="sqlite",
        backup_path=clean_db,
        scan_pii=True,
    )
    summary, assertions, _ = runner.run_drill(clean_cfg)
    assert summary.overall_status == "PASSED"
    pii_assertion = next((a for a in assertions if a.rule_name == "soc2_cc6_1_pii_sanitization"), None)
    assert pii_assertion is not None
    assert pii_assertion.passed is True

    # Dirty DB with scan_pii enabled
    dirty_cfg = VerificationConfig(
        database_type="sqlite",
        backup_path=dirty_db,
        scan_pii=True,
    )
    summary_dirty, assertions_dirty, _ = runner.run_drill(dirty_cfg)
    assert summary_dirty.overall_status == "FAILED"
    pii_assertion_dirty = next((a for a in assertions_dirty if a.rule_name == "soc2_cc6_1_pii_sanitization"), None)
    assert pii_assertion_dirty is not None
    assert pii_assertion_dirty.passed is False


def test_cli_scan_pii_command(clean_db, dirty_db, capsys):
    # Test clean DB terminal report
    ret_clean = main(["scan-pii", "--backup", clean_db])
    assert ret_clean == 0
    captured = capsys.readouterr()
    assert "STATUS: CLEAN / SANITIZED" in captured.out

    # Test dirty DB terminal report
    ret_dirty = main(["scan-pii", "--backup", dirty_db])
    assert ret_dirty == 1
    captured_dirty = capsys.readouterr()
    assert "STATUS: LEAKS DETECTED" in captured_dirty.out
    assert "CRITICAL" in captured_dirty.out

    # Test JSON output
    ret_json = main(["scan-pii", "--backup", dirty_db, "--json"])
    assert ret_json == 1
    captured_json = capsys.readouterr()
    data = json.loads(captured_json.out)
    assert data["clean"] is False
    assert data["findings_count"] >= 3
    assert len(data["findings"]) >= 3
