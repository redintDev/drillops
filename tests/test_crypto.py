"""Unit and integration tests for encrypted backup verification and ephemeral decryption."""

import gzip
import os
import subprocess
import pytest

from drillops.certifier import CertificateGenerator
from drillops.core.runner import DrillRunner
from drillops.models import AssertionRule, VerificationConfig
from drillops.storage.archive import ArchiveProcessor


@pytest.fixture
def sample_sql(tmp_path):
    sql_file = tmp_path / "production_dump.sql"
    content = """
    CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, balance INTEGER);
    INSERT INTO customers (id, name, balance) VALUES (1, 'Acme Corp', 50000);
    INSERT INTO customers (id, name, balance) VALUES (2, 'Globex Inc', 120000);
    """
    sql_file.write_text(content.strip(), encoding="utf-8")
    return str(sql_file)


@pytest.fixture
def openssl_encrypted_sql(sample_sql, tmp_path):
    enc_path = tmp_path / "production_dump.sql.enc"
    cmd = [
        "openssl", "enc", "-aes-256-cbc", "-pbkdf2",
        "-in", sample_sql,
        "-out", str(enc_path),
        "-pass", "pass:SuperSecret123!",
    ]
    subprocess.run(cmd, check=True)
    return str(enc_path)


@pytest.fixture
def openssl_encrypted_gzipped_sql(sample_sql, tmp_path):
    gz_path = tmp_path / "production_dump.sql.gz"
    with open(sample_sql, "rb") as f_in, gzip.open(gz_path, "wb") as f_out:
        f_out.write(f_in.read())

    enc_gz_path = tmp_path / "production_dump.sql.gz.enc"
    cmd = [
        "openssl", "enc", "-aes-256-cbc", "-pbkdf2",
        "-in", str(gz_path),
        "-out", str(enc_gz_path),
        "-pass", "pass:SuperSecret123!",
    ]
    subprocess.run(cmd, check=True)
    return str(enc_gz_path)


def test_detect_encryption_unencrypted(sample_sql):
    assert ArchiveProcessor.detect_encryption(sample_sql) is None


def test_detect_encryption_openssl(openssl_encrypted_sql):
    detected = ArchiveProcessor.detect_encryption(openssl_encrypted_sql)
    assert detected == "openssl"


def test_detect_encryption_by_extension(tmp_path):
    p1 = tmp_path / "backup.dump.enc"
    p1.write_bytes(b"some bytes")
    assert ArchiveProcessor.detect_encryption(str(p1)) == "openssl"

    p2 = tmp_path / "backup.dump.gpg"
    p2.write_bytes(b"some bytes")
    assert ArchiveProcessor.detect_encryption(str(p2)) == "gpg"


def test_prepare_archive_missing_passphrase(openssl_encrypted_sql, tmp_path):
    work_dir = tmp_path / "work"
    work_dir.mkdir()

    with pytest.raises(ValueError, match="no decryption passphrase was provided"):
        ArchiveProcessor.prepare_archive(openssl_encrypted_sql, str(work_dir), decrypt_passphrase=None)


def test_prepare_archive_wrong_passphrase(openssl_encrypted_sql, tmp_path):
    work_dir = tmp_path / "work"
    work_dir.mkdir()

    # In CBC mode without AEAD, OpenSSL has a 1/256 random chance of a valid PKCS#7 padding byte.
    # We attempt wrong passwords to ensure OpenSSL raises RuntimeError on decryption failure.
    raised = False
    for attempt in range(5):
        try:
            ArchiveProcessor.prepare_archive(
                openssl_encrypted_sql,
                str(work_dir),
                decrypt_passphrase=f"definitely_wrong_passphrase_{attempt}",
            )
        except RuntimeError as e:
            if "OpenSSL decryption failed" in str(e):
                raised = True
                break
    assert raised, "Expected RuntimeError from OpenSSL decryption failure"



def test_openssl_decryption_pipeline(openssl_encrypted_sql, tmp_path):
    work_dir = tmp_path / "work"
    work_dir.mkdir()

    decrypted = ArchiveProcessor.prepare_archive(
        openssl_encrypted_sql,
        str(work_dir),
        decrypt_passphrase="SuperSecret123!",
    )
    assert os.path.isfile(decrypted)
    assert decrypted.endswith(".sql")
    content = open(decrypted, "r", encoding="utf-8").read()
    assert "CREATE TABLE customers" in content
    assert "Acme Corp" in content


def test_encrypted_gzipped_multi_stage_pipeline(openssl_encrypted_gzipped_sql, tmp_path):
    work_dir = tmp_path / "work"
    work_dir.mkdir()

    decrypted = ArchiveProcessor.prepare_archive(
        openssl_encrypted_gzipped_sql,
        str(work_dir),
        decrypt_passphrase="SuperSecret123!",
    )
    assert os.path.isfile(decrypted)
    assert decrypted.endswith(".sql")
    content = open(decrypted, "r", encoding="utf-8").read()
    assert "CREATE TABLE customers" in content
    assert "Globex Inc" in content


def test_full_drill_with_encrypted_backup(openssl_encrypted_sql, tmp_path):
    cert_dir = tmp_path / "certificates"
    cert_dir.mkdir()

    config = VerificationConfig(
        database_type="sqlite",
        backup_path=openssl_encrypted_sql,
        expected_tables=["customers"],
        assertion_rules=[
            AssertionRule(
                name="customer_count",
                query="SELECT count(*) FROM customers",
                operator=">=",
                expected_value=2,
            )
        ],
        decrypt_passphrase="SuperSecret123!",
    )

    runner = DrillRunner()
    summary, assertions, artifacts = runner.run_drill(config, output_dir=str(cert_dir))

    assert summary.overall_status == "PASSED"
    assert summary.encrypted_at_rest is True
    assert "openssl" in summary.encryption_type

    # Verify SOC2 CC6.1 assertion is automatically added
    cc6_assertions = [a for a in assertions if a.rule_name == "soc2_cc6_1_encryption_at_rest"]
    assert len(cc6_assertions) == 1
    assert cc6_assertions[0].passed is True
    assert "verified" in str(cc6_assertions[0].actual_value)

    # Verify certificate generation includes encryption provenance
    cert_json = CertificateGenerator.generate_json(summary, assertions)
    assert cert_json["target"]["encrypted_at_rest"] is True
    assert "openssl" in cert_json["target"]["encryption_type"]

    cert_md = CertificateGenerator.generate_markdown(summary, assertions)
    assert "Encryption at Rest (SOC2 CC6.1)" in cert_md
    assert "VERIFIED (openssl" in cert_md


def test_cli_verify_encrypted_backup(openssl_encrypted_sql, tmp_path):
    from drillops.cli import main
    cert_dir = tmp_path / "cli_certs"
    cert_dir.mkdir()

    cmd_args = [
        "verify",
        "--backup", openssl_encrypted_sql,
        "--type", "sqlite",
        "--tables", "customers",
        "--out", str(cert_dir),
        "--decrypt-passphrase", "SuperSecret123!",
    ]
    exit_code = main(cmd_args)
    assert exit_code == 0

    # Ensure certificate files were written
    json_certs = list(cert_dir.glob("drill_cert_*.json"))
    assert len(json_certs) == 1
    import json
    data = json.loads(json_certs[0].read_text(encoding="utf-8"))
    assert data["overall_status"] == "PASSED"
    assert data["target"]["encrypted_at_rest"] is True

