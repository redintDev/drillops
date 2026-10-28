"""Unit tests for offline cryptographic license generation and verification."""

import pytest

from drillops.licensing import (
    LicenseGenerator,
    LicenseTier,
    LicenseValidator,
)


def test_default_community_license():
    validator = LicenseValidator()
    valid, info, error = validator.validate_key("")

    assert valid is True
    assert info is not None
    assert info.tier == LicenseTier.COMMUNITY
    assert info.license_id == "COMMUNITY"
    assert validator.is_feature_enabled("sqlite_engine", "") is True
    assert validator.is_feature_enabled("multi_target", "") is False


def test_mint_and_validate_pro_license():
    secret = "test-secret-salt-12345"
    generator = LicenseGenerator(secret=secret)
    validator = LicenseValidator(secret=secret)

    token = generator.mint_license(
        customer_name="Acme Corp",
        customer_email="admin@acme.com",
        tier=LicenseTier.PRO,
        days_valid=30,
        max_targets=5,
    )

    assert token.startswith("DRILLOPS-V1.")

    valid, info, error = validator.validate_key(token)
    assert valid is True
    assert error is None
    assert info is not None
    assert info.tier == LicenseTier.PRO
    assert info.customer_name == "Acme Corp"
    assert info.customer_email == "admin@acme.com"
    assert info.max_targets == 5
    assert info.is_expired is False

    assert validator.is_feature_enabled("multi_target", token) is True
    assert validator.is_feature_enabled("soc2_audit_pack", token) is True


def test_mint_and_validate_enterprise_license():
    secret = "enterprise-secret"
    generator = LicenseGenerator(secret=secret)
    validator = LicenseValidator(secret=secret)

    token = generator.mint_license(
        customer_name="Global Enterprise Inc",
        customer_email="ciso@global.com",
        tier=LicenseTier.ENTERPRISE,
        days_valid=365,
        max_targets=-1,
    )

    valid, info, error = validator.validate_key(token)
    assert valid is True
    assert info.tier == LicenseTier.ENTERPRISE
    assert validator.is_feature_enabled("unlimited_targets", token) is True
    assert validator.is_feature_enabled("white_label_dossier", token) is True


def test_signature_tamper_detection():
    secret = "super-secret"
    generator = LicenseGenerator(secret=secret)
    validator = LicenseValidator(secret=secret)

    token = generator.mint_license("Hacker", "hacker@evil.com", LicenseTier.PRO)
    parts = token.split(".")

    # Tamper with signature
    tampered_sig = parts[2][:-4] + "dead"
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"

    valid, info, error = validator.validate_key(tampered_token)
    assert valid is False
    assert "Cryptographic signature mismatch" in error


def test_expired_license():
    secret = "super-secret"
    generator = LicenseGenerator(secret=secret)
    validator = LicenseValidator(secret=secret)

    # Negative days_valid to create an expired license
    token = generator.mint_license("Expired User", "old@acme.com", LicenseTier.PRO, days_valid=-5)

    valid, info, error = validator.validate_key(token)
    assert valid is False
    assert "License expired" in error


def test_cli_license_mint_and_info(tmp_path, capsys):
    from drillops.cli import main
    lic_file = tmp_path / "cli_test.key"

    # Mint license via CLI
    ret = main([
        "license", "mint",
        "--name", "Test Corp",
        "--email", "test@corp.com",
        "--tier", "enterprise",
        "--days", "90",
        "--out", str(lic_file),
    ])
    assert ret == 0
    assert lic_file.exists()
    token = lic_file.read_text().strip()
    assert token.startswith("DRILLOPS-V1.")

    # Inspect license via CLI
    ret = main(["license", "info", "--key", token])
    assert ret == 0
    captured = capsys.readouterr()
    assert "VALID" in captured.out
    assert "ENTERPRISE" in captured.out
    assert "Test Corp" in captured.out


def test_cli_license_mint_missing_args(capsys):
    from drillops.cli import main
    ret = main(["license", "mint", "--tier", "pro"])
    assert ret == 1
    captured = capsys.readouterr()
    assert "Error: --name and --email are required" in captured.out


def test_public_evaluation_trial_license_valid():
    from drillops.licensing.validator import EVALUATION_TRIAL_SECRET
    generator = LicenseGenerator(secret=EVALUATION_TRIAL_SECRET)
    validator = LicenseValidator()  # uses default verification secret, should recognize eval key

    token = generator.mint_license(
        customer_name="Trial Tester",
        customer_email="eval@test.com",
        tier=LicenseTier.PRO,
        days_valid=14,
        max_targets=5,
    )

    valid, info, error = validator.validate_key(token)
    assert valid is True
    assert error is None
    assert info.tier == LicenseTier.PRO
    assert "[EVALUATION TRIAL]" in info.license_id
    assert info.customer_name == "Trial Tester"


def test_public_evaluation_trial_enterprise_rejected():
    from drillops.licensing.validator import EVALUATION_TRIAL_SECRET
    generator = LicenseGenerator(secret=EVALUATION_TRIAL_SECRET)
    validator = LicenseValidator()

    # Attempting to mint an Enterprise key with the public trial secret must be rejected
    token = generator.mint_license(
        customer_name="Adversary Corp",
        customer_email="attacker@test.com",
        tier=LicenseTier.ENTERPRISE,
        days_valid=14,
        max_targets=100,
    )

    valid, info, error = validator.validate_key(token)
    assert valid is False
    assert "cannot authorize Enterprise tier" in error


def test_public_evaluation_trial_excessive_duration_rejected():
    from drillops.licensing.validator import EVALUATION_TRIAL_SECRET
    generator = LicenseGenerator(secret=EVALUATION_TRIAL_SECRET)
    validator = LicenseValidator()

    # Attempting to mint a 1-year key with the public trial secret must be rejected
    token = generator.mint_license(
        customer_name="Trial Tester",
        customer_email="eval@test.com",
        tier=LicenseTier.PRO,
        days_valid=365,
        max_targets=5,
    )

    valid, info, error = validator.validate_key(token)
    assert valid is False
    assert "exceeds maximum allowed duration" in error


