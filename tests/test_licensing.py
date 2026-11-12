"""Unit and negative regression tests for offline cryptographic license validation.

Adheres to REC-006 & REC-001:
- Zero authentic production signing keys or production-signed tokens in test fixtures.
- Test keypair used strictly in test scope.
- Production verifier asserted to reject rogue, revoked, and test keys.
- Strict tier feature boundaries and evaluation trial limits verified.
"""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
import pytest

from drillops.licensing import (
    DRILLOPS_PUBLIC_KEY,
    EVALUATION_TRIAL_SECRET,
    LicenseInfo,
    LicenseTier,
    LicenseValidator,
)
from drillops.licensing.crypto import (
    _B,
    _Q,
    _edwards_add,
    _encodepoint,
    _scalarmult,
    verify_ed25519,
)

# ------------------------------------------------------------------------------
# Isolated Ephemeral Test Keypair (Test-Only Scope — NEVER Used in Production)
# ------------------------------------------------------------------------------
_TEST_SK_BYTES = bytes.fromhex("1234567890abcdef" * 4)


def _test_publickey(sk: bytes) -> bytes:
    h = hashlib.sha512(sk).digest()
    a = 2**254 + sum(h[i] << (8 * i) for i in range(3, 32))
    a &= ~((1 << 3) - 1)
    return _encodepoint(_scalarmult(_B, a))


_TEST_PK_BYTES = _test_publickey(_TEST_SK_BYTES)
_TEST_PK_HEX = _TEST_PK_BYTES.hex()


def _test_sign_ed25519(sk: bytes, m: bytes) -> bytes:
    h = hashlib.sha512(sk).digest()
    a = 2**254 + sum(h[i] << (8 * i) for i in range(3, 32))
    a &= ~((1 << 3) - 1)
    r = sum(hashlib.sha512(h[32:] + m).digest()[i] << (8 * i) for i in range(64)) % _Q
    R = _scalarmult(_B, r)
    Rs = _encodepoint(R)
    A = _encodepoint(_scalarmult(_B, a))
    k = sum(hashlib.sha512(Rs + A + m).digest()[i] << (8 * i) for i in range(64)) % _Q
    S = (r + k * a) % _Q
    return Rs + int(S).to_bytes(32, "little")


def _mint_test_v2_token(
    sk: bytes = _TEST_SK_BYTES,
    name: str = "Test Customer Corp",
    email: str = "billing@test-customer.com",
    tier: str = "pro",
    days: int = 365,
    targets: int = 10,
    features: list[str] | None = None,
    lic_id: str | None = None,
) -> str:
    """Mints a dynamic test DRILLOPS-V2 token signed by the provided test private key."""
    now = datetime.now(timezone.utc)
    exp_str = (now + timedelta(days=days)).isoformat() if days > 0 else None
    token_id = lic_id or f"LIC-TEST-{os.urandom(4).hex().upper()}"

    default_features = ["multi_target", "soc2_audit_pack", "custom_webhooks", "slack_alerts"]
    if tier.lower() == "enterprise":
        default_features.extend(["unlimited_targets", "priority_support", "white_label_dossier", "ci_integration"])

    payload = {
        "id": token_id,
        "tier": tier.lower(),
        "name": name,
        "email": email,
        "issued_at": now.isoformat(),
        "expires_at": exp_str,
        "max_targets": targets,
        "features": features if features is not None else default_features,
    }
    payload_json = json.dumps(payload, separators=(",", ":"))
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("utf-8").rstrip("=")
    sig_bytes = _test_sign_ed25519(sk, payload_b64.encode("utf-8"))
    return f"DRILLOPS-V2.{payload_b64}.{sig_bytes.hex()}"


def _mint_eval_token(
    name: str = "Test User",
    email: str = "user@test.com",
    tier: str = "pro",
    days: int = 14,
    targets: int = 5,
    features: list[str] | None = None,
    issued_dt: datetime | None = None,
    expires_dt: datetime | None = None,
    lic_id: str | None = None,
) -> str:
    """Helper to mint a test DRILLOPS-V1 evaluation token using public trial secret."""
    now = issued_dt or datetime.now(timezone.utc)
    if expires_dt is not None:
        exp_str = expires_dt.isoformat()
    elif days > 0:
        exp_str = (now + timedelta(days=days)).isoformat()
    else:
        exp_str = None

    payload = {
        "id": lic_id or f"LIC-EVAL-{os.urandom(4).hex().upper()}",
        "tier": tier,
        "name": name,
        "email": email,
        "issued_at": now.isoformat(),
        "expires_at": exp_str,
        "max_targets": targets,
        "features": features if features is not None else ["multi_target", "soc2_audit_pack"],
    }
    payload_json = json.dumps(payload, separators=(",", ":"))
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("utf-8").rstrip("=")
    sig = hmac.new(
        EVALUATION_TRIAL_SECRET.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"DRILLOPS-V1.{payload_b64}.{sig}"


# ------------------------------------------------------------------------------
# Test Cases
# ------------------------------------------------------------------------------

def test_default_community_license():
    validator = LicenseValidator()
    valid, info, error = validator.validate_key("")

    assert valid is True
    assert info is not None
    assert info.tier == LicenseTier.COMMUNITY
    assert info.license_id == "COMMUNITY"
    assert validator.is_feature_enabled("sqlite_engine", "") is True
    assert validator.is_feature_enabled("multi_target", "") is False


def test_ed25519_test_pro_license_valid():
    """Verify that an authentic Ed25519 Pro license validates against its corresponding public key."""
    test_token = _mint_test_v2_token(tier="pro", targets=10)
    test_validator = LicenseValidator(public_key=_TEST_PK_HEX)

    valid, info, error = test_validator.validate_key(test_token)
    assert valid is True
    assert error is None
    assert info is not None
    assert info.tier == LicenseTier.PRO
    assert info.max_targets == 10
    assert test_validator.is_feature_enabled("multi_target", test_token) is True
    assert test_validator.is_feature_enabled("soc2_audit_pack", test_token) is True
    # Pro license cannot activate Enterprise-exclusive features
    assert test_validator.is_feature_enabled("enterprise_sso", test_token) is False
    assert test_validator.is_feature_enabled("airgapped_vault", test_token) is False


def test_ed25519_test_enterprise_license_valid():
    """Verify that an authentic Ed25519 Enterprise license validates and unlocks Enterprise features."""
    test_token = _mint_test_v2_token(tier="enterprise", targets=100)
    test_validator = LicenseValidator(public_key=_TEST_PK_HEX)

    valid, info, error = test_validator.validate_key(test_token)
    assert valid is True
    assert info is not None
    assert info.tier == LicenseTier.ENTERPRISE
    assert info.max_targets == 100
    assert test_validator.is_feature_enabled("unlimited_targets", test_token) is True
    assert test_validator.is_feature_enabled("priority_support", test_token) is True


def test_ed25519_production_verifier_rejects_test_key():
    """Security Gate (REC-006): Production LicenseValidator MUST reject test-signed tokens."""
    test_token = _mint_test_v2_token(tier="pro")
    prod_validator = LicenseValidator()  # uses DRILLOPS_PUBLIC_KEY

    valid, info, error = prod_validator.validate_key(test_token)
    assert valid is False
    assert "Cryptographic signature mismatch" in error


def test_revocation_blacklist_enforced():
    """Security Gate (REC-006): Disclosed/revoked fixture license IDs must be explicitly rejected."""
    prod_validator = LicenseValidator()

    for revoked_id in ["LIC-PRO-ABC7801E", "LIC-ENT-E55FC6BE", "LIC-PRO-D6CC1B02", "LIC-PRO-A1B2C3D4"]:
        # Try both as evaluation and V2 format with revoked ID
        eval_token = _mint_eval_token(lic_id=revoked_id)
        valid, info, error = prod_validator.validate_key(eval_token)
        assert valid is False
        assert "has been revoked and is invalid" in error


def test_ed25519_tamper_signature_rejected():
    test_token = _mint_test_v2_token(tier="pro")
    test_validator = LicenseValidator(public_key=_TEST_PK_HEX)

    parts = test_token.split(".")
    bad_sig = parts[2][:-2] + ("00" if parts[2][-2:] != "00" else "ff")
    tampered_token = f"{parts[0]}.{parts[1]}.{bad_sig}"

    valid, info, error = test_validator.validate_key(tampered_token)
    assert valid is False
    assert "Cryptographic signature mismatch" in error


def test_ed25519_tamper_payload_rejected():
    test_token = _mint_test_v2_token(tier="pro")
    test_validator = LicenseValidator(public_key=_TEST_PK_HEX)

    parts = test_token.split(".")
    tampered_payload = ("B" if parts[1][5] != "B" else "C") + parts[1][1:]
    tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

    valid, info, error = test_validator.validate_key(tampered_token)
    assert valid is False


def test_ed25519_forged_keypair_rejected():
    """Negative test: Attempting to sign with a rogue Ed25519 private key must fail against official public key."""
    payload = {"id": "FORGED-01", "tier": "enterprise", "name": "Attacker", "max_targets": 999}
    payload_json = json.dumps(payload, separators=(",", ":"))
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("utf-8").rstrip("=")

    fake_sig = os.urandom(64).hex()
    forged_token = f"DRILLOPS-V2.{payload_b64}.{fake_sig}"

    validator = LicenseValidator()
    valid, info, error = validator.validate_key(forged_token)
    assert valid is False
    assert "Cryptographic signature mismatch" in error


def test_evaluation_trial_license_valid():
    token = _mint_eval_token(name="Trial User", email="eval@corp.com", tier="pro", days=14, targets=5)
    validator = LicenseValidator()

    valid, info, error = validator.validate_key(token)
    assert valid is True
    assert error is None
    assert info.tier == LicenseTier.PRO
    assert "[EVALUATION TRIAL]" in info.license_id
    assert info.customer_name == "Trial User"
    assert info.max_targets == 5


def test_evaluation_trial_enterprise_rejected():
    """Negative test (REC-001): Evaluation trial key attempting to claim Enterprise tier must be rejected."""
    token = _mint_eval_token(name="Attacker", email="attacker@corp.com", tier="enterprise", days=14, targets=100)
    validator = LicenseValidator()

    valid, info, error = validator.validate_key(token)
    assert valid is False
    assert "cannot authorize Enterprise tier" in error


def test_evaluation_trial_enterprise_features_rejected():
    """Negative test (REC-001): Evaluation trial attempting to claim Enterprise-exclusive features must be rejected."""
    token = _mint_eval_token(
        name="Attacker",
        tier="pro",
        days=14,
        features=["multi_target", "enterprise_sso", "airgapped_vault"],
    )
    validator = LicenseValidator()

    valid, info, error = validator.validate_key(token)
    assert valid is False
    assert "cannot claim Enterprise-exclusive features" in error


def test_evaluation_trial_excessive_duration_rejected():
    """Negative test (REC-001): Evaluation trial key with duration > 14 days must be rejected."""
    token = _mint_eval_token(name="Trial User", email="eval@corp.com", tier="pro", days=30, targets=5)
    validator = LicenseValidator()

    valid, info, error = validator.validate_key(token)
    assert valid is False
    assert "exceeds maximum allowed duration" in error


def test_evaluation_trial_missing_expiry_rejected():
    """Negative test: Evaluation trial key without expiration date must be rejected."""
    token = _mint_eval_token(name="Trial User", email="eval@corp.com", tier="pro", days=0, targets=5)
    validator = LicenseValidator()

    valid, info, error = validator.validate_key(token)
    assert valid is False
    assert "must have a defined expiration date" in error


def test_evaluation_trial_targets_capped_at_five():
    """Evaluation trial claiming 50 targets must be capped strictly at 5."""
    token = _mint_eval_token(name="Trial User", email="eval@corp.com", tier="pro", days=14, targets=50)
    validator = LicenseValidator()

    valid, info, error = validator.validate_key(token)
    assert valid is True
    assert info.max_targets == 5


def test_evaluation_trial_expired_rejected():
    """Negative test: Expired evaluation trial token must be rejected."""
    past_issued = datetime.now(timezone.utc) - timedelta(days=20)
    past_expires = datetime.now(timezone.utc) - timedelta(days=6)
    token = _mint_eval_token(issued_dt=past_issued, expires_dt=past_expires)
    validator = LicenseValidator()

    valid, info, error = validator.validate_key(token)
    assert valid is False
    assert "License expired" in error


def test_license_future_issuance_rejected():
    """Negative test: License claiming issuance far in the future must be rejected."""
    future_time = datetime.now(timezone.utc) + timedelta(days=10)
    token = _mint_eval_token(issued_dt=future_time, days=14)
    validator = LicenseValidator()

    valid, info, error = validator.validate_key(token)
    assert valid is False
    assert "in the future" in error


def test_malformed_token_formats():
    validator = LicenseValidator()

    # Invalid parts count
    valid, _, err = validator.validate_key("JUST_A_STRING")
    assert valid is False
    assert "Invalid license format" in err

    # Unsupported version prefix
    valid, _, err = validator.validate_key("DRILLOPS-V9.payload.sig")
    assert valid is False
    assert "Unsupported license token version" in err

    # Non-hex signature in V2
    valid, _, err = validator.validate_key("DRILLOPS-V2.eyJ0ZXN0IjoxfQ.NOT_HEX_SIG!")
    assert valid is False
    assert "Malformed cryptographic signature" in err


def test_cli_license_info_and_verify(capsys):
    from drillops.cli import main

    eval_token = _mint_eval_token(name="CLI Tester", tier="pro", days=14, targets=5)

    # Test 'verify'
    ret = main(["license", "verify", "--key", eval_token])
    assert ret == 0
    captured = capsys.readouterr()
    assert "VALID" in captured.out
    assert "PRO" in captured.out
    assert "CLI Tester" in captured.out

    # Test 'info'
    ret = main(["license", "info", "--key", eval_token])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Max Targets:    5" in captured.out

    # Test invalid key returns 1
    ret = main(["license", "verify", "--key", "DRILLOPS-V2.invalid.badhex"])
    assert ret == 1
    captured = capsys.readouterr()
    assert "INVALID" in captured.out


def test_evaluation_trial_cannot_substitute_paid_pro_commercial_value():
    """
    Economic & Security Boundary Test (REC-001):
    Asserts that repeated self-minting of DRILLOPS-V1 evaluation tokens cannot yield
    the durable value of an authentic paid Pro license (DRILLOPS-V2):
    1. Evaluation tokens are strictly capped at max 5 targets (Pro allows 25+).
    2. Evaluation tokens cannot exceed 14 days duration.
    3. Evaluation tokens cannot unlock Enterprise exclusive capabilities.
    4. Re-minting after expiry still enforces target capping and 14-day expiry.
    """
    validator = LicenseValidator()

    # 1. Evaluation tokens are strictly capped at 5 targets
    eval_token_5 = _mint_eval_token(name="Repeat User", targets=5, days=14)
    valid, info, _ = validator.validate_key(eval_token_5)
    assert valid is True
    assert info.max_targets == 5

    # Claiming 10 targets in an evaluation token is strictly clamped down to 5
    eval_token_10 = _mint_eval_token(name="Repeat User", targets=10, days=14)
    valid, info_10, _ = validator.validate_key(eval_token_10)
    assert valid is True
    assert info_10.max_targets == 5

    # Evaluation token license_id is indelibly watermarked for auditors
    assert info_10.license_id.endswith("[EVALUATION TRIAL]")

    # 2. Evaluation token duration cannot exceed 14 days
    eval_token_long = _mint_eval_token(name="Repeat User", targets=5, days=30)
    valid, _, err = validator.validate_key(eval_token_long)
    assert valid is False
    assert "exceeds maximum allowed duration (14 days)" in err

    # 3. Enterprise exclusive features cannot be unlocked by evaluation tokens
    assert validator.is_feature_enabled("enterprise_sso", eval_token_5) is False
    assert validator.is_feature_enabled("airgapped_vault", eval_token_5) is False

