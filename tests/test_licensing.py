"""Unit and negative regression tests for offline cryptographic license validation."""

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


def _mint_eval_token(
    name: str = "Test User",
    email: str = "user@test.com",
    tier: str = "pro",
    days: int = 14,
    targets: int = 5,
    features: list[str] | None = None,
    issued_dt: datetime | None = None,
    expires_dt: datetime | None = None,
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
        "id": f"LIC-EVAL-{os.urandom(4).hex().upper()}",
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


# Pre-minted authentic DRILLOPS-V2 Pro & Enterprise licenses signed by official DrillOps issuer key
OFFICIAL_PRO_TOKEN = (
    "DRILLOPS-V2.eyJpZCI6IkxJQy1QUk8tQUJDNzgwMUUiLCJ0aWVyIjoicHJvIiwibmFtZSI6IkFjbWUgQ29ycC"
    "IsImVtYWlsIjoiYWRtaW5AYWNtZS5jb20iLCJpc3N1ZWRfYXQiOiIyMDI2LTEwLTI5VDAwOjA3OjE3LjM4NTg1OC"
    "swMDowMCIsImV4cGlyZXNfYXQiOiIyMDI3LTEwLTI5VDAwOjA3OjE3LjM4NTg1OCswMDowMCIsIm1heF90YXJnZX"
    "RzIjoxMCwiZmVhdHVyZXMiOlsibXVsdGlfdGFyZ2V0Iiwic29jMl9hdWRpdF9wYWNrIiwiY3VzdG9tX3dlYmhvb2"
    "tzIiwic2xhY2tfYWxlcnRzIl19.ea200f113cf4fa19a5491d5cdd69f251cd9d3175abfbc07829dbfa07c563"
    "83c2fdc2a1ad1003ff9844e2aa6da8a40f272607b3d1ef296907f6a273e816c34208"
)

OFFICIAL_ENTERPRISE_TOKEN = (
    "DRILLOPS-V2.eyJpZCI6IkxJQy1FTlQtRTU1RkM2QkUiLCJ0aWVyIjoiZW50ZXJwcmlzZSIsIm5hbWUiOiJHbG9i"
    "YWwgQmFuayIsImVtYWlsIjoiY2lzb0BnbG9iYWxiYW5rLmNvbSIsImlzc3VlZF9hdCI6IjIwMjYtMTAtMjlUMDA6"
    "MDc6MzAuMzM3MjQxKzAwOjAwIiwiZXhwaXJlc19hdCI6IjIwMjctMTAtMjlUMDA6MDc6MzAuMzM3MjQxKzAwOjAw"
    "IiwibWF4X3RhcmdldHMiOjEwMCwiZmVhdHVyZXMiOlsibXVsdGlfdGFyZ2V0Iiwic29jMl9hdWRpdF9wYWNrIiwi"
    "Y3VzdG9tX3dlYmhvb2tzIiwic2xhY2tfYWxlcnRzIiwidW5saW1pdGVkX3RhcmdldHMiLCJwcmlvcml0eV9zdXBw"
    "b3J0Iiwid2hpdGVfbGFiZWxfZG9zc2llciIsImNpX2ludGVncmF0aW9uIl19.d87e19c32499d626b86e4ad056"
    "2a883a84d68ead41ade710de666646aa5b9e3ab459e16ad75c8f65c7da560167dd5c6a81bceffef2d9c116"
    "183c68798006be09"
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


def test_ed25519_official_pro_license_valid():
    validator = LicenseValidator()
    valid, info, error = validator.validate_key(OFFICIAL_PRO_TOKEN)
    assert valid is True
    assert error is None
    assert info is not None
    assert info.tier == LicenseTier.PRO
    assert info.max_targets == 10
    assert validator.is_feature_enabled("multi_target", OFFICIAL_PRO_TOKEN) is True
    assert validator.is_feature_enabled("soc2_audit_pack", OFFICIAL_PRO_TOKEN) is True


def test_ed25519_official_enterprise_license_valid():
    validator = LicenseValidator()
    valid, info, error = validator.validate_key(OFFICIAL_ENTERPRISE_TOKEN)
    assert valid is True
    assert info.tier == LicenseTier.ENTERPRISE
    assert info.max_targets == 100
    assert validator.is_feature_enabled("unlimited_targets", OFFICIAL_ENTERPRISE_TOKEN) is True


def test_ed25519_tamper_signature_rejected():
    validator = LicenseValidator()
    parts = OFFICIAL_PRO_TOKEN.split(".")
    bad_sig = parts[2][:-2] + ("00" if parts[2][-2:] != "00" else "ff")
    tampered_token = f"{parts[0]}.{parts[1]}.{bad_sig}"

    valid, info, error = validator.validate_key(tampered_token)
    assert valid is False
    assert "Cryptographic signature mismatch" in error


def test_ed25519_tamper_payload_rejected():
    validator = LicenseValidator()
    parts = OFFICIAL_PRO_TOKEN.split(".")
    tampered_payload = ("B" if parts[1][5] != "B" else "C") + parts[1][1:]
    tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

    valid, info, error = validator.validate_key(tampered_token)
    assert valid is False


def test_ed25519_forged_keypair_rejected():
    """Negative test: Attempting to sign with a rogue Ed25519 private key must fail against official public key."""
    from drillops.licensing.crypto import verify_ed25519
    import os

    payload = {"id": "FORGED-01", "tier": "enterprise", "name": "Attacker", "max_targets": 999}
    payload_json = json.dumps(payload, separators=(",", ":"))
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("utf-8").rstrip("=")

    # Attacker tries to generate a fake signature (random 64 bytes)
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
    """Negative test: Evaluation trial key attempting to claim Enterprise tier must be rejected."""
    token = _mint_eval_token(name="Attacker", email="attacker@corp.com", tier="enterprise", days=14, targets=100)
    validator = LicenseValidator()

    valid, info, error = validator.validate_key(token)
    assert valid is False
    assert "cannot authorize Enterprise tier" in error


def test_evaluation_trial_excessive_duration_rejected():
    """Negative test: Evaluation trial key with duration > 14 days must be rejected."""
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
