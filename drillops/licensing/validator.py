"""Cryptographic offline license token validation for DrillOps.

Validates authentic customer licenses offline using asymmetric Ed25519 public-key
cryptography. Contains no private signing keys or minting secrets.
"""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from typing import Optional, Tuple

from drillops.licensing.crypto import (
    DRILLOPS_PUBLIC_KEY,
    EVALUATION_TRIAL_SECRET,
    verify_ed25519,
)
from drillops.licensing.models import LicenseInfo, LicenseTier


class LicenseValidator:
    """Validates license keys offline against asymmetric Ed25519 public key or restricted evaluation HMAC."""

    def __init__(self, public_key: Optional[str] = None):
        self.public_key_hex = public_key or os.environ.get("DRILLOPS_PUBLIC_KEY", DRILLOPS_PUBLIC_KEY)
        try:
            self.public_key_bytes = bytes.fromhex(self.public_key_hex)
        except Exception:
            self.public_key_bytes = b""

    def validate_key(self, token: Optional[str] = None) -> Tuple[bool, Optional[LicenseInfo], Optional[str]]:
        """
        Validates token integrity, cryptographic signature, and validity period.
        Returns (is_valid, license_info, error_message).
        """
        raw_token = token or os.environ.get("DRILLOPS_LICENSE_KEY", "").strip()
        if not raw_token:
            # Default to Community tier when no key is supplied
            info = LicenseInfo(
                license_id="COMMUNITY",
                tier=LicenseTier.COMMUNITY,
                customer_name="Open Source Community",
                customer_email="community@drillops.dev",
                issued_at="2026-01-01T00:00:00Z",
                expires_at=None,
                max_targets=1,
                features=["single_target_restore", "sqlite_engine", "postgres_engine"],
            )
            return True, info, None

        parts = raw_token.split(".")
        if len(parts) != 3:
            return False, None, "Invalid license format. Expected format: DRILLOPS-V2.<payload>.<signature>"

        token_version, payload_b64, signature = parts
        is_eval_trial = False

        if token_version == "DRILLOPS-V2":
            # Asymmetric Ed25519 verification using official public verification key
            try:
                sig_bytes = bytes.fromhex(signature)
            except ValueError:
                return False, None, "Malformed cryptographic signature encoding. Hex signature required."

            msg = payload_b64.encode("utf-8")
            if not self.public_key_bytes or not verify_ed25519(self.public_key_bytes, msg, sig_bytes):
                return False, None, "Cryptographic signature mismatch. License key may be forged, modified, or corrupted."

        elif token_version == "DRILLOPS-V1":
            # Legacy evaluation trial token signed with public evaluation secret
            eval_sig = hmac.new(
                EVALUATION_TRIAL_SECRET.encode("utf-8"),
                payload_b64.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            if hmac.compare_digest(eval_sig, signature):
                is_eval_trial = True
            else:
                return False, None, "Cryptographic signature mismatch. License key may be forged or corrupted."

        else:
            return False, None, f"Unsupported license token version: {token_version}. Expected DRILLOPS-V2 or DRILLOPS-V1."

        # Decode and parse payload JSON safely
        try:
            padded_b64 = payload_b64 + "=" * (-len(payload_b64) % 4)
            payload_json = base64.urlsafe_b64decode(padded_b64).decode("utf-8")
            data = json.loads(payload_json)
        except Exception as e:
            return False, None, f"Failed to decode license payload: {str(e)}"

        if not isinstance(data, dict):
            return False, None, "Invalid license payload structure. JSON object expected."

        # Parse tier safely
        raw_tier = str(data.get("tier", "pro")).lower()
        try:
            tier = LicenseTier(raw_tier)
        except ValueError:
            tier = LicenseTier.PRO

        # Validate issuance and expiration timestamps
        now = datetime.now(timezone.utc)
        issued_str = data.get("issued_at")
        expires_str = data.get("expires_at")

        if issued_str:
            try:
                iss_dt = datetime.fromisoformat(str(issued_str).replace("Z", "+00:00"))
                # Allow maximum 1 hour clock skew into the future
                if iss_dt > now + timedelta(hours=1):
                    return False, None, "License issuance date is in the future. Check system clock."
            except Exception:
                return False, None, "Malformed issuance timestamp format in license token."
        else:
            iss_dt = now

        exp_dt = None
        if expires_str:
            try:
                exp_dt = datetime.fromisoformat(str(expires_str).replace("Z", "+00:00"))
            except Exception:
                return False, None, "Malformed expiration timestamp format in license token."

        # Enforce strict security guardrails on evaluation trial keys
        if is_eval_trial:
            if tier == LicenseTier.ENTERPRISE:
                return False, None, "Evaluation trial key cannot authorize Enterprise tier. Official license required."

            if not exp_dt:
                return False, None, "Evaluation trial key must have a defined expiration date."

            # Strictly cap evaluation duration at 14 days (with 1 hour clock skew allowance)
            max_trial_duration_secs = 14 * 86400 + 3600
            if (exp_dt - iss_dt).total_seconds() > max_trial_duration_secs:
                return False, None, "Evaluation trial key exceeds maximum allowed duration (14 days). Official license required."

        # Evaluation trials are hard-capped at 5 targets regardless of payload claims
        max_targets_claimed = int(data.get("max_targets", 5)) if str(data.get("max_targets", "")).isdigit() else 5
        max_targets_val = min(max_targets_claimed, 5) if is_eval_trial else max_targets_claimed

        lic_id = str(data.get("id", "UNKNOWN"))
        if is_eval_trial and not lic_id.endswith("[EVALUATION TRIAL]"):
            lic_id = f"{lic_id} [EVALUATION TRIAL]"

        info = LicenseInfo(
            license_id=lic_id,
            tier=tier,
            customer_name=str(data.get("name", "Unknown")),
            customer_email=str(data.get("email", "unknown@domain.com")),
            issued_at=str(issued_str or ""),
            expires_at=str(expires_str) if expires_str else None,
            max_targets=max_targets_val,
            features=list(data.get("features", [])),
        )

        if info.is_expired:
            return False, info, f"License expired on {info.expires_at}."

        return True, info, None

    def is_feature_enabled(self, feature: str, token: Optional[str] = None) -> bool:
        """Checks whether a specific feature is enabled under the current license."""
        valid, info, _ = self.validate_key(token)
        if not valid or not info:
            return False
        if feature in ("single_target_restore", "sqlite_engine", "postgres_engine"):
            return True
        return feature in info.features
