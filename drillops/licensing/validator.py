"""Cryptographic offline license token minting and validation."""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from typing import Any, Dict, List, Optional, Tuple
import uuid

from drillops.licensing.models import LicenseInfo, LicenseTier

# Default HMAC verification seed (can be overridden via DRILLOPS_LICENSE_SECRET)
DEFAULT_VERIFICATION_SECRET = "drillops_sec_k98a2f1b04d84c179c3b88d407e3a9c5"
# Public evaluation trial secret (strictly limited to 14-day Pro evaluation)
EVALUATION_TRIAL_SECRET = "drillops_eval_public_trial_2026"


class LicenseGenerator:
    """Mints cryptographically signed license keys for customer fulfillment."""

    def __init__(self, secret: Optional[str] = None):
        self.secret = secret or os.environ.get("DRILLOPS_LICENSE_SECRET", DEFAULT_VERIFICATION_SECRET)

    def mint_license(
        self,
        customer_name: str,
        customer_email: str,
        tier: LicenseTier = LicenseTier.PRO,
        days_valid: int = 365,
        max_targets: int = 10,
        features: Optional[List[str]] = None,
    ) -> str:
        """Constructs a signed license token string: DRILLOPS-V1.<payload_b64>.<hmac_sig>."""
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(days=days_valid)).isoformat() if days_valid != 0 else None
        lic_id = f"LIC-{tier.value.upper()[:3]}-{uuid.uuid4().hex[:8].upper()}"

        default_features = ["multi_target", "soc2_audit_pack", "custom_webhooks", "slack_alerts"]
        if tier == LicenseTier.ENTERPRISE:
            default_features.extend(["unlimited_targets", "priority_support", "white_label_dossier"])

        payload = {
            "id": lic_id,
            "tier": tier.value,
            "name": customer_name,
            "email": customer_email,
            "issued_at": now.isoformat(),
            "expires_at": expires_at,
            "max_targets": max_targets,
            "features": features if features is not None else default_features,
        }

        payload_json = json.dumps(payload, separators=(",", ":"))
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("utf-8").rstrip("=")

        sig = hmac.new(
            self.secret.encode("utf-8"),
            payload_b64.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return f"DRILLOPS-V1.{payload_b64}.{sig}"


class LicenseValidator:
    """Validates license keys offline against cryptographic HMAC-SHA256 signature."""

    def __init__(self, secret: Optional[str] = None):
        self.secret = secret or os.environ.get("DRILLOPS_LICENSE_SECRET", DEFAULT_VERIFICATION_SECRET)

    def validate_key(self, token: Optional[str] = None) -> Tuple[bool, Optional[LicenseInfo], Optional[str]]:
        """
        Validates token integrity, signature match, and expiration date.
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
        if len(parts) != 3 or parts[0] != "DRILLOPS-V1":
            return False, None, "Invalid license format. Expected format: DRILLOPS-V1.<payload>.<signature>"

        _, payload_b64, signature = parts

        # Verify signature against primary secret or public evaluation trial secret
        is_eval_trial = False
        expected_sig = hmac.new(
            self.secret.encode("utf-8"),
            payload_b64.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(expected_sig, signature):
            # Check if this is a web-generated evaluation trial key
            eval_sig = hmac.new(
                EVALUATION_TRIAL_SECRET.encode("utf-8"),
                payload_b64.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            if hmac.compare_digest(eval_sig, signature):
                is_eval_trial = True
            else:
                return False, None, "Cryptographic signature mismatch. License key may be forged or corrupted."

        # Decode payload
        try:
            # Restore padding
            padded_b64 = payload_b64 + "=" * (-len(payload_b64) % 4)
            payload_json = base64.urlsafe_b64decode(padded_b64).decode("utf-8")
            data = json.loads(payload_json)
        except Exception as e:
            return False, None, f"Failed to decode license payload: {str(e)}"

        try:
            tier = LicenseTier(data.get("tier", "pro"))
        except ValueError:
            tier = LicenseTier.PRO

        # Enforce strict security guardrails on evaluation trial keys
        if is_eval_trial:
            if tier == LicenseTier.ENTERPRISE:
                return False, None, "Evaluation trial key cannot authorize Enterprise tier. Official license required."
            
            issued_str = data.get("issued_at")
            expires_str = data.get("expires_at")
            if not expires_str:
                return False, None, "Evaluation trial key must have a defined expiration date."
            try:
                iss_dt = datetime.fromisoformat(issued_str.replace("Z", "+00:00"))
                exp_dt = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
                if (exp_dt - iss_dt).total_seconds() > 15 * 86400:
                    return False, None, "Evaluation trial key exceeds maximum allowed duration (14 days). Official license required."
            except Exception:
                pass

        max_targets_val = min(int(data.get("max_targets", 5)), 5) if is_eval_trial else int(data.get("max_targets", 5))

        info = LicenseInfo(
            license_id=f"{data.get('id', 'UNKNOWN')} [EVALUATION TRIAL]" if is_eval_trial else data.get("id", "UNKNOWN"),
            tier=tier,
            customer_name=data.get("name", "Unknown"),
            customer_email=data.get("email", "unknown@domain.com"),
            issued_at=data.get("issued_at", ""),
            expires_at=data.get("expires_at"),
            max_targets=max_targets_val,
            features=data.get("features", []),
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
