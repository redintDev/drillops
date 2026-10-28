"""Data models and enums for DrillOps commercial licensing."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional


class LicenseTier(str, Enum):
    COMMUNITY = "community"
    PRO = "pro"
    ENTERPRISE = "enterprise"


@dataclass
class LicenseInfo:
    """Parsed and verified DrillOps license record."""
    license_id: str
    tier: LicenseTier
    customer_name: str
    customer_email: str
    issued_at: str
    expires_at: Optional[str]
    max_targets: int
    features: List[str] = field(default_factory=list)

    @property
    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        try:
            exp = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
            return datetime.now(timezone.utc) > exp
        except Exception:
            return True

    @property
    def is_pro_or_enterprise(self) -> bool:
        return self.tier in (LicenseTier.PRO, LicenseTier.ENTERPRISE)
