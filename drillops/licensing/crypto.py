"""Cryptographic verification primitives for DrillOps offline license tokens.

Implements pure-Python RFC 8032 Ed25519 public-key signature verification with
zero third-party dependencies. Does not contain private signing keys or minting logic.
"""

import hashlib
from typing import Optional

# Official DrillOps Master Public Verification Key (Ed25519)
# Used to verify authentic customer licenses offline.
DRILLOPS_PUBLIC_KEY = "4d8e30c506b386e6e5efd8ee8da2464d853ea7a17483aa7fe0602c02d0a12b45"

# Public evaluation trial secret (strictly limited to 14-day Pro evaluation)
EVALUATION_TRIAL_SECRET = "drillops_eval_public_trial_2026"

# RFC 8032 Ed25519 Curve Parameters
_P = 2**255 - 19
_D = -121665 * pow(121666, -1, _P) % _P
_Q = 2**252 + 27742317777372353535851937790883648493
_I = pow(2, (_P - 1) // 4, _P)


def _inv(z: int) -> int:
    return pow(z, _P - 2, _P)


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        if sign:
            return None
        return 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = (x * _I) % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


# Base Point B
_By = 4 * _inv(5) % _P
_Bx = _recover_x(_By, 0)
assert _Bx is not None
_B = (_Bx, _By)


def _edwards_add(P: tuple[int, int], Q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _D * x1 * x2 * y1 * y2) % _P
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _D * x1 * x2 * y1 * y2) % _P
    return (x3, y3)


def _scalarmult(P: tuple[int, int], e: int) -> tuple[int, int]:
    R = (0, 1)
    while e > 0:
        if e & 1:
            R = _edwards_add(R, P)
        P = _edwards_add(P, P)
        e >>= 1
    return R


def _encodepoint(P: tuple[int, int]) -> bytes:
    x, y = P
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(32))


def _decodepoint(s: bytes) -> Optional[tuple[int, int]]:
    if len(s) != 32:
        return None
    y = sum(s[i] << (8 * i) for i in range(32))
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y)


def verify_ed25519(public_key_bytes: bytes, message: bytes, signature_bytes: bytes) -> bool:
    """Verifies an RFC 8032 Ed25519 signature.
    
    Returns True if authentic and untampered, False otherwise.
    """
    if len(signature_bytes) != 64 or len(public_key_bytes) != 32:
        return False
    Rs, Ss = signature_bytes[:32], signature_bytes[32:]
    S = int.from_bytes(Ss, "little")
    if S >= _Q:
        return False
    R = _decodepoint(Rs)
    A = _decodepoint(public_key_bytes)
    if R is None or A is None:
        return False
    k = sum(hashlib.sha512(Rs + public_key_bytes + message).digest()[i] << (8 * i) for i in range(64)) % _Q
    # Verify SB == R + kA
    SB = _scalarmult(_B, S)
    R_plus_kA = _edwards_add(R, _scalarmult(A, k))
    return _encodepoint(SB) == _encodepoint(R_plus_kA)
