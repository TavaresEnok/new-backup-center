import base64
import hashlib
import hmac
import secrets
import struct
import time


_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def generate_totp_secret(length: int = 32) -> str:
    return "".join(secrets.choice(_BASE32_ALPHABET) for _ in range(length))


def _totp_at(secret: str, for_counter: int, digits: int = 6) -> str:
    key = base64.b32decode(secret, casefold=True)
    msg = struct.pack(">Q", for_counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    code %= 10 ** digits
    return str(code).zfill(digits)


def verify_totp(secret: str, code: str, step_seconds: int = 30, window: int = 1, digits: int = 6) -> bool:
    if not secret or not code:
        return False
    code = "".join(ch for ch in str(code) if ch.isdigit())
    if len(code) != digits:
        return False
    now_counter = int(time.time() // step_seconds)
    for drift in range(-window, window + 1):
        if _totp_at(secret, now_counter + drift, digits=digits) == code:
            return True
    return False
