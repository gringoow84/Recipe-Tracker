"""
Encryption helpers using Fernet symmetric encryption.
Key is loaded from RECIPE_TRACKER_ENC_KEY env var or auto-generated and saved to secret.key.
"""

import os
import base64
from cryptography.fernet import Fernet

_fernet = None

KEY_FILE = os.path.join(os.path.dirname(__file__), "secret.key")


def _get_fernet():
    global _fernet
    if _fernet is not None:
        return _fernet

    env_key = os.environ.get("RECIPE_TRACKER_ENC_KEY")
    if env_key:
        key = env_key.encode() if isinstance(env_key, str) else env_key
        _fernet = Fernet(key)
        return _fernet

    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read().strip()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        print(f"[crypto] Generated new encryption key -> {KEY_FILE}")

    _fernet = Fernet(key)
    return _fernet


def encrypt(value: str) -> str:
    if not value:
        return ""
    f = _get_fernet()
    return f.encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    if not value:
        return ""
    f = _get_fernet()
    return f.decrypt(value.encode()).decode()


def encrypt_float(v: float) -> str:
    return encrypt(str(v))


def decrypt_float(v: str) -> float:
    raw = decrypt(v)
    if not raw:
        return 0.0
    return float(raw)
