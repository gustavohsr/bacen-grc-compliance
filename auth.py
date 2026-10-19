"""
Authentication, RBAC and MFA (RFC 6238 TOTP) engine for BACEN CMN 4.893 & 5.274 GRC.
Pure Python standard library (hashlib, hmac, secrets, time, struct, base64).
"""
import hashlib
import hmac
import secrets
import time
import struct
import base64

PBKDF2_ITERATIONS = 100000

def hash_password(password: str) -> tuple[str, str]:
    salt = secrets.token_bytes(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)
    return salt.hex(), pwd_hash.hex()

def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    try:
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(hash_hex)
        actual_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)
        return hmac.compare_digest(actual_hash, expected_hash)
    except Exception:
        return False

def generate_session_token() -> str:
    return secrets.token_hex(32)

def generate_mfa_secret() -> str:
    """Generates a Base32 secret key for Google Authenticator / TOTP apps."""
    random_bytes = secrets.token_bytes(20) # 160-bit secret
    return base64.b32encode(random_bytes).decode('utf-8').rstrip('=')

def get_totp_code(secret: str, time_step: int = 30, for_time: float = None) -> str:
    """Calculates 6-digit TOTP code per RFC 6238."""
    if for_time is None:
        for_time = time.time()
    counter = int(for_time // time_step)
    
    # Pad base32 secret if needed
    secret_clean = secret.strip().replace(' ', '').upper()
    padding_needed = (8 - len(secret_clean) % 8) % 8
    key = base64.b32decode(secret_clean + '=' * padding_needed)

    counter_bytes = struct.pack(">Q", counter)
    h = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code_int = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    code = str(code_int % 1000000).zfill(6)
    return code

def verify_totp(secret: str, code: str, time_step: int = 30, window: int = 1) -> bool:
    """Verifies a 6-digit code allowing a time drift window of +/- window intervals."""
    code_str = str(code).strip()
    if len(code_str) != 6 or not code_str.isdigit():
        return False
    current_time = time.time()
    for offset in range(-window, window + 1):
        check_time = current_time + (offset * time_step)
        expected_code = get_totp_code(secret, time_step, check_time)
        if hmac.compare_digest(expected_code, code_str):
            return True
    return False

if __name__ == "__main__":
    # Self-test
    s, h = hash_password("Admin@123")
    assert verify_password("Admin@123", s, h) is True
    assert verify_password("WrongPassword", s, h) is False
    
    secret = generate_mfa_secret()
    totp = get_totp_code(secret)
    assert len(totp) == 6
    assert verify_totp(secret, totp) is True
    print("Authentication and TOTP self-test passed successfully.")
