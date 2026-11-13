from __future__ import annotations
import hmac
import hashlib
import time

ZERO_BIT = '\u200b'
ONE_BIT  = '\u200c'

def encode_canary(session_id: str, secret: str) -> str:
    """Generate a zero-width cryptographic canary for a session."""
    # Create an HMAC signature
    msg = f"{session_id}:{int(time.time() / 86400)}".encode() # Rotates daily
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()[:8] # 64 bits
    
    # Convert bits to zero-width chars
    bits = "".join(f"{b:08b}" for b in sig)
    return "".join(ZERO_BIT if bit == '0' else ONE_BIT for bit in bits)

def decode_canary(text: str) -> str | None:
    """Extract zero-width canary from text if present."""
    # Find sequence of exactly 64 zero-width bits
    import re
    pattern = re.compile(f"[{ZERO_BIT}{ONE_BIT}]{{64}}")
    match = pattern.search(text)
    if not match:
        return None
    return match.group(0)

def verify_canary(text: str, session_id: str, secret: str) -> bool:
    """Verify if the text contains a valid canary for the session."""
    extracted = decode_canary(text)
    if not extracted:
        return False
    expected = encode_canary(session_id, secret)
    return extracted == expected
