"""Base64url encoding/decoding per RFC 4648 Section 5, no padding."""

import base64


def encode_base64url(data: bytes) -> str:
    """Encode bytes to base64url string without padding.

    Uses the URL-safe alphabet (A-Z, a-z, 0-9, -, _) with no = padding,
    per RFC 4648 Section 5.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_base64url(s: str) -> bytes:
    """Decode a base64url string (with or without padding) to bytes."""
    # Add padding if needed
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s.encode("ascii"))
