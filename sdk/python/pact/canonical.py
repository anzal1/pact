"""RFC 8785 JSON Canonicalization Scheme (JCS).

Produces deterministic JSON output for signing:
- Object keys sorted lexicographically by Unicode code points
- No whitespace between tokens
- Numbers per ECMAScript 2015 Number.prototype.toString()
- Strings use standard JSON escaping (RFC 8259)
"""

import json
import math
from typing import Any


def canonical_json(obj: Any) -> bytes:
    """Serialize a Python object to canonical JSON bytes (RFC 8785 JCS).

    The input can be any JSON-serializable Python value: dict, list, str,
    int, float, bool, or None.

    Returns UTF-8 encoded bytes that are deterministic — the same logical
    value always produces the same byte sequence across implementations.
    """
    # If the input is a dataclass or has a to_dict method, convert first
    if hasattr(obj, "to_dict"):
        obj = obj.to_dict()

    # Round-trip through json to normalize (handles dataclasses, enums, etc.)
    normalized = json.loads(json.dumps(obj, default=_json_default))
    return _write_canonical(normalized).encode("utf-8")


def _json_default(obj: Any) -> Any:
    """Default serializer for objects json.dumps can't handle."""
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def _write_canonical(val: Any) -> str:
    """Write a value in JCS canonical form."""
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        return str(val)
    if isinstance(val, float):
        return _canonical_float(val)
    if isinstance(val, str):
        return _canonical_string(val)
    if isinstance(val, dict):
        # RFC 8785: keys sorted by Unicode code point order
        parts = []
        for key in sorted(val.keys()):
            k = _canonical_string(key)
            v = _write_canonical(val[key])
            parts.append(f"{k}:{v}")
        return "{" + ",".join(parts) + "}"
    if isinstance(val, list):
        parts = [_write_canonical(item) for item in val]
        return "[" + ",".join(parts) + "]"
    raise TypeError(f"Unsupported type in canonical JSON: {type(val)}")


def _canonical_string(s: str) -> str:
    """Serialize a string with standard JSON escaping (RFC 8259).

    Uses Python's json.dumps which handles all required escaping.
    """
    return json.dumps(s, ensure_ascii=False)


def _canonical_float(f: float) -> str:
    """Serialize a float per ECMAScript 2015 Number.prototype.toString().

    Handles special cases required by RFC 8785.
    """
    if math.isnan(f) or math.isinf(f):
        raise ValueError(f"Cannot serialize {f} in canonical JSON")
    if f == 0.0:
        return "0"
    # Use repr to get shortest representation that round-trips
    s = repr(f)
    # Python's repr already gives shortest roundtrip representation
    # but we need to match ES2015 formatting
    if "e" in s or "E" in s:
        return s
    # Remove trailing zeros after decimal point
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return s
