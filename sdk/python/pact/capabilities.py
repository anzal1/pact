"""Capability URIs for the Pact protocol.

Format: resource:action,constraint=value,constraint=value

Examples:
    "github:pr:create,repo=myorg/*"
    "flights:book<500USD"
    "email:send,to=*@mycompany.com"
    "github:*"                        (wildcard — all github actions)
    "*"                               (full access — dangerous, explicit)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Capability:
    """A parsed capability URI.

    Attributes:
        resource: Hierarchical resource path (e.g., "github:pr" or "flights").
        action: The specific operation (e.g., "create", "book", "*").
        constraints: Key=value pairs that further restrict the capability.
        raw: The original capability string.
    """

    resource: str
    action: str
    constraints: dict[str, str] = field(default_factory=dict)
    raw: str = ""

    def covers(self, child: Capability) -> bool:
        """Check whether this capability covers (is a superset of) another.

        A parent capability covers a child if:
        - The parent resource matches the child resource (including wildcards)
        - The parent action matches the child action (including wildcards)
        - All parent constraints are satisfied by the child's constraints
        """
        # Full wildcard covers everything
        if self.resource == "*" and self.action == "*":
            return True

        # Check resource match
        if not _resource_matches(self.resource, child.resource):
            return False

        # Check action match
        if self.action != "*" and self.action != child.action:
            return False

        # Check constraints — parent's constraints must be satisfied by child
        for key, parent_val in self.constraints.items():
            child_val = child.constraints.get(key)
            if child_val is None:
                return False
            if not _constraint_satisfied(key, parent_val, child_val):
                return False

        return True


def parse_capability(raw: str) -> Capability:
    """Parse a capability URI string into a structured Capability.

    Supported formats:
        "resource:action"
        "resource:action,key=value,key=value"
        "resource:sub:action,key=value"
        "resource:*"                         (wildcard action)
        "*"                                  (full access)
        "flights:book<500USD"                (shorthand for max constraint)

    Raises:
        ValueError: If the capability string is invalid.
    """
    raw = raw.strip()
    if not raw:
        raise ValueError("Empty capability string")

    # Full wildcard
    if raw == "*":
        return Capability(resource="*", action="*", raw=raw)

    # Split off constraints
    resource_action = ""
    constraint_str = ""

    # Find the first comma — constraints start there
    comma_idx = raw.find(",")
    if comma_idx >= 0:
        resource_action = raw[:comma_idx]
        constraint_str = raw[comma_idx + 1:]
    else:
        # Check for < constraint (e.g., "flights:book<500USD")
        lt_idx = raw.find("<")
        if lt_idx >= 0:
            resource_action = raw[:lt_idx]
            constraint_str = "max=" + raw[lt_idx + 1:]
        else:
            resource_action = raw

    # Parse resource:action (may have multiple colon-separated segments)
    parts = resource_action.split(":")
    if len(parts) < 1:
        raise ValueError(f"Invalid capability format: {raw!r}")

    if len(parts) == 1:
        # Just a resource with implied wildcard action
        resource = parts[0]
        action = "*"
    else:
        # Last part is the action, everything before is the resource path
        action = parts[-1]
        resource = ":".join(parts[:-1])

    if not resource:
        raise ValueError(f"Empty resource in capability: {raw!r}")

    # Parse constraints
    constraints: dict[str, str] = {}
    if constraint_str:
        for c in constraint_str.split(","):
            c = c.strip()
            if not c:
                continue
            eq_idx = c.find("=")
            if eq_idx < 0:
                raise ValueError(
                    f"Invalid constraint (no '='): {c!r} in capability {raw!r}"
                )
            key = c[:eq_idx]
            value = c[eq_idx + 1:]
            if not key:
                raise ValueError(f"Empty constraint key in capability {raw!r}")
            constraints[key] = value

    return Capability(
        resource=resource,
        action=action,
        constraints=constraints,
        raw=raw,
    )


class CapabilitySet:
    """An ordered list of capabilities.

    Used in delegation chains to specify what an agent is allowed to do.
    """

    def __init__(self, capabilities: list[Capability]):
        self.capabilities = capabilities

    def covers(self, child: CapabilitySet) -> bool:
        """Check if this capability set covers all capabilities in the child set.

        Every child capability must be covered by at least one parent capability.
        """
        for child_cap in child.capabilities:
            covered = any(
                parent_cap.covers(child_cap) for parent_cap in self.capabilities
            )
            if not covered:
                return False
        return True

    def strings(self) -> list[str]:
        """Return the raw string representations of all capabilities."""
        return [cap.raw for cap in self.capabilities]


def parse_capability_set(raw_list: list[str]) -> CapabilitySet:
    """Parse a list of capability strings into a CapabilitySet.

    Raises:
        ValueError: If any capability string is invalid.
    """
    caps = [parse_capability(r) for r in raw_list]
    return CapabilitySet(caps)


def _resource_matches(parent: str, child: str) -> bool:
    """Check if a parent resource pattern matches a child resource.

    Supports hierarchical matching: "github" matches "github:pr", "github:issue", etc.
    Supports wildcards: "github:*" matches any github sub-resource.
    """
    if parent == child:
        return True

    # Parent "github" covers "github:pr", "github:issue", etc.
    if child.startswith(parent + ":"):
        return True

    # Wildcard in parent resource
    if parent.endswith(":*"):
        prefix = parent[:-2]
        return child == prefix or child.startswith(prefix + ":")

    return False


def _constraint_satisfied(key: str, parent_val: str, child_val: str) -> bool:
    """Check if a child constraint value satisfies a parent constraint.

    Handles numeric comparisons (for "max" constraints) and pattern matching.
    """
    # Numeric max constraint: child's value must be <= parent's value
    if key == "max":
        parent_num = _extract_number(parent_val)
        child_num = _extract_number(child_val)
        if parent_num >= 0 and child_num >= 0:
            return child_num <= parent_num

    # Pattern matching for glob-like constraints (e.g., repo=myorg/*)
    if "*" in parent_val:
        return _glob_match(parent_val, child_val)

    # Exact match
    return parent_val == child_val


def _extract_number(s: str) -> int:
    """Pull a leading integer from a string like '500USD'.

    Returns -1 if no leading digits found.
    """
    num_str = ""
    for ch in s:
        if ch.isdigit():
            num_str += ch
        else:
            break
    if not num_str:
        return -1
    return int(num_str)


def _glob_match(pattern: str, value: str) -> bool:
    """Simple glob matching where * matches any substring."""
    if pattern == "*":
        return True

    parts = pattern.split("*")
    if len(parts) == 1:
        # No wildcard — exact match
        return pattern == value

    # Check prefix
    if parts[0] and not value.startswith(parts[0]):
        return False

    # Check suffix
    last = parts[-1]
    if last and not value.endswith(last):
        return False

    # Check middle parts appear in order
    remaining = value
    for part in parts:
        if not part:
            continue
        idx = remaining.find(part)
        if idx < 0:
            return False
        remaining = remaining[idx + len(part):]

    return True
