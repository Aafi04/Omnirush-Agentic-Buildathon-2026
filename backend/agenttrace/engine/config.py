"""Bounded deterministic engine configuration. No DNS or host access is used."""
import ipaddress
import re
from typing import Literal

from pydantic import ConfigDict, Field, field_validator

from ..schemas import StrictModel
from .paths import normalize_path

SYNTHETIC_MARKER = "AGENTTRACE_SYNTHETIC_SECRET_001"


def canonical_host(value: str) -> str | None:
    """Canonical bare DNS/IP host, rejecting URL authority tricks and legacy IPs.

    DNS uses Python's deterministic IDNA codec, lowercase and one trailing dot.
    IPv6 is bare (no brackets, port, scope ID); callers strip URL brackets first.
    """
    if not value or len(value) > 253 or any(c.isspace() or ord(c) < 32 for c in value):
        return None
    if any(c in value for c in "%@\\/[]?#"):
        return None
    try:
        return ipaddress.ip_address(value).compressed.lower()
    except ValueError:
        pass
    if ":" in value:
        return None
    host = value[:-1] if value.endswith(".") else value
    try:
        host = host.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None
    # Purely numeric / hex forms may be interpreted as IPs by HTTP clients.
    labels = host.split(".")
    if all(re.fullmatch(r"(?:[0-9]+|0x[0-9a-f]+)", label) for label in labels):
        return None
    if not host or len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        return None
    return host


class EngineConfig(StrictModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    protected_roots: dict[Literal["posix", "windows"], list[str]] = Field(default_factory=lambda: {
        "posix": ["/etc", "/home", "/workspace"],
        "windows": ["C:/Windows", "C:/Users", "C:/workspace"],
    })
    workspace_roots: dict[Literal["posix", "windows"], list[str]] = Field(default_factory=lambda: {
        "posix": ["/workspace"], "windows": ["C:/workspace"],
    })
    allowed_hosts: list[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1", "::1"], max_length=64)
    synthetic_markers: list[Literal["AGENTTRACE_SYNTHETIC_SECRET_001"]] = Field(
        default_factory=lambda: [SYNTHETIC_MARKER], min_length=1, max_length=1)

    @field_validator("protected_roots", "workspace_roots")
    @classmethod
    def valid_roots(cls, roots):
        if set(roots) != {"posix", "windows"}:
            raise ValueError("Both path flavors require roots")
        for flavor, entries in roots.items():
            if not 1 <= len(entries) <= 16:
                raise ValueError("Require 1 to 16 roots per flavor")
            if any(len(root) > 256 or normalize_path(root, None, flavor) is None for root in entries):
                raise ValueError("Roots must be unambiguous absolute paths of at most 256 characters")
        return {flavor: list(entries) for flavor, entries in roots.items()}

    @field_validator("allowed_hosts")
    @classmethod
    def valid_hosts(cls, entries):
        canonical = [canonical_host(host) for host in entries]
        if any(host is None for host in canonical):
            raise ValueError("Allowed hosts must be bare unambiguous DNS names or IP addresses")
        return list(dict.fromkeys(canonical))


DEFAULT_CONFIG = EngineConfig()
