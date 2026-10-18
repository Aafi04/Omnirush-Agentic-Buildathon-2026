"""Host-independent lexical paths; never resolve symlinks or inspect a filesystem."""
import posixpath
import re


def normalize_path(value: str, cwd: str | None, flavor: str) -> str | None:
    """Return an absolute lexical path, or None when interpretation is ambiguous."""
    if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        return None
    if any(c in value for c in ("$", "%", "~", "*", "?", "[", "]", "{", "}")):
        return None
    if flavor == "windows":
        text = value.replace("\\", "/")
        if text.startswith("/") or ":" in text[2:]:
            return None  # UNC, device, root-relative, alternate data streams
        if re.match(r"^[A-Za-z]:/", text):
            absolute = text
        else:
            if ":" in text or cwd is None:
                return None
            base = normalize_path(cwd, None, flavor)
            if base is None:
                return None
            absolute = base + "/" + text
        parts = absolute[3:].split("/")
        for part in parts:
            if part not in {"", ".", ".."}:
                if part.endswith((".", " ")) or any(c in part for c in '<>"|:'):
                    return None
                if part.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10))}:
                    return None
        return absolute[:2].lower() + posixpath.normpath("/" + absolute[3:]).lower()
    if flavor != "posix" or "\\" in value or value.startswith("//"):
        return None
    if value.startswith("/"):
        return posixpath.normpath(value)
    base = normalize_path(cwd, None, flavor) if cwd is not None else None
    return posixpath.normpath(base + "/" + value) if base is not None else None


def within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")
