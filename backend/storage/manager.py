"""Storage path validation, disk-space checks, and sandbox enforcement."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from backend.config import ALLOWED_MOUNT_ROOTS, DATA_DIR, STORAGE_DIR, TEMP_UPLOAD_DIR


class StorageError(Exception):
    """Base class for storage-layer failures."""


class PathTraversalError(StorageError):
    """Raised when a path escapes the allowed roots."""


class InsufficientSpaceError(StorageError):
    """Raised when free disk space is insufficient for the planned write."""


class UnauthorizedRootError(StorageError):
    """Raised when a path is outside configured mount roots."""


def available_bytes(path: Path | None = None) -> int:
    target = path or STORAGE_DIR
    try:
        if not target.exists():
            target = DATA_DIR
        return shutil.disk_usage(str(target)).free
    except OSError:
        return 0


def ensure_space(required_bytes: int, path: Path | None = None, margin: int = 256 * 1024**2) -> None:
    free = available_bytes(path)
    if free < required_bytes + margin:
        raise InsufficientSpaceError(
            f"Insufficient disk space: need {required_bytes + margin} bytes, "
            f"have {free} free."
        )


def _is_under(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def resolve_safe_path(
    user_path: str | Path,
    *,
    allowed_roots: list[Path] | None = None,
    must_exist: bool = False,
    allow_symlink: bool = False,
) -> Path:
    """
    Resolve a user-supplied path and verify it stays inside one of the allowed roots.
    Rejects path traversal (``..``), absolute paths outside roots, and unauthorized
    symlinks by default.
    """
    roots = allowed_roots if allowed_roots is not None else list(ALLOWED_MOUNT_ROOTS)
    if not roots:
        raise UnauthorizedRootError("No allowed mount roots are configured.")

    raw = Path(user_path)
    if ".." in raw.parts:
        raise PathTraversalError(f"Path traversal rejected: {user_path}")

    try:
        resolved = raw.expanduser().resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise PathTraversalError(f"Unable to resolve path: {user_path}") from exc

    if not allow_symlink and raw.is_symlink():
        try:
            final = Path(os.path.realpath(str(resolved)))
        except OSError as exc:
            raise PathTraversalError(f"Symlink resolution failed: {user_path}") from exc
        resolved = final

    under_any = any(_is_under(root, resolved) for root in roots)
    if not under_any:
        raise UnauthorizedRootError(
            f"Path is outside approved mount roots: {user_path}"
        )

    if must_exist and not resolved.is_file():
        raise FileNotFoundError(f"File not found under approved root: {user_path}")

    return resolved


def managed_storage_path(logical_image_id: str, filename: str | None = None) -> Path:
    """Return the canonical managed path for a logical image id."""
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    safe_id = "".join(c for c in logical_image_id if c.isalnum() or c in "-_")
    if not safe_id:
        raise StorageError("Invalid logical image id")
    if filename:
        suffix = Path(filename).suffix[:16]
        return STORAGE_DIR / f"{safe_id}{suffix}"
    return STORAGE_DIR / safe_id


def temp_upload_path(session_id: str) -> Path:
    TEMP_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    safe = "".join(c for c in session_id if c.isalnum() or c in "-_")
    return TEMP_UPLOAD_DIR / f"{safe}.partial"


def set_readonly(path: Path) -> None:
    try:
        mode = path.stat().st_mode
        path.chmod(mode & ~0o222)
    except OSError:
        pass
