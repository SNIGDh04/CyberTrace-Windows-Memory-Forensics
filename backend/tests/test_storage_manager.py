"""Path sandboxing, traversal guards, and disk-space checks."""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.storage.manager import (
    PathTraversalError,
    UnauthorizedRootError,
    available_bytes,
    ensure_space,
    resolve_safe_path,
)


def test_rejects_parent_traversal(tmp_path: Path) -> None:
    root = tmp_path / "forensic"
    root.mkdir()
    with pytest.raises(PathTraversalError):
        resolve_safe_path("../../etc/shadow", allowed_roots=[root])


def test_rejects_path_outside_roots(tmp_path: Path) -> None:
    root = tmp_path / "forensic"
    root.mkdir()
    outsider = tmp_path / "outside.bin"
    outsider.write_bytes(b"x")
    with pytest.raises(UnauthorizedRootError):
        resolve_safe_path(str(outsider), allowed_roots=[root], must_exist=True)


def test_accepts_path_inside_root(tmp_path: Path) -> None:
    root = tmp_path / "forensic"
    root.mkdir()
    target = root / "image.raw"
    target.write_bytes(b"memory")
    resolved = resolve_safe_path(str(target), allowed_roots=[root], must_exist=True)
    assert resolved == target.resolve()


def test_ensure_space_raises_when_insufficient(tmp_path: Path) -> None:
    free = available_bytes(tmp_path)
    with pytest.raises(Exception):
        ensure_space(free + 10**15, path=tmp_path, margin=0)
