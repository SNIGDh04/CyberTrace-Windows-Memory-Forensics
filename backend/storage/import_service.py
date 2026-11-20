"""Mounted-storage importer with path validation and SHA-256 verification."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path
from typing import Any

from backend.config import ALLOWED_MOUNT_ROOTS
from backend.storage.manager import (
    PathTraversalError,
    UnauthorizedRootError,
    ensure_space,
    managed_storage_path,
    resolve_safe_path,
    set_readonly,
)
from backend.storage.image_store import ImageStore, new_logical_image_id


class ImportError(Exception):
    pass


class ImportService:
    def __init__(self, database: Any, image_store: ImageStore | None = None):
        self.database = database
        self.image_store = image_store or ImageStore(database)

    def import_mounted(
        self,
        case_id: str,
        source_path: str,
        *,
        copy_into_managed: bool = False,
        expected_sha256: str | None = None,
    ) -> dict[str, Any]:
        case = self.database.get_case(case_id)
        if not case:
            raise ImportError("Case not found")

        try:
            resolved = resolve_safe_path(
                source_path,
                allowed_roots=ALLOWED_MOUNT_ROOTS,
                must_exist=True,
                allow_symlink=False,
            )
        except (PathTraversalError, UnauthorizedRootError, FileNotFoundError) as exc:
            raise ImportError(str(exc)) from exc

        if not resolved.is_file():
            raise ImportError(f"Not a regular file: {source_path}")

        size = resolved.stat().st_size
        if size == 0:
            raise ImportError("Empty file rejected")

        digest = hashlib.sha256()
        with resolved.open("rb") as fh:
            while True:
                block = fh.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
        sha256_hex = digest.hexdigest()

        if expected_sha256 and expected_sha256.lower() != sha256_hex.lower():
            raise ImportError(
                f"SHA-256 mismatch: expected {expected_sha256}, got {sha256_hex}"
            )

        logical_id = new_logical_image_id()
        original_filename = resolved.name

        if copy_into_managed:
            ensure_space(size)
            dest = managed_storage_path(logical_id, original_filename)
            shutil.copy2(resolved, dest)
            set_readonly(dest)
            final_path = dest
            storage_type = "mounted_import"
        else:
            final_path = resolved
            storage_type = "mounted_import"

        image_record = self.image_store.register(
            case_id=case_id,
            storage_type=storage_type,
            file_path=final_path,
            file_size_bytes=size,
            sha256_hash=sha256_hex,
            original_filename=original_filename,
            verification_status="verified",
            logical_image_id=logical_id,
        )
        updated_case = self.database.attach_image(
            case_id,
            original_filename,
            str(final_path),
            size,
            sha256_hex,
        )
        return {
            "logical_image_id": logical_id,
            "file_size_bytes": size,
            "sha256_hash": sha256_hex,
            "storage_type": storage_type,
            "verification_status": "verified",
            "file_path": str(final_path),
            "case": updated_case,
            "image_storage": image_record,
        }
