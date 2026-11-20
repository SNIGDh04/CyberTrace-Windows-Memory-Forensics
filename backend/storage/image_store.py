"""Logical image identity, path resolution, and verification status."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from backend.storage.manager import managed_storage_path, set_readonly


def new_logical_image_id() -> str:
    return f"img_{uuid.uuid4().hex}"


class ImageStore:
    """Thin coordinator between logical image IDs and on-disk paths."""

    def __init__(self, database: Any):
        self.database = database

    def register(
        self,
        *,
        case_id: str,
        storage_type: str,
        file_path: str | Path,
        file_size_bytes: int,
        sha256_hash: str,
        original_filename: str | None = None,
        verification_status: str = "verified",
        logical_image_id: str | None = None,
    ) -> dict[str, Any]:
        logical_image_id = logical_image_id or new_logical_image_id()
        path = Path(file_path).resolve()
        record = self.database.create_image_storage(
            logical_image_id=logical_image_id,
            case_id=case_id,
            storage_type=storage_type,
            file_path=str(path),
            file_size_bytes=file_size_bytes,
            sha256_hash=sha256_hash,
            verification_status=verification_status,
            original_filename=original_filename,
        )
        if verification_status == "verified" and path.is_file():
            set_readonly(path)
        return record

    def resolve_path(self, logical_image_id: str) -> Path | None:
        row = self.database.get_image_storage(logical_image_id)
        if not row:
            return None
        path = Path(row["file_path"])
        return path if path.is_file() else None

    def get(self, logical_image_id: str) -> dict[str, Any] | None:
        return self.database.get_image_storage(logical_image_id)

    def for_case(self, case_id: str) -> dict[str, Any] | None:
        return self.database.get_image_storage_for_case(case_id)

    def physical_path_for_new(self, logical_image_id: str, filename: str | None = None) -> Path:
        return managed_storage_path(logical_image_id, filename)
