"""Chunked streaming upload with progressive SHA-256 and partial-file cleanup."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

from backend.config import TEMP_UPLOAD_DIR, UPLOAD_CHUNK_SIZE_BYTES, effective_upload_limit_bytes
from backend.storage.manager import (
    ensure_space,
    managed_storage_path,
    set_readonly,
    temp_upload_path,
)
from backend.storage.image_store import ImageStore, new_logical_image_id


class UploadSessionError(Exception):
    pass


class UploadService:
    """
    Manages multi-chunk uploads.

    Sessions live as small JSON sidecars next to the partial binary so that a
    process restart can still clean up abandoned transfers.
    """

    def __init__(self, database: Any, image_store: ImageStore | None = None):
        self.database = database
        self.image_store = image_store or ImageStore(database)
        TEMP_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    def _session_meta_path(self, session_id: str) -> Path:
        return TEMP_UPLOAD_DIR / f"{session_id}.meta.json"

    def _load_meta(self, session_id: str) -> dict[str, Any]:
        path = self._session_meta_path(session_id)
        if not path.is_file():
            raise UploadSessionError(f"Upload session not found: {session_id}")
        return json.loads(path.read_text(encoding="utf-8"))

    def _save_meta(self, session_id: str, meta: dict[str, Any]) -> None:
        self._session_meta_path(session_id).write_text(
            json.dumps(meta, indent=None), encoding="utf-8"
        )

    def start_session(
        self,
        case_id: str,
        filename: str,
        total_size: int | None = None,
        investigator_limit_gib: int | None = None,
    ) -> dict[str, Any]:
        case = self.database.get_case(case_id)
        if not case:
            raise UploadSessionError("Case not found")

        limit = effective_upload_limit_bytes(investigator_limit_gib)
        if total_size is not None and total_size > limit:
            raise UploadSessionError(
                f"Declared size {total_size} exceeds effective limit {limit} bytes"
            )
        if total_size is not None and total_size > 0:
            ensure_space(total_size)

        session_id = uuid4().hex
        partial = temp_upload_path(session_id)
        partial.touch(exist_ok=False)

        meta = {
            "session_id": session_id,
            "case_id": case_id,
            "filename": Path(filename.replace("\\", "/")).name,
            "total_size": total_size,
            "received_bytes": 0,
            "sha256_hex": None,
            "limit_bytes": limit,
            "created_at": time.time(),
            "status": "active",
        }
        self._save_meta(session_id, meta)
        return {
            "session_id": session_id,
            "chunk_size": UPLOAD_CHUNK_SIZE_BYTES,
            "limit_bytes": limit,
            "filename": meta["filename"],
        }

    def write_chunk(
        self,
        session_id: str,
        chunk: bytes,
        *,
        is_last: bool = False,
        offset: int | None = None,
    ) -> dict[str, Any]:
        meta = self._load_meta(session_id)
        if meta["status"] != "active":
            raise UploadSessionError(f"Session is {meta['status']}")

        partial = temp_upload_path(session_id)
        if not partial.is_file():
            raise UploadSessionError("Partial file missing; session corrupted")

        current_size = partial.stat().st_size
        if offset is not None and offset != current_size:
            raise UploadSessionError(
                f"Offset mismatch: expected {current_size}, got {offset}"
            )

        new_size = current_size + len(chunk)
        if new_size > meta["limit_bytes"]:
            self.abort_session(session_id)
            raise UploadSessionError(
                f"Upload exceeds effective limit of {meta['limit_bytes']} bytes"
            )

        digest = hashlib.sha256()
        if current_size > 0:
            with partial.open("rb") as existing:
                while True:
                    block = existing.read(1024 * 1024)
                    if not block:
                        break
                    digest.update(block)
        digest.update(chunk)

        with partial.open("ab") as output:
            output.write(chunk)

        meta["received_bytes"] = new_size
        meta["sha256_hex"] = digest.hexdigest()
        self._save_meta(session_id, meta)

        if is_last:
            return self.finalize_session(session_id)

        return {
            "session_id": session_id,
            "received_bytes": new_size,
            "sha256_so_far": meta["sha256_hex"],
            "complete": False,
        }

    def finalize_session(self, session_id: str) -> dict[str, Any]:
        meta = self._load_meta(session_id)
        if meta["status"] != "active":
            raise UploadSessionError(f"Session is {meta['status']}")

        partial = temp_upload_path(session_id)
        if not partial.is_file():
            raise UploadSessionError("Partial file missing")

        size = partial.stat().st_size
        if size == 0:
            self.abort_session(session_id)
            raise UploadSessionError("Empty upload rejected")

        digest = hashlib.sha256()
        with partial.open("rb") as fh:
            while True:
                block = fh.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
        sha256_hex = digest.hexdigest()

        logical_id = new_logical_image_id()
        final_path = managed_storage_path(logical_id, meta["filename"])
        partial.replace(final_path)
        set_readonly(final_path)

        image_record = self.image_store.register(
            case_id=meta["case_id"],
            storage_type="browser_upload",
            file_path=final_path,
            file_size_bytes=size,
            sha256_hash=sha256_hex,
            original_filename=meta["filename"],
            verification_status="verified",
            logical_image_id=logical_id,
        )
        updated_case = self.database.attach_image(
            meta["case_id"],
            meta["filename"],
            str(final_path),
            size,
            sha256_hex,
        )

        self._session_meta_path(session_id).unlink(missing_ok=True)
        meta["status"] = "finalized"
        return {
            "session_id": session_id,
            "complete": True,
            "logical_image_id": logical_id,
            "file_size_bytes": size,
            "sha256_hash": sha256_hex,
            "storage_type": "browser_upload",
            "verification_status": "verified",
            "case": updated_case,
            "image_storage": image_record,
        }

    def abort_session(self, session_id: str) -> None:
        """Purge partial data and metadata. Never leaves an incomplete evidence record."""
        partial = temp_upload_path(session_id)
        partial.unlink(missing_ok=True)
        self._session_meta_path(session_id).unlink(missing_ok=True)

    def cleanup_stale(self, max_age_seconds: float = 3600) -> int:
        """Remove abandoned partial uploads older than max_age_seconds."""
        removed = 0
        now = time.time()
        for meta_path in TEMP_UPLOAD_DIR.glob("*.meta.json"):
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                if now - meta.get("created_at", 0) > max_age_seconds:
                    sid = meta.get("session_id") or meta_path.stem.replace(".meta", "")
                    self.abort_session(sid)
                    removed += 1
            except Exception:
                meta_path.unlink(missing_ok=True)
                removed += 1
        return removed
