"""Upload limit enforcement (HTTP 413 / session rejection)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import app as app_module
from backend.config import DEFAULT_UPLOAD_LIMIT_GIB, MAX_ADMIN_UPLOAD_LIMIT_GIB
from backend.database import Database


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    db_path = tmp_path / "test.sqlite3"
    monkeypatch.setenv("CYBERTRACE_DATA_DIR", str(tmp_path))
    app_module.database = Database(db_path)
    from backend.storage.image_store import ImageStore
    from backend.storage.upload_service import UploadService
    from backend.storage.import_service import ImportService

    app_module.image_store = ImageStore(app_module.database)
    app_module.upload_service = UploadService(app_module.database, app_module.image_store)
    app_module.import_service = ImportService(app_module.database, app_module.image_store)
    return TestClient(app_module.app)


def test_storage_config_exposes_limits(client: TestClient) -> None:
    response = client.get("/api/storage/config")
    assert response.status_code == 200
    body = response.json()
    assert body["default_upload_limit_gib"] == DEFAULT_UPLOAD_LIMIT_GIB
    assert body["max_admin_upload_limit_gib"] == MAX_ADMIN_UPLOAD_LIMIT_GIB
    assert body["upload_chunk_size_bytes"] > 0
    assert "allowed_mount_roots" in body


def test_upload_session_rejects_oversized_declaration(client: TestClient) -> None:
    case = client.post("/api/cases", json={"name": "limit-test"}).json()
    huge = (MAX_ADMIN_UPLOAD_LIMIT_GIB + 10) * 1024**3
    response = client.post(
        "/api/storage/upload-session",
        json={
            "case_id": case["case_id"],
            "filename": "big.raw",
            "total_size": huge,
        },
    )
    assert response.status_code == 400
    assert "limit" in response.json()["detail"].lower() or "exceed" in response.json()["detail"].lower()


def test_chunk_upload_within_limits(client: TestClient) -> None:
    case = client.post("/api/cases", json={"name": "ok-upload"}).json()
    payload = b"A" * 4096
    session = client.post(
        "/api/storage/upload-session",
        json={
            "case_id": case["case_id"],
            "filename": "sample.raw",
            "total_size": len(payload),
        },
    )
    assert session.status_code == 201
    sid = session.json()["session_id"]
    final = client.post(
        "/api/storage/upload-chunk",
        data={"session_id": sid, "is_last": "true", "offset": "0"},
        files={"chunk": ("chunk.bin", payload, "application/octet-stream")},
    )
    assert final.status_code == 200
    body = final.json()
    assert body["complete"] is True
    assert body["file_size_bytes"] == len(payload)
    assert len(body["sha256_hash"]) == 64
    assert body["storage_type"] == "browser_upload"
    assert body["verification_status"] == "verified"
