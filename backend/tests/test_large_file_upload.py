"""Chunked upload memory behaviour and interruption cleanup."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import app as app_module
from backend.database import Database
from backend.storage.upload_service import UploadService


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("CYBERTRACE_DATA_DIR", str(data))
    app_module.database = Database(data / "test.sqlite3")
    from backend.storage.image_store import ImageStore
    from backend.storage.import_service import ImportService

    app_module.image_store = ImageStore(app_module.database)
    app_module.upload_service = UploadService(app_module.database, app_module.image_store)
    app_module.import_service = ImportService(app_module.database, app_module.image_store)
    return TestClient(app_module.app)


def test_interrupted_upload_leaves_no_case_image(client: TestClient) -> None:
    case = client.post("/api/cases", json={"name": "interrupt"}).json()
    session = client.post(
        "/api/storage/upload-session",
        json={
            "case_id": case["case_id"],
            "filename": "partial.raw",
            "total_size": 8192,
        },
    )
    assert session.status_code == 201
    sid = session.json()["session_id"]

    client.post(
        "/api/storage/upload-chunk",
        data={"session_id": sid, "is_last": "false", "offset": "0"},
        files={"chunk": ("c.bin", b"X" * 2048, "application/octet-stream")},
    )
    abort = client.post("/api/storage/upload-abort", data={"session_id": sid})
    assert abort.status_code == 200

    refreshed = client.get(f"/api/cases/{case['case_id']}").json()
    assert refreshed["has_image"] is False
    assert refreshed.get("image_sha256") in (None, "")


def test_multi_chunk_upload_produces_verified_record(client: TestClient) -> None:
    case = client.post("/api/cases", json={"name": "multi"}).json()
    chunks = [b"AAAA" * 256, b"BBBB" * 256, b"CCCC" * 128]
    total = sum(len(c) for c in chunks)
    session = client.post(
        "/api/storage/upload-session",
        json={
            "case_id": case["case_id"],
            "filename": "multi.raw",
            "total_size": total,
        },
    )
    sid = session.json()["session_id"]
    offset = 0
    for i, chunk in enumerate(chunks):
        is_last = i == len(chunks) - 1
        response = client.post(
            "/api/storage/upload-chunk",
            data={
                "session_id": sid,
                "is_last": str(is_last).lower(),
                "offset": str(offset),
            },
            files={"chunk": ("c.bin", chunk, "application/octet-stream")},
        )
        assert response.status_code == 200, response.text
        offset += len(chunk)
        if is_last:
            body = response.json()
            assert body["complete"] is True
            assert body["file_size_bytes"] == total
            assert body["verification_status"] == "verified"
            assert len(body["sha256_hash"]) == 64
