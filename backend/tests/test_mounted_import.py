"""Mounted storage import validation and SHA-256 verification."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import app as app_module
from backend.database import Database


@pytest.fixture()
def client_and_mount(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    mount = tmp_path / "mount"
    mount.mkdir()
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setenv("CYBERTRACE_DATA_DIR", str(data_dir))
    monkeypatch.setenv("CYBERTRACE_ALLOWED_MOUNT_ROOTS", str(mount))
    import backend.config as cfg

    cfg.ALLOWED_MOUNT_ROOTS = [mount.resolve()]
    app_module.database = Database(data_dir / "test.sqlite3")
    from backend.storage.image_store import ImageStore
    from backend.storage.upload_service import UploadService
    from backend.storage.import_service import ImportService
    import backend.storage.import_service as imp
    import backend.storage.manager as mgr

    imp.ALLOWED_MOUNT_ROOTS = [mount.resolve()]
    mgr.ALLOWED_MOUNT_ROOTS = [mount.resolve()]
    app_module.image_store = ImageStore(app_module.database)
    app_module.upload_service = UploadService(app_module.database, app_module.image_store)
    app_module.import_service = ImportService(app_module.database, app_module.image_store)
    return TestClient(app_module.app), mount


def test_mounted_import_computes_sha256(client_and_mount) -> None:
    client, mount = client_and_mount
    sample = mount / "evidence.raw"
    content = b"forensic-memory-image-sample-data-0123456789"
    sample.write_bytes(content)
    expected = hashlib.sha256(content).hexdigest()

    case = client.post("/api/cases", json={"name": "mounted-case"}).json()
    response = client.post(
        "/api/storage/import-mounted",
        json={
            "case_id": case["case_id"],
            "source_path": str(sample),
            "copy_into_managed": False,
            "expected_sha256": expected,
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["sha256_hash"] == expected
    assert body["file_size_bytes"] == len(content)
    assert body["storage_type"] == "mounted_import"
    assert body["verification_status"] == "verified"
    assert body["case"]["has_image"] is True


def test_mounted_import_rejects_outside_root(client_and_mount) -> None:
    client, mount = client_and_mount
    outsider = mount.parent / "outside.raw"
    outsider.write_bytes(b"nope")
    case = client.post("/api/cases", json={"name": "bad-mount"}).json()
    response = client.post(
        "/api/storage/import-mounted",
        json={"case_id": case["case_id"], "source_path": str(outsider)},
    )
    assert response.status_code == 400
