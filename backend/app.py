import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.config import (
    ALLOWED_MOUNT_ROOTS,
    DATABASE_PATH,
    DEFAULT_UPLOAD_LIMIT_GIB,
    FRONTEND_DIR,
    MAX_ADMIN_UPLOAD_LIMIT_GIB,
    MAX_UPLOAD_BYTES,
    RAW_DIR,
    SUPPORTED_PLUGINS,
    UPLOAD_CHUNK_SIZE_BYTES,
    VOLATILITY_OUTPUT_DIR,
    effective_upload_limit_bytes,
    ensure_data_directories,
)
from backend.database import Database, utc_now
from backend.evidence.normalizer import system_information
from backend.evidence.schema import EvidenceRecord, RelationshipRecord
from backend.models import AnalyzeRequest, CaseCreate
from backend.pipeline import process_analysis_outputs
from backend.reconstruction.graph_builder import EvidenceGraphBuilder
from backend.reports.report_generator import generate_report
from backend.storage.image_store import ImageStore
from backend.storage.import_service import ImportError as MountedImportError
from backend.storage.import_service import ImportService
from backend.storage.manager import InsufficientSpaceError, StorageError
from backend.storage.upload_service import UploadService, UploadSessionError
from backend.volatility.runner import VolatilityRunner

ensure_data_directories()
database = Database(DATABASE_PATH)
runner = VolatilityRunner(VOLATILITY_OUTPUT_DIR)
image_store = ImageStore(database)
upload_service = UploadService(database, image_store)
import_service = ImportService(database, image_store)

app = FastAPI(
    title="CyberTrace",
    description="Evidence-driven attack reconstruction from volatile memory.",
    version="0.1.0",
)
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


def public_case(case: dict[str, Any]) -> dict[str, Any]:
    image_meta = database.get_image_storage_for_case(case["case_id"])
    result = {
        "case_id": case["case_id"],
        "name": case["name"],
        "original_filename": case.get("original_filename"),
        "image_size_bytes": case.get("image_size_bytes"),
        "image_sha256": case.get("image_sha256"),
        "has_image": bool(case.get("stored_path") and Path(case["stored_path"]).is_file()),
        "created_at": case["created_at"],
        "updated_at": case["updated_at"],
    }
    if image_meta:
        result["logical_image_id"] = image_meta["logical_image_id"]
        result["storage_type"] = image_meta["storage_type"]
        result["verification_status"] = image_meta["verification_status"]
    return result


def public_analysis(run: dict[str, Any]) -> dict[str, Any]:
    result = {
        key: value
        for key, value in run.items()
        if key not in {"case_id", "image_path"}
    }
    result["source_image_filename"] = run.get("image_filename")
    result["source_image_sha256"] = run.get("image_sha256")
    public_plugins = []
    for plugin_result in run["plugin_results"]:
        item = {
            key: value
            for key, value in plugin_result.items()
            if key not in {
                "stdout_path",
                "stderr_path",
                "structured_output_path",
                "parsed_output",
            }
        }
        item["raw_output_url"] = (
            f"/api/analyses/{run['run_id']}/plugins/{plugin_result['plugin']}/stdout"
            if plugin_result.get("stdout_path")
            else None
        )
        item["raw_error_url"] = (
            f"/api/analyses/{run['run_id']}/plugins/{plugin_result['plugin']}/stderr"
            if plugin_result.get("stderr_path")
            else None
        )
        item["structured_output_url"] = (
            f"/api/analyses/{run['run_id']}/plugins/{plugin_result['plugin']}/json"
            if plugin_result.get("structured_output_path")
            else None
        )
        public_plugins.append(item)
    result["plugin_results"] = public_plugins
    result["evidence_summary"] = database.case_summary(run["case_id"], run["run_id"])
    return result


def execute_analysis(run_id: str, case_id: str, image_path: str, plugins: list[str]) -> None:
    database.update_analysis(run_id, status="running", started_at=utc_now())
    results = [{"plugin": plugin, "status": "queued"} for plugin in plugins]
    try:
        for index, plugin in enumerate(plugins):
            result = runner.run_plugin(Path(image_path), case_id, run_id, plugin)
            # Keep parsed JSON out of run metadata; the evidence pipeline reads it
            # from the structured-output file after plugin execution.
            stored = {key: value for key, value in result.items() if key != "parsed_output"}
            results[index] = stored
            database.update_analysis(run_id, plugin_results=results)
        processing = process_analysis_outputs(database, run_id, case_id, results)
        completed_count = sum(result.get("status") == "completed" for result in results)
        failed_count = sum(result.get("status") == "failed" for result in results)
        final_status = (
            "completed"
            if failed_count == 0 and not processing["processing_errors"]
            else "partial"
            if completed_count > 0 or processing["evidence_count"] > 0
            else "failed"
        )
        database.update_analysis(
            run_id,
            status=final_status,
            plugin_results=results,
            error="; ".join(processing["processing_errors"]) or None,
            completed_at=utc_now(),
        )
    except Exception as exc:
        database.update_analysis(
            run_id,
            status="failed",
            plugin_results=results,
            error=str(exc)[:2000],
            completed_at=utc_now(),
        )


@app.get("/", include_in_schema=False)
def home() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "favicon.svg", media_type="image/svg+xml")


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "CyberTrace",
        "volatility_available": bool(runner.executable_path()),
        "volatility_executable": runner.executable_path(),
        "supported_plugins": list(SUPPORTED_PLUGINS),
        "max_upload_bytes": MAX_UPLOAD_BYTES,
        "default_upload_limit_gib": DEFAULT_UPLOAD_LIMIT_GIB,
        "max_admin_upload_limit_gib": MAX_ADMIN_UPLOAD_LIMIT_GIB,
        "upload_chunk_size_bytes": UPLOAD_CHUNK_SIZE_BYTES,
    }


@app.get("/benchmarking", include_in_schema=False)
def benchmarking_methodology() -> PlainTextResponse:
    path = Path(__file__).resolve().parent.parent / "docs" / "benchmarking.md"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Benchmark methodology is unavailable.")
    return PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/markdown")


@app.get("/api/cases")
def list_cases() -> list[dict[str, Any]]:
    return [public_case(case) for case in database.list_cases()]


@app.get("/api/cases/{case_id}/analyses")
def list_case_analyses(case_id: str) -> list[dict[str, Any]]:
    if not database.get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    return [public_analysis(run) for run in database.list_analyses_for_case(case_id)]


@app.post("/api/cases", status_code=201)
def create_case(payload: CaseCreate) -> dict[str, Any]:
    if not payload.name.strip():
        raise HTTPException(status_code=422, detail="Case name cannot be blank.")
    return public_case(database.create_case(payload.name))


@app.get("/api/cases/{case_id}")
def get_case(case_id: str) -> dict[str, Any]:
    case = database.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return public_case(case)


def resolve_run_id(case_id: str, requested_run_id: str | None) -> str | None:
    if not database.get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    if requested_run_id:
        run = database.get_analysis(requested_run_id)
        if not run or run["case_id"] != case_id:
            raise HTTPException(status_code=404, detail="Analysis run not found for this case")
        return requested_run_id
    runs = database.list_analyses_for_case(case_id)
    return runs[0]["run_id"] if runs else None


def public_evidence(record: dict[str, Any]) -> dict[str, Any]:
    result = {
        key: value for key, value in record.items() if key != "raw_output_path"
    }
    result["raw_source_url"] = (
        f"/api/analyses/{record['run_id']}/plugins/{record['source_plugin']}/stdout"
        if record.get("raw_output_path")
        else None
    )
    return result


@app.get("/api/cases/{case_id}/summary")
def get_case_summary(case_id: str, run_id: str | None = None) -> dict[str, Any]:
    selected_run = resolve_run_id(case_id, run_id)
    summary = database.case_summary(case_id, selected_run)
    system_records = (
        database.list_evidence(
            case_id,
            run_id=selected_run,
            evidence_type="system",
            page=1,
            page_size=500,
        )["items"]
        if selected_run
        else []
    )
    return {
        "case_id": case_id,
        "run_id": selected_run,
        "os_info": system_information(system_records),
        **summary,
    }


@app.get("/api/evidence")
def list_evidence(
    case_id: str,
    run_id: str | None = None,
    evidence_type: str | None = Query(default=None, alias="type"),
    pid: str | None = None,
    source_plugin: str | None = None,
    relationship_type: str | None = None,
    q: str | None = Query(default=None, max_length=250),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
) -> dict[str, Any]:
    selected_run = resolve_run_id(case_id, run_id)
    if selected_run is None:
        return {"items": [], "total": 0, "page": page, "page_size": page_size}
    result = database.list_evidence(
        case_id,
        run_id=selected_run,
        evidence_type=evidence_type,
        pid=pid,
        source_plugin=source_plugin,
        relationship_type=relationship_type,
        query=q,
        page=page,
        page_size=page_size,
    )
    result["items"] = [public_evidence(record) for record in result["items"]]
    return result


@app.get("/api/evidence/{evidence_id}")
def get_evidence(evidence_id: str) -> dict[str, Any]:
    record = database.get_evidence(evidence_id)
    if not record:
        raise HTTPException(status_code=404, detail="Evidence not found")
    relationships = database.list_relationships(
        record["case_id"], record["run_id"]
    )
    related = []
    for relationship in relationships:
        if evidence_id not in {
            relationship["source_evidence_id"],
            relationship["target_evidence_id"],
        }:
            continue
        other_id = (
            relationship["target_evidence_id"]
            if relationship["source_evidence_id"] == evidence_id
            else relationship["source_evidence_id"]
        )
        other = database.get_evidence(other_id)
        related.append(
            {
                **relationship,
                "related_evidence": public_evidence(other) if other else None,
            }
        )
    pid_linked_evidence = (
        [
            public_evidence(item)
            for item in database.list_evidence_by_pid(
                record["case_id"], record["run_id"], record["pid"]
            )
            if item["evidence_id"] != evidence_id
        ]
        if record["type"] == "process" and record.get("pid")
        else []
    )
    return {
        **public_evidence(record),
        "relationships": related,
        "timeline_events": database.list_events_for_evidence(evidence_id),
        "pid_linked_evidence": pid_linked_evidence,
    }


@app.get("/api/processes")
def list_processes(
    case_id: str,
    run_id: str | None = None,
    q: str | None = Query(default=None, max_length=250),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    selected_run = resolve_run_id(case_id, run_id)
    if selected_run is None:
        return {"items": [], "total": 0, "page": page, "page_size": page_size}
    result = database.list_evidence(
        case_id,
        run_id=selected_run,
        evidence_type="process",
        query=q,
        page=page,
        page_size=page_size,
    )
    result["items"] = [public_evidence(record) for record in result["items"]]
    return result


@app.get("/api/network")
def list_network(
    case_id: str,
    run_id: str | None = None,
    q: str | None = Query(default=None, max_length=250),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    selected_run = resolve_run_id(case_id, run_id)
    if selected_run is None:
        return {"items": [], "total": 0, "page": page, "page_size": page_size}
    result = database.list_evidence(
        case_id,
        run_id=selected_run,
        evidence_type="network",
        query=q,
        page=page,
        page_size=page_size,
    )
    result["items"] = [public_evidence(record) for record in result["items"]]
    return result


@app.get("/api/relationships")
def list_relationships(
    case_id: str,
    run_id: str | None = None,
    relationship_type: str | None = None,
    q: str | None = Query(default=None, max_length=250),
) -> list[dict[str, Any]]:
    selected_run = resolve_run_id(case_id, run_id)
    if selected_run is None:
        return []
    return database.list_relationships(
        case_id,
        selected_run,
        relationship_type=relationship_type,
        query=q,
    )


@app.get("/api/timeline")
def get_timeline(
    case_id: str,
    run_id: str | None = None,
    event_type: str | None = None,
    q: str | None = Query(default=None, max_length=250),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    selected_run = resolve_run_id(case_id, run_id)
    if selected_run is None:
        return {"items": [], "total": 0, "page": page, "page_size": page_size}
    events = database.list_events(case_id, selected_run, event_type, q)
    start = (page - 1) * page_size
    return {
        "items": events[start : start + page_size],
        "total": len(events),
        "page": page,
        "page_size": page_size,
    }


@app.get("/api/graph")
def get_graph(
    case_id: str,
    run_id: str | None = None,
    limit: int = Query(default=200, ge=1, le=500),
) -> dict[str, Any]:
    selected_run = resolve_run_id(case_id, run_id)
    if selected_run is None:
        return {"nodes": [], "edges": [], "truncated": False}
    result = database.list_evidence(
        case_id, run_id=selected_run, page=1, page_size=limit + 1
    )
    truncated = result["total"] > limit
    records = result["items"][:limit]
    evidence_models = [EvidenceRecord.model_validate(record) for record in records]
    relationships = database.list_relationships(case_id, selected_run)
    relationship_models = [
        RelationshipRecord.model_validate(relationship)
        for relationship in relationships
    ]
    graph = EvidenceGraphBuilder.build(evidence_models, relationship_models)
    payload = EvidenceGraphBuilder.to_payload(
        graph, node_limit=limit, edge_limit=limit * 4
    )
    payload["total_nodes"] = result["total"]
    payload["truncated"] = truncated or payload["truncated"].get("truncated", False)
    return payload


@app.get("/api/hypotheses")
def list_hypotheses(
    case_id: str,
    run_id: str | None = None,
) -> list[dict[str, Any]]:
    selected_run = resolve_run_id(case_id, run_id)
    if selected_run is None:
        return []
    return database.list_hypotheses(case_id, selected_run)


@app.get("/api/search")
def search_evidence(
    case_id: str,
    q: str = Query(min_length=1, max_length=250),
    run_id: str | None = None,
) -> dict[str, Any]:
    selected_run = resolve_run_id(case_id, run_id)
    if selected_run is None:
        return {"evidence": [], "relationships": []}
    records = database.list_evidence(
        case_id, run_id=selected_run, query=q, page=1, page_size=30
    )
    relationships = database.list_relationships(
        case_id, selected_run, query=q
    )[:30]
    return {
        "evidence": [public_evidence(record) for record in records["items"]],
        "evidence_total": records["total"],
        "relationships": relationships,
    }


@app.get("/api/report")
def download_report(
    case_id: str,
    run_id: str | None = None,
) -> PlainTextResponse:
    selected_run = resolve_run_id(case_id, run_id)
    if selected_run is None:
        raise HTTPException(status_code=409, detail="Run an analysis before generating a report.")
    run = database.get_analysis(selected_run)
    case = database.get_case(case_id)
    if not run or not case:
        raise HTTPException(status_code=404, detail="Case or analysis run not found")
    evidence = database.list_evidence(
        case_id, selected_run, page=1, page_size=100000
    )["items"]
    relationships = database.list_relationships(case_id, selected_run)
    events = database.list_events(case_id, selected_run)
    hypotheses = database.list_hypotheses(case_id, selected_run)
    report = generate_report(
        case,
        run,
        database.case_summary(case_id, selected_run),
        evidence,
        relationships,
        events,
        hypotheses,
    )
    return PlainTextResponse(
        report,
        media_type="text/markdown",
        headers={
            "Content-Disposition": (
                f'attachment; filename="CyberTrace_{case_id}_{selected_run}_report.md"'
            )
        },
    )


# ---------------------------------------------------------------------------
# Storage / ingestion endpoints (Phase 1)
# ---------------------------------------------------------------------------


class UploadSessionStart(BaseModel):
    case_id: str = Field(min_length=1, max_length=64)
    filename: str = Field(min_length=1, max_length=512)
    total_size: int | None = Field(default=None, ge=0)
    investigator_limit_gib: int | None = Field(default=None, ge=1, le=MAX_ADMIN_UPLOAD_LIMIT_GIB)


class MountedImportRequest(BaseModel):
    case_id: str = Field(min_length=1, max_length=64)
    source_path: str = Field(min_length=1, max_length=4096)
    copy_into_managed: bool = False
    expected_sha256: str | None = Field(default=None, max_length=128)


class HypothesisReviewUpdate(BaseModel):
    review_state: str = Field(pattern="^(unreviewed|confirmed|dismissed)$")


@app.get("/api/storage/config")
def storage_config() -> dict[str, Any]:
    return {
        "default_upload_limit_gib": DEFAULT_UPLOAD_LIMIT_GIB,
        "max_admin_upload_limit_gib": MAX_ADMIN_UPLOAD_LIMIT_GIB,
        "upload_chunk_size_bytes": UPLOAD_CHUNK_SIZE_BYTES,
        "effective_limit_bytes": effective_upload_limit_bytes(),
        "allowed_mount_roots": [str(p) for p in ALLOWED_MOUNT_ROOTS],
    }


@app.post("/api/storage/upload-session", status_code=201)
def start_upload_session(payload: UploadSessionStart) -> dict[str, Any]:
    try:
        return upload_service.start_session(
            payload.case_id,
            payload.filename,
            total_size=payload.total_size,
            investigator_limit_gib=payload.investigator_limit_gib,
        )
    except UploadSessionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except InsufficientSpaceError as exc:
        raise HTTPException(status_code=507, detail=str(exc)) from exc


@app.post("/api/storage/upload-chunk")
async def upload_chunk(
    request: Request,
    session_id: str = Form(...),
    is_last: bool = Form(False),
    offset: int | None = Form(None),
    chunk: UploadFile = File(...),
) -> dict[str, Any]:
    data = await chunk.read()
    try:
        return upload_service.write_chunk(
            session_id, data, is_last=is_last, offset=offset
        )
    except UploadSessionError as exc:
        status = 413 if "exceeds" in str(exc).lower() else 400
        raise HTTPException(status_code=status, detail=str(exc)) from exc
    except InsufficientSpaceError as exc:
        raise HTTPException(status_code=507, detail=str(exc)) from exc
    finally:
        await chunk.close()


@app.post("/api/storage/upload-abort")
def abort_upload(session_id: str = Form(...)) -> dict[str, str]:
    upload_service.abort_session(session_id)
    return {"status": "aborted", "session_id": session_id}


@app.post("/api/storage/import-mounted", status_code=201)
def import_mounted(payload: MountedImportRequest) -> dict[str, Any]:
    try:
        result = import_service.import_mounted(
            payload.case_id,
            payload.source_path,
            copy_into_managed=payload.copy_into_managed,
            expected_sha256=payload.expected_sha256,
        )
        return {
            "logical_image_id": result["logical_image_id"],
            "file_size_bytes": result["file_size_bytes"],
            "sha256_hash": result["sha256_hash"],
            "storage_type": result["storage_type"],
            "verification_status": result["verification_status"],
            "case": public_case(result["case"]),
        }
    except MountedImportError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except InsufficientSpaceError as exc:
        raise HTTPException(status_code=507, detail=str(exc)) from exc


@app.patch("/api/hypotheses/{hypothesis_id}/review")
def update_hypothesis_review(
    hypothesis_id: str, payload: HypothesisReviewUpdate
) -> dict[str, Any]:
    updated = database.update_hypothesis_review_state(
        hypothesis_id, payload.review_state
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Hypothesis not found")
    return updated


@app.post("/api/cases/{case_id}/image")
def upload_image(case_id: str, file: UploadFile = File(...)) -> dict[str, Any]:
    case = database.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    original_filename = Path((file.filename or "memory-image").replace("\\", "/")).name
    suffix = Path(original_filename).suffix[:12]
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    destination = RAW_DIR / f"{case_id}_{uuid4().hex}{suffix}"
    size = 0
    digest = hashlib.sha256()
    try:
        with destination.open("xb") as output:
            while chunk := file.file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Image exceeds the configured {MAX_UPLOAD_BYTES // (1024**3)} GiB upload limit.",
                    )
                digest.update(chunk)
                output.write(chunk)
        sha = digest.hexdigest()
        from backend.storage.image_store import ImageStore, new_logical_image_id

        logical_id = new_logical_image_id()
        ImageStore(database).register(
            case_id=case_id,
            storage_type="browser_upload",
            file_path=destination.resolve(),
            file_size_bytes=size,
            sha256_hash=sha,
            original_filename=original_filename,
            verification_status="verified",
            logical_image_id=logical_id,
        )
        updated = database.attach_image(
            case_id,
            original_filename,
            str(destination.resolve()),
            size,
            sha,
        )
        if not updated:
            raise HTTPException(status_code=404, detail="Case not found")
        return public_case(updated)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        file.file.close()


@app.post("/api/analyze", status_code=202)
def analyze(payload: AnalyzeRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
    case = database.get_case(payload.case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    if not case.get("stored_path") or not Path(case["stored_path"]).is_file():
        raise HTTPException(status_code=409, detail="Upload a memory image before starting analysis.")
    if not payload.plugins:
        raise HTTPException(status_code=422, detail="Select at least one plugin.")
    invalid_plugins = sorted(set(payload.plugins) - set(SUPPORTED_PLUGINS))
    if invalid_plugins:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported plugins: {', '.join(invalid_plugins)}",
        )
    if len(set(payload.plugins)) != len(payload.plugins):
        raise HTTPException(status_code=422, detail="Plugin selections must be unique.")
    run = database.create_analysis(
        payload.case_id,
        payload.plugins,
        image_path=case["stored_path"],
        image_filename=case.get("original_filename"),
        image_sha256=case.get("image_sha256"),
    )
    background_tasks.add_task(
        execute_analysis, run["run_id"], payload.case_id, case["stored_path"], payload.plugins
    )
    return public_analysis(run)


@app.get("/api/analyses/{run_id}")
def get_analysis(run_id: str) -> dict[str, Any]:
    run = database.get_analysis(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    return public_analysis(run)


@app.get("/api/analyses/{run_id}/plugins/{plugin}/{stream}")
def get_plugin_output(run_id: str, plugin: str, stream: str) -> FileResponse:
    stream_suffix = {"stdout": "stdout.txt", "stderr": "stderr.txt", "json": "json"}
    if plugin not in SUPPORTED_PLUGINS or stream not in stream_suffix:
        raise HTTPException(status_code=404, detail="Output not found")
    run = database.get_analysis(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    output = VOLATILITY_OUTPUT_DIR / run["case_id"] / run_id / (
        f"{plugin.replace('.', '_')}.{stream_suffix[stream]}"
    )
    if not output.is_file():
        raise HTTPException(status_code=404, detail="Plugin output is not available yet")
    if not output.resolve().is_relative_to(VOLATILITY_OUTPUT_DIR.resolve()):
        raise HTTPException(status_code=404, detail="Output not found")
    return FileResponse(output, media_type="text/plain", filename=output.name)