import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.timeline.engine import timeline_sort_key

SCHEMA_VERSION = 4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            existing_schema_version = connection.execute("PRAGMA user_version").fetchone()[0]
            if existing_schema_version > SCHEMA_VERSION:
                raise RuntimeError(
                    "Database schema is newer than this CyberTrace version supports."
                )
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    original_filename TEXT,
                    stored_path TEXT,
                    image_size_bytes INTEGER,
                    image_sha256 TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS analysis_runs (
                    run_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                    status TEXT NOT NULL,
                    requested_plugins_json TEXT NOT NULL,
                    plugin_results_json TEXT NOT NULL DEFAULT '[]',
                    image_path TEXT,
                    image_filename TEXT,
                    image_sha256 TEXT,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_analysis_runs_case
                    ON analysis_runs(case_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
                    type TEXT NOT NULL,
                    source_plugin TEXT NOT NULL,
                    source_row INTEGER NOT NULL,
                    pid TEXT,
                    ppid TEXT,
                    process_name TEXT,
                    timestamp TEXT,
                    artifact_json TEXT NOT NULL,
                    raw_output_path TEXT,
                    confidence TEXT NOT NULL CHECK (confidence = 'observed'),
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_evidence_case_run_type
                    ON evidence(case_id, run_id, type);
                CREATE INDEX IF NOT EXISTS idx_evidence_case_run_pid
                    ON evidence(case_id, run_id, pid);
                CREATE INDEX IF NOT EXISTS idx_evidence_source_plugin
                    ON evidence(case_id, run_id, source_plugin);

                CREATE TABLE IF NOT EXISTS relationships (
                    relationship_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
                    source_evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id) ON DELETE CASCADE,
                    target_evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id) ON DELETE CASCADE,
                    relationship_type TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    source_plugin TEXT NOT NULL,
                    matched_fields_json TEXT NOT NULL DEFAULT '{}',
                    confidence TEXT NOT NULL CHECK (confidence = 'correlated'),
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_relationships_case_run
                    ON relationships(case_id, run_id, relationship_type);

                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id) ON DELETE CASCADE,
                    timestamp TEXT,
                    event_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    related_pid TEXT,
                    source_plugin TEXT NOT NULL,
                    confidence TEXT NOT NULL CHECK (confidence = 'observed'),
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_case_run_timestamp
                    ON events(case_id, run_id, timestamp);

                CREATE TABLE IF NOT EXISTS hypotheses (
                    hypothesis_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    rationale TEXT NOT NULL,
                    limitations_json TEXT NOT NULL,
                    supporting_evidence_ids_json TEXT NOT NULL,
                    supporting_relationship_ids_json TEXT NOT NULL,
                    steps_json TEXT NOT NULL,
                    confidence TEXT NOT NULL CHECK (confidence = 'hypothesis'),
                    review_state TEXT NOT NULL DEFAULT 'unreviewed'
                        CHECK (review_state IN ('unreviewed', 'confirmed', 'dismissed')),
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_hypotheses_case_run
                    ON hypotheses(case_id, run_id);

                CREATE TABLE IF NOT EXISTS image_storage (
                    logical_image_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                    storage_type TEXT NOT NULL
                        CHECK (storage_type IN ('browser_upload', 'mounted_import')),
                    file_path TEXT NOT NULL,
                    file_size_bytes INTEGER NOT NULL,
                    sha256_hash TEXT NOT NULL,
                    verification_status TEXT NOT NULL DEFAULT 'pending'
                        CHECK (verification_status IN ('pending', 'verified', 'failed')),
                    original_filename TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_image_storage_case
                    ON image_storage(case_id, created_at DESC);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_image_storage_sha
                    ON image_storage(sha256_hash, case_id);
                """
            )
            # Upgrade databases created by the Day 1 foundation without replacing
            # existing cases or analysis history.
            analysis_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(analysis_runs)").fetchall()
            }
            for name in ("image_path", "image_filename", "image_sha256"):
                if name not in analysis_columns:
                    connection.execute(f"ALTER TABLE analysis_runs ADD COLUMN {name} TEXT")
            relationship_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(relationships)").fetchall()
            }
            if "matched_fields_json" not in relationship_columns:
                connection.execute(
                    "ALTER TABLE relationships ADD COLUMN matched_fields_json TEXT NOT NULL DEFAULT '{}'"
                )
            hyp_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(hypotheses)").fetchall()
            }
            if "review_state" not in hyp_columns:
                connection.execute(
                    "ALTER TABLE hypotheses ADD COLUMN review_state TEXT NOT NULL DEFAULT 'unreviewed'"
                )
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def create_case(self, name: str) -> dict[str, Any]:
        now = utc_now()
        case = {
            "case_id": f"CT-{uuid.uuid4().hex[:10].upper()}",
            "name": name.strip(),
            "created_at": now,
            "updated_at": now,
        }
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO cases (case_id, name, created_at, updated_at)
                VALUES (:case_id, :name, :created_at, :updated_at)
                """,
                case,
            )
        return case

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM cases WHERE case_id = ?", (case_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_cases(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM cases ORDER BY created_at DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def attach_image(
        self,
        case_id: str,
        filename: str,
        stored_path: str,
        size_bytes: int,
        sha256: str,
    ) -> dict[str, Any] | None:
        with self.connect() as connection:
            result = connection.execute(
                """
                UPDATE cases
                SET original_filename = ?, stored_path = ?, image_size_bytes = ?,
                    image_sha256 = ?, updated_at = ?
                WHERE case_id = ?
                """,
                (filename, stored_path, size_bytes, sha256, utc_now(), case_id),
            )
        return self.get_case(case_id) if result.rowcount else None

    def create_image_storage(
        self,
        *,
        logical_image_id: str,
        case_id: str,
        storage_type: str,
        file_path: str,
        file_size_bytes: int,
        sha256_hash: str,
        verification_status: str = "verified",
        original_filename: str | None = None,
    ) -> dict[str, Any]:
        now = utc_now()
        row = {
            "logical_image_id": logical_image_id,
            "case_id": case_id,
            "storage_type": storage_type,
            "file_path": file_path,
            "file_size_bytes": file_size_bytes,
            "sha256_hash": sha256_hash,
            "verification_status": verification_status,
            "original_filename": original_filename,
            "created_at": now,
        }
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO image_storage (
                    logical_image_id, case_id, storage_type, file_path,
                    file_size_bytes, sha256_hash, verification_status,
                    original_filename, created_at
                ) VALUES (
                    :logical_image_id, :case_id, :storage_type, :file_path,
                    :file_size_bytes, :sha256_hash, :verification_status,
                    :original_filename, :created_at
                )
                """,
                row,
            )
        return row

    def get_image_storage(self, logical_image_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM image_storage WHERE logical_image_id = ?",
                (logical_image_id,),
            ).fetchone()
        return dict(row) if row else None

    def get_image_storage_for_case(self, case_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM image_storage
                WHERE case_id = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (case_id,),
            ).fetchone()
        return dict(row) if row else None

    def update_hypothesis_review_state(
        self, hypothesis_id: str, review_state: str
    ) -> dict[str, Any] | None:
        if review_state not in ("unreviewed", "confirmed", "dismissed"):
            raise ValueError(f"Invalid review_state: {review_state}")
        with self.connect() as connection:
            result = connection.execute(
                "UPDATE hypotheses SET review_state = ? WHERE hypothesis_id = ?",
                (review_state, hypothesis_id),
            )
            if result.rowcount == 0:
                return None
            row = connection.execute(
                "SELECT * FROM hypotheses WHERE hypothesis_id = ?",
                (hypothesis_id,),
            ).fetchone()
        return self._hydrate_hypothesis(dict(row)) if row else None

    def create_analysis(
        self,
        case_id: str,
        plugins: list[str],
        image_path: str | None = None,
        image_filename: str | None = None,
        image_sha256: str | None = None,
    ) -> dict[str, Any]:
        run = {
            "run_id": f"RUN-{uuid.uuid4().hex[:12].upper()}",
            "case_id": case_id,
            "status": "queued",
            "requested_plugins_json": json.dumps(plugins),
            "plugin_results_json": json.dumps(
                [{"plugin": plugin, "status": "queued"} for plugin in plugins]
            ),
            "image_path": image_path,
            "image_filename": image_filename,
            "image_sha256": image_sha256,
            "created_at": utc_now(),
        }
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO analysis_runs
                    (run_id, case_id, status, requested_plugins_json,
                     plugin_results_json, image_path, image_filename, image_sha256, created_at)
                VALUES
                    (:run_id, :case_id, :status, :requested_plugins_json,
                     :plugin_results_json, :image_path, :image_filename, :image_sha256, :created_at)
                """,
                run,
            )
        return self.get_analysis(run["run_id"]) or run

    def get_analysis(self, run_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM analysis_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["requested_plugins"] = json.loads(result.pop("requested_plugins_json"))
        result["plugin_results"] = json.loads(result.pop("plugin_results_json"))
        return result

    def list_analyses_for_case(self, case_id: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT run_id FROM analysis_runs
                WHERE case_id = ?
                ORDER BY created_at DESC
                """,
                (case_id,),
            ).fetchall()
        return [
            analysis
            for row in rows
            if (analysis := self.get_analysis(row["run_id"])) is not None
        ]

    def store_derived_data(
        self,
        run_id: str,
        evidence: list[dict[str, Any]],
        relationships: list[dict[str, Any]],
        events: list[dict[str, Any]],
        hypotheses: list[dict[str, Any]],
    ) -> None:
        run = self.get_analysis(run_id)
        if not run:
            raise ValueError(f"Analysis run not found: {run_id}")
        case_id = run["case_id"]
        created_at = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM hypotheses WHERE run_id = ?", (run_id,))
            connection.execute("DELETE FROM events WHERE run_id = ?", (run_id,))
            connection.execute("DELETE FROM relationships WHERE run_id = ?", (run_id,))
            connection.execute("DELETE FROM evidence WHERE run_id = ?", (run_id,))

            for record in evidence:
                connection.execute(
                    """
                    INSERT INTO evidence
                      (evidence_id, case_id, run_id, type, source_plugin, source_row,
                       pid, ppid, process_name, timestamp, artifact_json,
                       raw_output_path, confidence, created_at)
                    VALUES
                      (:evidence_id, :case_id, :run_id, :type, :source_plugin, :source_row,
                       :pid, :ppid, :process_name, :timestamp, :artifact_json,
                       :raw_output_path, :confidence, :created_at)
                    """,
                    {
                        **record,
                        "case_id": case_id,
                        "run_id": run_id,
                        "artifact_json": json.dumps(record.get("artifact") or {}),
                        "created_at": created_at,
                    },
                )

            for relation in relationships:
                connection.execute(
                    """
                    INSERT INTO relationships
                      (relationship_id, case_id, run_id, source_evidence_id,
                       target_evidence_id, relationship_type, reason, source_plugin,
                       matched_fields_json, confidence, created_at)
                    VALUES
                      (:relationship_id, :case_id, :run_id, :source_evidence_id,
                       :target_evidence_id, :relationship_type, :reason, :source_plugin,
                       :matched_fields_json, :confidence, :created_at)
                    """,
                    {
                        **relation,
                        "case_id": case_id,
                        "run_id": run_id,
                        "matched_fields_json": json.dumps(
                            relation.get("matched_fields") or {}
                        ),
                        "created_at": created_at,
                    },
                )

            for event in events:
                connection.execute(
                    """
                    INSERT INTO events
                      (event_id, case_id, run_id, evidence_id, timestamp, event_type,
                       description, related_pid, source_plugin, confidence, created_at)
                    VALUES
                      (:event_id, :case_id, :run_id, :evidence_id, :timestamp, :event_type,
                       :description, :related_pid, :source_plugin, :confidence, :created_at)
                    """,
                    {**event, "case_id": case_id, "run_id": run_id, "created_at": created_at},
                )

            for hypothesis in hypotheses:
                connection.execute(
                    """
                    INSERT INTO hypotheses
                      (hypothesis_id, case_id, run_id, title, description, rationale,
                       limitations_json, supporting_evidence_ids_json,
                       supporting_relationship_ids_json, steps_json, confidence,
                       review_state, created_at)
                    VALUES
                      (:hypothesis_id, :case_id, :run_id, :title, :description, :rationale,
                       :limitations_json, :supporting_evidence_ids_json,
                       :supporting_relationship_ids_json, :steps_json, :confidence,
                       :review_state, :created_at)
                    """,
                    {
                        "hypothesis_id": hypothesis["hypothesis_id"],
                        "case_id": case_id,
                        "run_id": run_id,
                        "title": hypothesis["title"],
                        "description": hypothesis["description"],
                        "rationale": hypothesis["rationale"],
                        "limitations_json": json.dumps(hypothesis["limitations"]),
                        "supporting_evidence_ids_json": json.dumps(
                            hypothesis["supporting_evidence_ids"]
                        ),
                        "supporting_relationship_ids_json": json.dumps(
                            hypothesis["supporting_relationship_ids"]
                        ),
                        "steps_json": json.dumps(hypothesis["steps"]),
                        "confidence": hypothesis["confidence"],
                        "review_state": hypothesis.get("review_state", "unreviewed"),
                        "created_at": created_at,
                    },
                )

    def _decode_evidence(self, row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
        result = dict(row)
        result["artifact"] = json.loads(result.pop("artifact_json"))
        return result

    def _hydrate_hypothesis(self, result: dict[str, Any]) -> dict[str, Any]:
        if "limitations_json" in result:
            result["limitations"] = json.loads(result.pop("limitations_json"))
        if "supporting_evidence_ids_json" in result:
            result["supporting_evidence_ids"] = json.loads(
                result.pop("supporting_evidence_ids_json")
            )
        if "supporting_relationship_ids_json" in result:
            result["supporting_relationship_ids"] = json.loads(
                result.pop("supporting_relationship_ids_json")
            )
        if "steps_json" in result:
            result["steps"] = json.loads(result.pop("steps_json"))
        result.setdefault("review_state", "unreviewed")
        return result

    def list_evidence(
        self,
        case_id: str,
        run_id: str | None = None,
        evidence_type: str | None = None,
        pid: str | None = None,
        source_plugin: str | None = None,
        relationship_type: str | None = None,
        query: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, Any]:
        clauses = ["e.case_id = ?"]
        params: list[Any] = [case_id]
        if run_id:
            clauses.append("e.run_id = ?")
            params.append(run_id)
        if evidence_type:
            clauses.append("e.type = ?")
            params.append(evidence_type)
        if pid:
            clauses.append("(e.pid = ? OR e.ppid = ?)")
            params.extend([pid, pid])
        if source_plugin:
            clauses.append("e.source_plugin = ?")
            params.append(source_plugin)
        if relationship_type:
            clauses.append(
                """
                EXISTS (
                    SELECT 1 FROM relationships r
                    WHERE r.run_id = e.run_id
                      AND r.relationship_type = ?
                      AND (r.source_evidence_id = e.evidence_id
                           OR r.target_evidence_id = e.evidence_id)
                )
                """
            )
            params.append(relationship_type)
        if query:
            clauses.append(
                """
                (e.evidence_id LIKE ? OR e.pid LIKE ? OR e.ppid LIKE ?
                 OR e.process_name LIKE ? OR e.source_plugin LIKE ? OR e.artifact_json LIKE ?)
                """
            )
            params.extend([f"%{query}%"] * 6)
        where = " AND ".join(clauses)
        with self.connect() as connection:
            total = connection.execute(
                f"SELECT COUNT(*) FROM evidence e WHERE {where}", params
            ).fetchone()[0]
            rows = connection.execute(
                f"""
                SELECT e.* FROM evidence e
                WHERE {where}
                ORDER BY e.source_plugin, e.source_row, e.evidence_id
                LIMIT ? OFFSET ?
                """,
                [*params, page_size, (page - 1) * page_size],
            ).fetchall()
        return {
            "items": [self._decode_evidence(row) for row in rows],
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    def get_evidence(self, evidence_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,)
            ).fetchone()
        return self._decode_evidence(row) if row else None

    def list_relationships(
        self,
        case_id: str,
        run_id: str | None = None,
        relationship_type: str | None = None,
        query: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses = ["case_id = ?"]
        params: list[Any] = [case_id]
        if run_id:
            clauses.append("run_id = ?")
            params.append(run_id)
        if relationship_type:
            clauses.append("relationship_type = ?")
            params.append(relationship_type)
        if query:
            clauses.append(
                "(relationship_id LIKE ? OR relationship_type LIKE ? OR reason LIKE ?)"
            )
            params.extend([f"%{query}%"] * 3)
        with self.connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM relationships WHERE {' AND '.join(clauses)} ORDER BY relationship_id",
                params,
            ).fetchall()
        relationships = [dict(row) for row in rows]
        for relationship in relationships:
            relationship["matched_fields"] = json.loads(
                relationship.pop("matched_fields_json", "{}")
            )
        return relationships

    def list_evidence_by_pid(
        self,
        case_id: str,
        run_id: str,
        pid: str,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM evidence
                WHERE case_id = ? AND run_id = ? AND pid = ?
                ORDER BY source_plugin, source_row, evidence_id
                LIMIT ?
                """,
                (case_id, run_id, pid, limit),
            ).fetchall()
        return [self._decode_evidence(row) for row in rows]

    def list_events_for_evidence(self, evidence_id: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM events WHERE evidence_id = ?",
                (evidence_id,),
            ).fetchall()
        events = [dict(row) for row in rows]
        events.sort(key=timeline_sort_key)
        return events

    def list_events(
        self,
        case_id: str,
        run_id: str | None = None,
        event_type: str | None = None,
        query: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses = ["case_id = ?"]
        params: list[Any] = [case_id]
        if run_id:
            clauses.append("run_id = ?")
            params.append(run_id)
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if query:
            clauses.append(
                "(event_id LIKE ? OR evidence_id LIKE ? OR description LIKE ? OR related_pid LIKE ?)"
            )
            params.extend([f"%{query}%"] * 4)
        with self.connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM events WHERE {' AND '.join(clauses)}",
                params,
            ).fetchall()
        events = [dict(row) for row in rows]
        events.sort(key=timeline_sort_key)
        return events

    def list_hypotheses(self, case_id: str, run_id: str | None = None) -> list[dict[str, Any]]:
        clauses = ["case_id = ?"]
        params: list[Any] = [case_id]
        if run_id:
            clauses.append("run_id = ?")
            params.append(run_id)
        with self.connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM hypotheses WHERE {' AND '.join(clauses)} ORDER BY hypothesis_id",
                params,
            ).fetchall()
        return [self._hydrate_hypothesis(dict(row)) for row in rows]

    def case_summary(self, case_id: str, run_id: str | None = None) -> dict[str, Any]:
        clauses = ["case_id = ?"]
        params: list[Any] = [case_id]
        if run_id:
            clauses.append("run_id = ?")
            params.append(run_id)
        where = " AND ".join(clauses)
        with self.connect() as connection:
            type_rows = connection.execute(
                f"SELECT type, COUNT(*) AS count FROM evidence WHERE {where} GROUP BY type",
                params,
            ).fetchall()
            process_count = connection.execute(
                f"""
                SELECT COUNT(DISTINCT pid) + SUM(CASE WHEN pid IS NULL THEN 1 ELSE 0 END)
                FROM evidence
                WHERE {where} AND type = 'process'
                """,
                params,
            ).fetchone()[0] or 0
            relationship_count = connection.execute(
                f"SELECT COUNT(*) FROM relationships WHERE {where}", params
            ).fetchone()[0]
            event_count = connection.execute(
                f"SELECT COUNT(*) FROM events WHERE {where}", params
            ).fetchone()[0]
            hypothesis_count = connection.execute(
                f"SELECT COUNT(*) FROM hypotheses WHERE {where}", params
            ).fetchone()[0]
        counts = {row["type"]: row["count"] for row in type_rows}
        return {
            "evidence_count": sum(counts.values()),
            "process_count": process_count,
            "network_count": counts.get("network", 0),
            "dll_count": counts.get("dll", 0),
            "command_count": counts.get("command", 0),
            "memory_findings_count": counts.get("memory", 0),
            "system_count": counts.get("system", 0),
            "relationship_count": relationship_count,
            "event_count": event_count,
            "hypothesis_count": hypothesis_count,
            "by_type": counts,
        }

    def update_analysis(
        self,
        run_id: str,
        *,
        status: str | None = None,
        plugin_results: list[dict[str, Any]] | None = None,
        error: str | None = None,
        started_at: str | None = None,
        completed_at: str | None = None,
    ) -> None:
        fields: list[str] = []
        values: list[Any] = []
        if status is not None:
            fields.append("status = ?")
            values.append(status)
        if plugin_results is not None:
            fields.append("plugin_results_json = ?")
            values.append(json.dumps(plugin_results))
        if error is not None:
            fields.append("error = ?")
            values.append(error)
        if started_at is not None:
            fields.append("started_at = ?")
            values.append(started_at)
        if completed_at is not None:
            fields.append("completed_at = ?")
            values.append(completed_at)
        if not fields:
            return
        values.append(run_id)
        with self.connect() as connection:
            connection.execute(
                f"UPDATE analysis_runs SET {', '.join(fields)} WHERE run_id = ?",
                values,
            )