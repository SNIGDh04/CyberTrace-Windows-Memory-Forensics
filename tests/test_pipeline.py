import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from backend.correlation.engine import CorrelationEngine
from backend.database import Database
from backend.evidence.normalizer import normalize_plugin_output
from backend.pipeline import process_analysis_outputs
from backend.reconstruction.graph_builder import EvidenceGraphBuilder
from backend.reconstruction.hypothesis import HypothesisEngine
from backend.timeline.engine import TimelineEngine


CASE_ID = "CT-TEST000001"
RUN_ID = "RUN-TEST000001"


def normalize(plugin, row, sequence=1):
    return normalize_plugin_output(
        {"columns": list(row), "rows": [list(row.values())]},
        case_id=CASE_ID,
        run_id=RUN_ID,
        plugin=plugin,
        raw_output_path=f"/test/{plugin}.stdout.txt",
        first_sequence=sequence,
    )


class NormalizerTests(unittest.TestCase):
    def test_process_table_preserves_row_and_extracts_join_fields(self):
        records = normalize(
            "windows.pslist",
            {
                "PID": 1300,
                "PPID": 900,
                "ImageFileName": "powershell.exe",
                "CreateTime": "2024-02-03T04:05:06+00:00",
            },
        )

        self.assertEqual(len(records), 1)
        process = records[0]
        self.assertEqual(process.type, "process")
        self.assertEqual(process.pid, "1300")
        self.assertEqual(process.ppid, "900")
        self.assertEqual(process.process_name, "powershell.exe")
        self.assertEqual(process.timestamp, "2024-02-03T04:05:06+00:00")
        self.assertEqual(process.artifact["PID"], 1300)
        self.assertEqual(process.confidence, "observed")

    def test_empty_and_unknown_fields_do_not_create_fake_timestamps(self):
        records = normalize(
            "windows.netscan",
            {
                "PID": "-",
                "ForeignAddr": "203.0.113.9",
                "ForeignPort": 443,
                "CreateTime": "-",
            },
        )

        self.assertIsNone(records[0].pid)
        self.assertIsNone(records[0].timestamp)
        self.assertEqual(records[0].type, "network")

    def test_identifiers_include_the_run_scope(self):
        first = normalize(
            "windows.pslist",
            {"PID": 1, "ImageFileName": "one.exe"},
        )[0]
        second = normalize_plugin_output(
            {"columns": ["PID", "ImageFileName"], "rows": [[1, "one.exe"]]},
            case_id=CASE_ID,
            run_id="RUN-OTHER000001",
            plugin="windows.pslist",
            raw_output_path=None,
        )[0]
        self.assertNotEqual(first.evidence_id, second.evidence_id)
        self.assertIn(RUN_ID, first.evidence_id)
        self.assertIn("RUN-OTHER000001", second.evidence_id)


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.records = []
        self.records += normalize(
            "windows.pstree",
            {"PID": 900, "PPID": 4, "ImageFileName": "explorer.exe"},
            1,
        )
        self.records += normalize(
            "windows.pstree",
            {"PID": 1300, "PPID": 900, "ImageFileName": "powershell.exe"},
            2,
        )
        self.records += normalize(
            "windows.cmdline",
            {"PID": 1300, "Name": "powershell.exe", "Args": "powershell.exe -File review.ps1"},
            3,
        )
        self.records += normalize(
            "windows.netscan",
            {
                "PID": 1300,
                "Owner": "powershell.exe",
                "ForeignAddr": "203.0.113.9",
                "ForeignPort": 443,
            },
            4,
        )
        self.records += normalize(
            "windows.dlllist",
            {"PID": 1300, "Name": "example.dll", "Path": "C:\\Windows\\example.dll"},
            5,
        )

    def test_all_deterministic_relationships_keep_reasons_and_sources(self):
        relationships = CorrelationEngine.correlate(CASE_ID, RUN_ID, self.records)
        types = {relationship.relationship_type for relationship in relationships}

        self.assertEqual(
            types,
            {
                "PARENT_CHILD",
                "PROCESS_EXECUTED_WITH_COMMAND",
                "PROCESS_CONNECTS_TO",
                "PROCESS_LOADS_DLL",
            },
        )
        self.assertTrue(all(relationship.reason for relationship in relationships))
        self.assertTrue(all(relationship.source_plugin for relationship in relationships))
        self.assertTrue(all(relationship.confidence == "correlated" for relationship in relationships))
        by_type = {item.relationship_type: item for item in relationships}
        self.assertEqual(
            by_type["PARENT_CHILD"].matched_fields,
            {"child.ppid": "900", "parent.pid": "900"},
        )
        self.assertEqual(
            by_type["PROCESS_CONNECTS_TO"].matched_fields,
            {"process.pid": "1300", "network.pid": "1300"},
        )

    def test_no_relationship_is_created_when_the_pid_join_is_missing(self):
        evidence = normalize(
            "windows.netscan",
            {"Owner": "unknown.exe", "ForeignAddr": "203.0.113.9", "ForeignPort": 443},
        )
        self.assertEqual(CorrelationEngine.correlate(CASE_ID, RUN_ID, evidence), [])

    def test_graph_edges_retain_explainability_fields(self):
        relationships = CorrelationEngine.correlate(CASE_ID, RUN_ID, self.records)
        graph = EvidenceGraphBuilder.build(self.records, relationships)

        self.assertEqual(graph.number_of_nodes(), len(self.records))
        self.assertTrue(graph.number_of_edges() >= 4)
        edge = next(iter(graph.edges(data=True)))[2]
        self.assertTrue(edge["relationship_id"].startswith("REL-"))
        self.assertTrue(edge["reason"])
        self.assertTrue(edge["source_plugin"])


class TimelineAndHypothesisTests(unittest.TestCase):
    def test_timeline_keeps_untimed_events_without_inventing_dates(self):
        evidence = []
        evidence += normalize(
            "windows.pslist",
            {
                "PID": 2,
                "PPID": 1,
                "ImageFileName": "later.exe",
                "CreateTime": "2024-02-03T04:05:07+00:00",
            },
            1,
        )
        evidence += normalize(
            "windows.pslist",
            {
                "PID": 1,
                "PPID": 0,
                "ImageFileName": "earlier.exe",
                "CreateTime": "2024-02-03T04:05:06+00:00",
            },
            2,
        )
        evidence += normalize(
            "windows.pslist",
            {"PID": 3, "PPID": 1, "ImageFileName": "untimed.exe"},
            3,
        )

        events = TimelineEngine.build_events(CASE_ID, RUN_ID, evidence)

        self.assertEqual(events[0].related_pid, "1")
        self.assertEqual(events[1].related_pid, "2")
        self.assertIsNone(events[2].timestamp)
        self.assertEqual(events[2].event_type, "Process observation")

    def test_possible_sequence_requires_command_or_child_and_network_links(self):
        evidence = []
        evidence += normalize(
            "windows.pslist",
            {"PID": 1300, "PPID": 900, "ImageFileName": "powershell.exe"},
            1,
        )
        evidence += normalize(
            "windows.cmdline",
            {"PID": 1300, "Args": "powershell.exe -File review.ps1"},
            2,
        )
        evidence += normalize(
            "windows.netscan",
            {"PID": 1300, "ForeignAddr": "203.0.113.9", "ForeignPort": 443},
            3,
        )
        relationships = CorrelationEngine.correlate(CASE_ID, RUN_ID, evidence)
        hypotheses = HypothesisEngine.generate(CASE_ID, RUN_ID, evidence, relationships)

        self.assertEqual(len(hypotheses), 1)
        hypothesis = hypotheses[0]
        self.assertEqual(hypothesis.title, "Possible Attack Sequence")
        self.assertIn("not a compromise verdict", hypothesis.rationale)
        self.assertTrue(hypothesis.supporting_evidence_ids)
        self.assertTrue(hypothesis.supporting_relationship_ids)
        self.assertTrue(hypothesis.limitations)

    def test_network_activity_alone_does_not_generate_a_hypothesis(self):
        evidence = normalize(
            "windows.pslist",
            {"PID": 1300, "ImageFileName": "process.exe"},
        )
        evidence += normalize(
            "windows.netscan",
            {"PID": 1300, "ForeignAddr": "203.0.113.9", "ForeignPort": 443},
            2,
        )
        relationships = CorrelationEngine.correlate(CASE_ID, RUN_ID, evidence)
        self.assertEqual(
            HypothesisEngine.generate(CASE_ID, RUN_ID, evidence, relationships),
            [],
        )


class PersistedPipelineTests(unittest.TestCase):
    def test_plugin_rows_flow_through_storage_with_run_image_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = Database(root / "cybertrace.sqlite3")
            with database.connect() as connection:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 4)
            case = database.create_case("Pipeline fixture")
            run = database.create_analysis(
                case["case_id"],
                ["windows.pslist", "windows.cmdline", "windows.netscan"],
                image_path=str(root / "capture.raw"),
                image_filename="capture.raw",
                image_sha256="a" * 64,
            )
            fixtures = {
                "windows.pslist": {
                    "columns": ["PID", "PPID", "ImageFileName", "CreateTime"],
                    "rows": [[1300, 900, "powershell.exe", "2024-02-03T04:05:06Z"]],
                },
                "windows.cmdline": {
                    "columns": ["PID", "Name", "Args"],
                    "rows": [[1300, "powershell.exe", "powershell.exe -File review.ps1"]],
                },
                "windows.netscan": {
                    "columns": ["PID", "Owner", "ForeignAddr", "ForeignPort"],
                    "rows": [[1300, "powershell.exe", "203.0.113.9", 443]],
                },
            }
            plugin_results = []
            for plugin, payload in fixtures.items():
                stdout = root / f"{plugin}.stdout.txt"
                structured = root / f"{plugin}.json"
                stdout.write_text(json.dumps(payload), encoding="utf-8")
                structured.write_text(json.dumps(payload), encoding="utf-8")
                plugin_results.append(
                    {
                        "plugin": plugin,
                        "status": "completed",
                        "stdout_path": str(stdout),
                        "structured_output_path": str(structured),
                    }
                )

            result = process_analysis_outputs(
                database,
                run["run_id"],
                case["case_id"],
                plugin_results,
            )
            summary = database.case_summary(case["case_id"], run["run_id"])
            saved_run = database.get_analysis(run["run_id"])
            evidence = database.list_evidence(case["case_id"], run["run_id"])

            self.assertEqual(result["processing_errors"], [])
            self.assertEqual(result["evidence_count"], 3)
            self.assertEqual(result["relationship_count"], 2)
            self.assertEqual(result["event_count"], 3)
            self.assertEqual(result["hypothesis_count"], 1)
            self.assertEqual(summary["evidence_count"], 3)
            self.assertEqual(summary["hypothesis_count"], 1)
            self.assertEqual(saved_run["image_sha256"], "a" * 64)
            self.assertEqual(saved_run["image_filename"], "capture.raw")
            self.assertTrue(evidence["items"][0]["raw_output_path"].endswith(".stdout.txt"))

            # Reprocessing a run replaces its derived records instead of duplicating them.
            process_analysis_outputs(database, run["run_id"], case["case_id"], plugin_results)
            self.assertEqual(database.case_summary(case["case_id"], run["run_id"]), summary)


class DatabaseMigrationTests(unittest.TestCase):
    def test_day_one_database_is_upgraded_without_losing_analysis_history(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.sqlite3"
            with sqlite3.connect(path) as connection:
                connection.executescript(
                    """
                    CREATE TABLE cases (
                        case_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        original_filename TEXT,
                        stored_path TEXT,
                        image_size_bytes INTEGER,
                        image_sha256 TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    CREATE TABLE analysis_runs (
                        run_id TEXT PRIMARY KEY,
                        case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                        status TEXT NOT NULL,
                        requested_plugins_json TEXT NOT NULL,
                        plugin_results_json TEXT NOT NULL DEFAULT '[]',
                        error TEXT,
                        created_at TEXT NOT NULL,
                        started_at TEXT,
                        completed_at TEXT
                    );
                    CREATE TABLE relationships (
                        relationship_id TEXT PRIMARY KEY,
                        case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                        run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
                        source_evidence_id TEXT NOT NULL,
                        target_evidence_id TEXT NOT NULL,
                        relationship_type TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        source_plugin TEXT NOT NULL,
                        confidence TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );
                    INSERT INTO cases (case_id, name, created_at, updated_at)
                    VALUES ('CT-LEGACY', 'Legacy case', '2024-01-01', '2024-01-01');
                    INSERT INTO analysis_runs
                      (run_id, case_id, status, requested_plugins_json,
                       plugin_results_json, created_at)
                    VALUES
                      ('RUN-LEGACY', 'CT-LEGACY', 'failed', '["windows.pslist"]',
                       '[{"plugin":"windows.pslist","status":"failed"}]', '2024-01-01');
                    """
                )

            database = Database(path)
            preserved = database.get_analysis("RUN-LEGACY")
            with database.connect() as connection:
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                columns = {
                    row["name"]
                    for row in connection.execute("PRAGMA table_info(analysis_runs)")
                }

            self.assertEqual(version, 4)
            self.assertTrue({"image_path", "image_filename", "image_sha256"} <= columns)
            self.assertEqual(preserved["case_id"], "CT-LEGACY")
            self.assertEqual(preserved["status"], "failed")
            self.assertEqual(preserved["requested_plugins"], ["windows.pslist"])
            self.assertIn(
                "matched_fields_json",
                {
                    row["name"]
                    for row in connection.execute("PRAGMA table_info(relationships)")
                },
            )


if __name__ == "__main__":
    unittest.main()