import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend import app as app_module
from backend.database import Database
from backend.pipeline import process_analysis_outputs


class EvidenceApiPipelineTests(unittest.TestCase):
    def test_normalized_evidence_and_provenance_are_queryable_through_api_routes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_root = root / "volatility"
            database = Database(root / "cybertrace.sqlite3")
            case = database.create_case("API evidence fixture")
            run = database.create_analysis(
                case["case_id"],
                [
                    "windows.info",
                    "windows.pslist",
                    "windows.cmdline",
                    "windows.netscan",
                    "windows.dlllist",
                    "windows.malfind",
                ],
                image_path=str(root / "capture.raw"),
                image_filename="capture.raw",
                image_sha256="b" * 64,
            )
            payloads = {
                "windows.info": {
                    "columns": ["Variable", "Value"],
                    "rows": [["OS", "Windows"]],
                },
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
                "windows.dlllist": {
                    "columns": ["PID", "Name", "Path"],
                    "rows": [[1300, "powershell.exe", "C:\\Windows\\example.dll"]],
                },
                "windows.malfind": {
                    "columns": ["PID", "Process", "Protection"],
                    "rows": [[1300, "powershell.exe", "PAGE_EXECUTE_READWRITE"]],
                },
            }
            plugin_results = []
            run_output_dir = output_root / case["case_id"] / run["run_id"]
            run_output_dir.mkdir(parents=True)
            for plugin, payload in payloads.items():
                safe_name = plugin.replace(".", "_")
                stdout_path = run_output_dir / f"{safe_name}.stdout.txt"
                structured_path = run_output_dir / f"{safe_name}.json"
                stdout_path.write_text(
                    f"Raw output for {plugin}\n", encoding="utf-8"
                )
                structured_path.write_text(
                    json.dumps(payload), encoding="utf-8"
                )
                plugin_results.append(
                    {
                        "plugin": plugin,
                        "status": "completed",
                        "stdout_path": str(stdout_path),
                        "structured_output_path": str(structured_path),
                    }
                )

            result = process_analysis_outputs(
                database, run["run_id"], case["case_id"], plugin_results
            )
            database.update_analysis(
                run["run_id"], status="completed", plugin_results=plugin_results
            )

            with patch.object(app_module, "database", database), patch.object(
                app_module, "VOLATILITY_OUTPUT_DIR", output_root
            ):
                summary = app_module.get_case_summary(case["case_id"], run["run_id"])
                evidence_page = app_module.list_evidence(
                    case["case_id"],
                    run["run_id"],
                    "network",
                    None,
                    None,
                    None,
                    None,
                    1,
                    50,
                )
                network_evidence = evidence_page["items"][0]
                inspected = app_module.get_evidence(network_evidence["evidence_id"])
                relationships = app_module.list_relationships(
                    case["case_id"], run["run_id"], None, None
                )
                inspected_process = app_module.get_evidence(
                    next(
                        item["evidence_id"]
                        for item in database.list_evidence(
                            case["case_id"],
                            run["run_id"],
                            evidence_type="process",
                        )["items"]
                    )
                )
                timeline = app_module.get_timeline(
                    case["case_id"], run["run_id"], None, None, 1, 100
                )
                graph = app_module.get_graph(case["case_id"], run["run_id"], 200)
                hypotheses = app_module.list_hypotheses(case["case_id"], run["run_id"])
                search = app_module.search_evidence(
                    case["case_id"], "review.ps1", run["run_id"]
                )
                report = app_module.download_report(case["case_id"], run["run_id"])
                raw_output = app_module.get_plugin_output(
                    run["run_id"], "windows.netscan", "stdout"
                )

            self.assertEqual(result["processing_errors"], [])
            self.assertEqual(summary["evidence_count"], 6)
            self.assertEqual(summary["process_count"], 1)
            self.assertEqual(summary["network_count"], 1)
            self.assertEqual(summary["memory_findings_count"], 1)
            self.assertTrue(network_evidence["raw_source_url"].endswith("/stdout"))
            self.assertEqual(len(inspected["relationships"]), 1)
            self.assertEqual(len(inspected["timeline_events"]), 1)
            self.assertEqual(
                {item["type"] for item in inspected_process["pid_linked_evidence"]},
                {"command", "network", "dll", "memory"},
            )
            self.assertEqual(
                {item["relationship_type"] for item in relationships},
                {
                    "PROCESS_EXECUTED_WITH_COMMAND",
                    "PROCESS_CONNECTS_TO",
                    "PROCESS_LOADS_DLL",
                },
            )
            self.assertEqual(timeline["total"], 6)
            self.assertEqual(graph["total_nodes"], 6)
            self.assertEqual(len(graph["edges"]), 3)
            self.assertEqual(
                graph["edges"][0]["matched_fields"],
                {"process.pid": "1300", "network.pid": "1300"},
            )
            self.assertEqual(hypotheses[0]["title"], "Possible Attack Sequence")
            self.assertTrue(search["evidence"])
            report_text = report.body.decode("utf-8")
            self.assertIn("Observed evidence records: 6", report_text)
            self.assertIn("requires analyst validation", report_text)
            self.assertIn('"network.pid": "1300"', report_text)
            self.assertEqual(
                Path(raw_output.path).read_text(encoding="utf-8"),
                "Raw output for windows.netscan\n",
            )


if __name__ == "__main__":
    unittest.main()