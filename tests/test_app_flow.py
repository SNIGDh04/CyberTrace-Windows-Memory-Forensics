import hashlib
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from fastapi import BackgroundTasks, HTTPException
from starlette.datastructures import UploadFile

import backend.app as app_module
from backend.database import Database
from backend.evidence.normalizer import normalize_plugin_output, system_information
from backend.models import AnalyzeRequest, CaseCreate
from backend.volatility.runner import VolatilityRunner


class UploadFlowTests(unittest.TestCase):
    def test_upload_calculates_sha256_and_unsupported_plugins_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = Database(root / "cybertrace.sqlite3")
            payload = b"memory image fixture bytes"
            with patch.object(app_module, "database", database), patch.object(
                app_module, "RAW_DIR", root / "raw"
            ):
                case = app_module.create_case(CaseCreate(name="Upload verification"))
                response = app_module.upload_image(
                    case["case_id"],
                    UploadFile(
                        filename="../../capture.raw",
                        file=BytesIO(payload),
                    ),
                )
                stored_case = database.get_case(case["case_id"])
                with self.assertRaises(HTTPException) as error:
                    app_module.analyze(
                        AnalyzeRequest(
                            case_id=case["case_id"],
                            plugins=["not.a.supported.plugin"],
                        ),
                        BackgroundTasks(),
                    )

            self.assertEqual(error.exception.status_code, 422)
            self.assertEqual(response["original_filename"], "capture.raw")
            self.assertEqual(response["image_size_bytes"], len(payload))
            self.assertEqual(
                response["image_sha256"],
                hashlib.sha256(payload).hexdigest(),
            )
            self.assertTrue(Path(stored_case["stored_path"]).is_file())


class OutputAndMetadataTests(unittest.TestCase):
    def test_malformed_volatility_json_keeps_raw_output_and_returns_parse_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "capture.raw"
            image.write_bytes(b"not a real capture")
            executable = root / "vol"
            executable.write_text(
                "#!/bin/sh\nprintf '%s' '{broken json'\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            runner = VolatilityRunner(
                root / "output",
                executable=str(executable),
                timeout_seconds=5,
            )

            result = runner.run_plugin(
                image,
                "CT-TEST",
                "RUN-TEST",
                "windows.pslist",
            )

            self.assertEqual(result["status"], "completed")
            self.assertIsNone(result["structured_output_path"])
            self.assertIn("not valid JSON", result["parse_error"])
            self.assertEqual(
                Path(result["stdout_path"]).read_text(encoding="utf-8"),
                "{broken json",
            )

    def test_windows_info_os_summary_uses_only_reported_values(self):
        records = normalize_plugin_output(
            {
                "columns": ["Variable", "Value"],
                "rows": [["OS", "Windows"], ["NtBuildNumber", 19045]],
            },
            case_id="CT-TEST",
            run_id="RUN-TEST",
            plugin="windows.info",
            raw_output_path=None,
        )

        self.assertEqual(
            system_information(records),
            {"OS": "Windows", "Build number": "19045"},
        )

    def test_benchmark_methodology_route_serves_the_documented_plan(self):
        response = app_module.benchmarking_methodology()
        self.assertIn(b"CyberTrace benchmarking plan", response.body)
        self.assertIn(b"Not measured", response.body)


class AnalysisFailurePersistenceTests(unittest.TestCase):
    def test_failed_and_malformed_plugins_are_persisted_without_stopping_the_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = Database(root / "cybertrace.sqlite3")
            case = database.create_case("Partial analysis")
            image = root / "capture.raw"
            image.write_bytes(b"not a real capture")
            run = database.create_analysis(
                case["case_id"],
                ["windows.pslist", "windows.cmdline"],
                image_path=str(image),
                image_filename=image.name,
                image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
            )

            class RunnerWithOneFailure:
                calls = []

                def run_plugin(self, memory_image, case_id, run_id, plugin):
                    self.calls.append(plugin)
                    output_dir = root / "output" / case_id / run_id
                    output_dir.mkdir(parents=True, exist_ok=True)
                    stem = plugin.replace(".", "_")
                    stdout_path = output_dir / f"{stem}.stdout.txt"
                    stderr_path = output_dir / f"{stem}.stderr.txt"
                    if plugin == "windows.pslist":
                        stdout_path.write_text("", encoding="utf-8")
                        stderr_path.write_text("unsupported image", encoding="utf-8")
                        return {
                            "plugin": plugin,
                            "status": "failed",
                            "error": "unsupported image",
                            "stdout_path": str(stdout_path),
                            "stderr_path": str(stderr_path),
                            "structured_output_path": None,
                        }
                    stdout_path.write_text("{broken json", encoding="utf-8")
                    stderr_path.write_text("", encoding="utf-8")
                    return {
                        "plugin": plugin,
                        "status": "completed",
                        "exit_code": 0,
                        "parse_error": "Output was not valid JSON",
                        "stdout_path": str(stdout_path),
                        "stderr_path": str(stderr_path),
                        "structured_output_path": None,
                    }

            runner = RunnerWithOneFailure()
            with patch.object(app_module, "database", database), patch.object(
                app_module, "runner", runner
            ):
                app_module.execute_analysis(
                    run["run_id"],
                    case["case_id"],
                    str(image),
                    ["windows.pslist", "windows.cmdline"],
                )

            saved = database.get_analysis(run["run_id"])
            self.assertEqual(runner.calls, ["windows.pslist", "windows.cmdline"])
            self.assertEqual(saved["status"], "partial")
            self.assertEqual(
                [item["status"] for item in saved["plugin_results"]],
                ["failed", "completed"],
            )
            self.assertIn("not valid JSON", saved["error"])
            self.assertTrue(Path(saved["plugin_results"][0]["stderr_path"]).is_file())
            self.assertTrue(Path(saved["plugin_results"][1]["stdout_path"]).is_file())


if __name__ == "__main__":
    unittest.main()