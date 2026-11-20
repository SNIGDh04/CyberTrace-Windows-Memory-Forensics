import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import backend.app as app_module
from backend.database import Database
from backend.volatility.runner import VolatilityRunner


class DatabaseTests(unittest.TestCase):
    def test_case_and_analysis_provenance_metadata_persist(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Database(Path(temporary) / "test.sqlite3")
            case = database.create_case("Memory review")
            image = Path(temporary) / "capture.raw"
            image.write_bytes(b"test image bytes")
            updated = database.attach_image(
                case["case_id"],
                image.name,
                str(image),
                image.stat().st_size,
                "abc123",
            )

            self.assertEqual(updated["image_sha256"], "abc123")
            self.assertEqual(updated["original_filename"], "capture.raw")

            run = database.create_analysis(case["case_id"], ["windows.pslist"])
            database.update_analysis(run["run_id"], status="running", started_at="start")
            database.update_analysis(
                run["run_id"],
                status="completed",
                plugin_results=[
                    {"plugin": "windows.pslist", "status": "completed", "exit_code": 0}
                ],
                completed_at="finish",
            )
            stored = database.get_analysis(run["run_id"])
            self.assertEqual(stored["status"], "completed")
            self.assertEqual(stored["requested_plugins"], ["windows.pslist"])
            self.assertEqual(stored["plugin_results"][0]["exit_code"], 0)
            self.assertEqual(
                database.list_analyses_for_case(case["case_id"])[0]["run_id"],
                run["run_id"],
            )


class VolatilityRunnerTests(unittest.TestCase):
    def make_executable(self, directory: Path, body: str) -> Path:
        executable = directory / "fake-vol"
        executable.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
        executable.chmod(0o755)
        return executable

    def test_success_preserves_raw_streams_and_parses_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "capture.raw"
            image.write_bytes(b"not a real memory image")
            executable = self.make_executable(
                root,
                "printf '{\"columns\":[\"PID\"],\"rows\":[]}\\n'\nprintf 'diagnostic\\n' >&2",
            )
            runner = VolatilityRunner(
                root / "output",
                executable=str(executable),
                timeout_seconds=5,
            )

            result = runner.run_plugin(image, "CT-TEST", "RUN-TEST", "windows.pslist")

            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["parsed_output"]["rows"], [])
            self.assertEqual(Path(result["stdout_path"]).read_text().strip(), '{"columns":["PID"],"rows":[]}')
            self.assertEqual(Path(result["stderr_path"]).read_text().strip(), "diagnostic")
            self.assertEqual(
                json.loads(Path(result["structured_output_path"]).read_text())["rows"],
                [],
            )

    def test_plugin_failure_is_reported_and_raw_error_is_kept(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "capture.raw"
            image.write_bytes(b"test")
            executable = self.make_executable(root, "printf 'unsupported image\\n' >&2\nexit 2")
            runner = VolatilityRunner(root / "output", executable=str(executable), timeout_seconds=5)

            result = runner.run_plugin(image, "CT-TEST", "RUN-TEST", "windows.pslist")

            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["exit_code"], 2)
            self.assertIn("unsupported image", result["error"])
            self.assertEqual(Path(result["stderr_path"]).read_text().strip(), "unsupported image")

    def test_unsupported_plugin_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = VolatilityRunner(root / "output", executable="/bin/true")
            with self.assertRaises(ValueError):
                runner.run_plugin(root / "missing.raw", "CT-TEST", "RUN-TEST", "arbitrary.plugin")

    def test_missing_image_is_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner = VolatilityRunner(Path(temporary) / "output", executable="/bin/true")
            with self.assertRaises(FileNotFoundError):
                runner.run_plugin(
                    Path(temporary) / "missing.raw",
                    "CT-TEST",
                    "RUN-TEST",
                    "windows.pslist",
                )

    def test_structured_json_output_route_is_case_scoped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = Database(root / "test.sqlite3")
            case = database.create_case("API route test")
            run = database.create_analysis(case["case_id"], ["windows.pslist"])
            output_root = root / "output"
            output = (
                output_root
                / case["case_id"]
                / run["run_id"]
                / "windows_pslist.json"
            )
            output.parent.mkdir(parents=True)
            output.write_text('{"rows":[]}', encoding="utf-8")
            database.update_analysis(
                run["run_id"],
                plugin_results=[
                    {
                        "plugin": "windows.pslist",
                        "status": "completed",
                        "structured_output_path": str(output),
                    }
                ],
            )

            with patch.object(app_module, "database", database), patch.object(
                app_module, "VOLATILITY_OUTPUT_DIR", output_root
            ):
                public = app_module.public_analysis(database.get_analysis(run["run_id"]))
                response = app_module.get_plugin_output(
                    run["run_id"], "windows.pslist", "json"
                )

            self.assertTrue(
                public["plugin_results"][0]["structured_output_url"].endswith("/json")
            )
            self.assertEqual(Path(response.path).read_text(encoding="utf-8"), '{"rows":[]}')


if __name__ == "__main__":
    unittest.main()