import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from backend.config import PLUGIN_TIMEOUT_SECONDS, SUPPORTED_PLUGINS, VOLATILITY_BINARY


class VolatilityRunner:
    def __init__(
        self,
        output_root: Path,
        executable: str = VOLATILITY_BINARY,
        timeout_seconds: int = PLUGIN_TIMEOUT_SECONDS,
    ):
        self.output_root = Path(output_root)
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def executable_path(self) -> str | None:
        return shutil.which(self.executable)

    def run_plugin(
        self,
        memory_image: Path,
        case_id: str,
        run_id: str,
        plugin: str,
    ) -> dict[str, Any]:
        if plugin not in SUPPORTED_PLUGINS:
            raise ValueError(f"Unsupported Volatility plugin: {plugin}")
        memory_image = Path(memory_image)
        if not memory_image.is_file():
            raise FileNotFoundError(f"Memory image not found: {memory_image.name}")
        binary = self.executable_path()
        if not binary:
            return {
                "plugin": plugin,
                "status": "failed",
                "exit_code": None,
                "duration_seconds": 0,
                "error": f"Volatility executable not found: {self.executable}",
                "stdout_path": None,
                "stderr_path": None,
                "parsed_output": None,
            }

        output_dir = self.output_root / case_id / run_id
        output_dir.mkdir(parents=True, exist_ok=True)
        safe_name = plugin.replace(".", "_")
        stdout_path = output_dir / f"{safe_name}.stdout.txt"
        stderr_path = output_dir / f"{safe_name}.stderr.txt"
        command = [
            binary,
            "-q",
            "-r",
            "json",
            "-f",
            str(memory_image),
            plugin,
        ]
        started = time.monotonic()

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds,
                check=False,
            )
            stdout = completed.stdout or ""
            stderr = completed.stderr or ""
            stdout_path.write_text(stdout, encoding="utf-8")
            stderr_path.write_text(stderr, encoding="utf-8")
            parsed_output = None
            structured_output_path = None
            parse_error = None
            if stdout.strip():
                try:
                    parsed_output = json.loads(stdout)
                    structured_path = output_dir / f"{safe_name}.json"
                    structured_path.write_text(
                        json.dumps(parsed_output, ensure_ascii=False, indent=2),
                        encoding="utf-8",
                    )
                    structured_output_path = str(structured_path)
                except json.JSONDecodeError as exc:
                    parse_error = f"Output was not valid JSON: {exc.msg}"
            elif completed.returncode == 0:
                parse_error = "Volatility returned empty stdout; expected JSON output."
            successful = completed.returncode == 0
            return {
                "plugin": plugin,
                "status": "completed" if successful else "failed",
                "exit_code": completed.returncode,
                "duration_seconds": round(time.monotonic() - started, 3),
                "error": None
                if successful
                else (stderr.strip() or stdout.strip() or "Plugin returned a non-zero exit code")[:2000],
                "parse_error": parse_error,
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
                "structured_output_path": structured_output_path,
                "parsed_output": parsed_output,
            }
        except subprocess.TimeoutExpired as exc:
            stdout = self._as_text(exc.stdout)
            stderr = self._as_text(exc.stderr)
            stdout_path.write_text(stdout, encoding="utf-8")
            stderr_path.write_text(stderr, encoding="utf-8")
            return {
                "plugin": plugin,
                "status": "failed",
                "exit_code": None,
                "duration_seconds": round(time.monotonic() - started, 3),
                "error": f"Plugin timed out after {self.timeout_seconds} seconds.",
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
                "structured_output_path": None,
                "parsed_output": None,
            }
        except OSError as exc:
            return {
                "plugin": plugin,
                "status": "failed",
                "exit_code": None,
                "duration_seconds": round(time.monotonic() - started, 3),
                "error": f"Plugin execution or output capture failed: {exc}",
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
                "structured_output_path": None,
                "parsed_output": None,
            }

    @staticmethod
    def _as_text(value: str | bytes | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value