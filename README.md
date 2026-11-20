# CyberTrace

**Evidence-driven digital forensics from volatile memory**

CyberTrace is a defensive digital-forensics MVP. It creates cases, accepts Windows memory images, runs selected Volatility 3 plugins, preserves raw output and source-image hashes, and derives reviewable evidence, relationships, timelines, graphs, and explicitly labeled hypotheses.

CyberTrace is an evidence-review aid, not a compromise verdict. Its deterministic pipeline works without an LLM, keeps every artifact tied to its plugin row and analysis run, and never claims that a possible sequence is confirmed malicious activity.

## Architecture

```text
Memory image → Volatility 3 → raw output + parsed rows
                                      ↓
                    observed evidence + image/run provenance
                       ↓              ↓             ↓
                  correlations    timeline      evidence graph
                       └──────────────┴─────────────┘
                                      ↓
                        Possible Attack Sequence
                                      ↓
                         investigator report
```

See [docs/architecture.md](docs/architecture.md) and [docs/implementation-checklist.md](docs/implementation-checklist.md) for the architecture, implementation sequence, and current scope.
See [docs/benchmarking.md](docs/benchmarking.md) for the unscored measurement protocol and comparison plan. No benchmark values have been invented.

## Requirements

- Python 3.11+
- Volatility 3
- Dependencies in `requirements.txt`

The project also uses Python's built-in SQLite support. The Replit setup uses `uv` to manage Python dependencies and the Volatility CLI.

## Run in Replit

The configured web entry point listens on `0.0.0.0:5000`.

```bash
uv run uvicorn backend.app:app --host 0.0.0.0 --port 5000
```

Alternatively:

```bash
uv run python main.py
```

The API is documented at `/docs` while the server is running.

## Run locally

```bash
python -m pip install -r requirements.txt
uvicorn backend.app:app --host 0.0.0.0 --port 5000
```

The Volatility executable must be available as `vol` on `PATH`. Set `CYBERTRACE_VOLATILITY_BINARY` to a different executable path if needed.

## Analyze a memory image

1. Create a case in the workspace.
2. Upload a memory image. CyberTrace streams it to disk and records its filename, size, and SHA-256 hash.
3. Select one or more supported plugins and start analysis.
4. Review each plugin's status, captured stdout/stderr, and parsed JSON output when available.
5. Review normalized evidence and source rows, then inspect deterministic PID/PPID relationships, the timeline, evidence graph, and any **Possible Attack Sequence** hypothesis.
6. Export a Markdown report for the selected run.

Evidence and derived data are scoped to a single analysis run. Replacing the case's active image affects future runs; earlier run records retain the image path, filename, and SHA-256 hash they used. Timestamps that cannot be parsed remain unavailable rather than being inferred.

## Validate with a genuine Windows memory image

Use only a capture you are authorized to analyze. CyberTrace does not generate sample investigations; the application UI is populated from uploaded-image Volatility runs, while synthetic artifacts exist only in automated tests.

1. Start the server using the command in [Run locally](#run-locally) or open the configured Replit preview.
2. Record the capture's source, format, size, and known Windows build. Optionally record a reference hash with `sha256sum /path/to/capture.raw`.
3. Create a case, upload the image, and compare the displayed SHA-256 with the reference hash.
4. Select the supported plugins appropriate for the capture and start analysis. Initial Volatility runs may need symbol downloads and can take a long time.
5. Confirm every plugin status. A failed or unparseable plugin must remain visible with its captured output; it must not be interpreted as an empty result.
6. Review Evidence, Process Explorer, Evidence Graph, Timeline, and Reconstruction. Open evidence and relationship inspectors to verify plugin, source row, matched fields, Evidence IDs, raw output, and timestamps.
7. Download the Markdown report and confirm the image hash, plugin outcomes, relationship reasons, supporting evidence, analyst-validation statement, and limitations.
8. Preserve the capture identifier, tool versions, plugin selection, environment, expected-artifact reference, and timings before recording any benchmark result.

CyberTrace cannot independently prove that an uploaded file is a genuine capture. Label it as an authorized real-capture experiment only after verifying its source and maintaining that experiment record.

## Demo flow

1. Open the case workspace and create a case.
2. Upload an authorized Windows memory image and verify its displayed SHA-256.
3. Select plugins and start the analysis; show per-plugin progress and errors.
4. Review evidence counts and open Process Explorer.
5. Open an evidence node and a relationship edge; verify source and target artifacts, join fields, reason, and raw-output links.
6. Follow an Evidence ID from the timeline to its inspector. Missing times remain unavailable.
7. Review the Possible Attack Sequence, supporting IDs, rationale, and limitations.
8. Download and review the investigation report.
9. Show the Benchmarking page with all unmeasured values clearly marked.

Supported plugins:

- `windows.info`
- `windows.pslist`
- `windows.pstree`
- `windows.cmdline`
- `windows.netscan`
- `windows.dlllist`
- `windows.malfind`

Analysis endpoints return run status; raw output and any successfully parsed JSON are saved under `data/volatility_output/`. A failed plugin is reported and does not prevent the remaining selected plugins from running.

## API

- `GET /api/health` — API and Volatility availability
- `GET /api/cases` — list cases
- `POST /api/cases` — create a case (`{"name":"Endpoint review"}`)
- `GET /api/cases/{case_id}` — get case details
- `GET /api/cases/{case_id}/analyses` — list case runs
- `POST /api/cases/{case_id}/image` — upload a `file`
- `POST /api/analyze` — start analysis (`{"case_id":"…","plugins":["windows.pslist"]}`)
- `GET /api/analyses/{run_id}` — get status and per-plugin results
- `GET /api/analyses/{run_id}/plugins/{plugin}/stdout` — retrieve captured stdout
- `GET /api/analyses/{run_id}/plugins/{plugin}/stderr` — retrieve captured stderr
- `GET /api/cases/{case_id}/summary` — evidence and derived-data counts for a run
- `GET /api/evidence` — paginated evidence with type, PID, plugin, relationship, and text filters
- `GET /api/evidence/{evidence_id}` — inspect an artifact and its recorded relationships
- `GET /api/processes` and `GET /api/network` — artifact-specific views
- `GET /api/relationships` — deterministic links and their join reasons
- `GET /api/timeline` — evidence-linked chronological events and filters
- `GET /api/graph` — graph nodes and explainable edges
- `GET /api/hypotheses` — explicitly labeled possible-sequence hypotheses
- `GET /api/search` — search evidence and relationships within a case/run
- `GET /api/report` — download a provenance- and limitations-aware Markdown report
- `GET /api/analyses/{run_id}/plugins/{plugin}/json` — retrieve parsed plugin JSON
- `GET /benchmarking` — read the benchmark measurement protocol and capability-comparison plan

Interactive API documentation is at `/docs`.

## Configuration

- `CYBERTRACE_DATA_DIR` — data root; default is `data/`
- `CYBERTRACE_MAX_UPLOAD_BYTES` — maximum uploaded image size; default is 8 GiB
- `CYBERTRACE_PLUGIN_TIMEOUT_SECONDS` — per-plugin timeout; default is 3600 seconds
- `CYBERTRACE_VOLATILITY_BINARY` — Volatility executable name/path; default is `vol`

The SQLite database, image captures, and Volatility output are excluded from Git. They are stored unencrypted; follow the evidence-handling and retention requirements for the environment where CyberTrace runs.

Replit may enforce a lower HTTP upload limit than this app setting, and recommends App Storage for large uploaded files. The current case database and images are stored on the local filesystem: workspace files persist between workspace sessions, but published-app files are reset on publish. Treat this as a development MVP and add managed persistence before relying on data in a published app.

## Tests

```bash
uv run python -m unittest discover -s tests -v
```

The tests use temporary data and a fake command-line program to verify runner behavior and deterministic downstream processing. Fixture artifacts are test-only; they are not used to populate an investigation.

## Limitations and next steps

- No successful run against a real Windows memory image was possible during the foundation build because none was provided.
- Supported JSON table layouts are normalized deterministically; unusual Volatility renderer shapes may need an adapter, while original raw output remains available.
- PID/PPID matches establish correlations only, not causation. A possible sequence is a review hypothesis, not a finding of confirmed compromise.
- Volatility may need to download symbol files and can consume substantial time, CPU, memory, and disk.
- The current background job runs inside the web process and will not survive a process restart.
- Authentication, case isolation, encryption at rest, and evidence-retention controls are not implemented. Do not expose this foundation to untrusted users or upload sensitive captures to a shared deployment.
- Local SQLite, image files, and plugin outputs are development-MVP storage; configure managed persistence and access controls before relying on a published deployment.# CyberTrace-Windows-Memory-Forensics
