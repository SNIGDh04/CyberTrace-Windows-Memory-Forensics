# CyberTrace architecture

## Day 1 implementation

```text
Browser
  └── FastAPI static UI and JSON API (same origin, port 5000)
        ├── SQLite: cases and analysis runs
        ├── data/raw/: uploaded memory images and recorded SHA-256
        └── Volatility 3 subprocesses
              └── data/volatility_output/<case>/<run>/
                    ├── <plugin>.stdout.txt
                    ├── <plugin>.stderr.txt
                    └── <plugin>.json (when stdout parses as JSON)
```

- **Backend:** Python 3.11, FastAPI, Pydantic request validation.
- **Forensics:** Volatility 3 CLI, invoked with argument arrays (not a shell command), a fixed plugin allowlist, per-plugin timeout, and separate output/error files.
- **Database:** SQLite for case and analysis-run metadata. Raw images and plugin output remain files so large binary data is not inserted into SQLite.
- **Frontend:** plain HTML, CSS, and JavaScript served by FastAPI on the same origin.
- **Analysis behavior:** plugin runs are sequential within a FastAPI background task. Each result is persisted as it completes. A failed plugin does not stop later plugins.

## Planned pipeline

```text
Memory image
  → Volatility plugin output
  → normalized observed evidence
  → evidence relationships
  → normalized timeline
  → evidence graph and possible attack hypothesis
  → investigator review and report
```

The current foundation preserves raw plugin output, a parsed JSON copy when available, and run status. It does not yet create normalized evidence, correlations, timelines, or hypotheses. Those features must be built from actual plugin output; synthetic records are reserved for tests.

## Replit and operational constraints

- Memory captures can be very large. Uploads are streamed to disk rather than loaded into memory; the default upload limit is 8 GiB and can be changed with `CYBERTRACE_MAX_UPLOAD_BYTES`.
- The 8 GiB setting is only CyberTrace's own limit; a proxy or runtime may impose a lower request limit. Replit recommends App Storage for large uploaded files.
- Volatility may need Windows symbol files and network access the first time it analyzes a capture. Analysis time and resource use depend on the image and plugin.
- Workspace files persist across workspace sessions, but a published app's local filesystem is reset on publish. The current SQLite database and captures are suitable for the development MVP only; use managed persistence before relying on evidence in a published app.
- The app listens on `0.0.0.0:5000` for Replit's web preview. CPU and memory assigned to a published app can limit analysis of large captures.
- FastAPI background tasks run in the web process. A process restart interrupts an active run; a durable worker/queue is deferred.
- The development application has no authentication or case-level access control. Do not publish it for untrusted users or upload sensitive captures to a shared instance until access control and retention protections are added.
- Captures and plugin output are excluded from Git. They are stored unencrypted in the workspace; handle and remove them according to the investigation's evidence-retention policy.
- No real Windows memory image was included with the implementation prompt, so successful extraction against an actual capture has not been verified.