# Implementation checklist

## Day 1 — Foundation and Volatility 3

- [x] Freeze the MVP architecture and runtime dependencies.
- [x] Set up the Python 3.11 environment, FastAPI API, and Replit port 5000 entry point.
- [x] Install and confirm the Volatility 3 CLI.
- [x] Create cases and persist case/analysis-run metadata in SQLite.
- [x] Stream-upload a memory image, enforce a configurable size limit, and record SHA-256.
- [x] Run a selected subset of the seven supported Windows plugins.
- [x] Preserve stdout/stderr per plugin, expose run status, time out individual plugins, and continue after failures.
- [x] Provide a minimal case workspace for upload and plugin execution.
- [ ] Verify successful extraction with an investigator-provided Windows memory image.

## Day 2 — Evidence extraction and normalization

- [x] Add normalized evidence and provenance models with stable Evidence IDs.
- [x] Add evidence storage and additive SQLite schema versioning.
- [x] Parse supported Volatility JSON renderers while retaining original raw artifacts.

## Day 3 — Correlation

- [x] Correlate parent/child processes.
- [x] Correlate processes with network, DLL, and command-line artifacts.
- [x] Persist reasons, source plugins, supporting evidence IDs, and confidence labels for every relationship.

## Day 4 — Timeline

- [x] Normalize available timestamps and create evidence-linked events.
- [x] Add chronological timeline API and filters.

## Day 5 — Graph and hypotheses

- [x] Build an evidence graph from observed artifacts and recorded relationships.
- [x] Generate deterministic, explicitly labeled possible-sequence hypotheses with supporting Evidence IDs and limitations.

## Day 6 — Investigator workflow

- [x] Add process explorer, graph, timeline, evidence inspector, search, and filters.
- [x] Generate an exportable investigation report with provenance and limitations.

## Day 7 — Verification and documentation

- [ ] Test with real, authorized memory captures and document the test conditions.
- [x] Add a benchmark page and measurement protocol with unmeasured values clearly labeled.
- [ ] Measure the proposed benchmark dimensions against reviewed ground truth; do not publish invented scores.
- [x] Document a repeatable demo workflow; continue fixing any issues exposed by real-capture validation.