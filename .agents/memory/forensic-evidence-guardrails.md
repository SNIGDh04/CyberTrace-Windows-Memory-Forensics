---
name: Forensic evidence guardrails
description: Rules for preserving CyberTrace provenance and avoiding unsupported forensic conclusions.
---

Live investigations must derive from uploaded memory images and actual Volatility output. Synthetic fixtures are for automated tests only. Correlations must expose their deterministic matched fields and reasons; shared identifiers do not establish causation. Missing timestamps remain missing. Hypotheses require analyst validation and must not be presented as confirmed compromise.

**Why:** The user requires evidence-only conclusions and prohibits fabricated findings.

**How to apply:** Preserve these constraints in ingestion, UI, reports, tests, benchmarks, and demo language. Use authorized captures and documented ground truth for measurements; otherwise mark results as not measured.