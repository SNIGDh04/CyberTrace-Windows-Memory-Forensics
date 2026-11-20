import json
from pathlib import Path
from typing import Any

from backend.correlation.engine import CorrelationEngine
from backend.database import Database
from backend.evidence.normalizer import normalize_plugin_output
from backend.evidence.schema import EvidenceRecord
from backend.reconstruction.hypothesis import HypothesisEngine
from backend.timeline.engine import TimelineEngine


def process_analysis_outputs(
    database: Database,
    run_id: str,
    case_id: str,
    plugin_results: list[dict[str, Any]],
) -> dict[str, Any]:
    evidence: list[EvidenceRecord] = []
    processing_errors: list[str] = []
    next_sequence = 1

    for result in plugin_results:
        structured_path = result.get("structured_output_path")
        if not structured_path:
            if result.get("status") == "completed" and result.get("parse_error"):
                processing_errors.append(
                    f"{result['plugin']}: {result['parse_error']}"
                )
            continue
        path = Path(structured_path).resolve()
        if not path.is_file():
            processing_errors.append(
                f"{result['plugin']}: structured JSON output was not found."
            )
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            normalized = normalize_plugin_output(
                payload,
                case_id=case_id,
                run_id=run_id,
                plugin=result["plugin"],
                raw_output_path=result.get("stdout_path"),
                first_sequence=next_sequence,
            )
            evidence.extend(normalized)
            next_sequence += len(normalized)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            processing_errors.append(f"{result['plugin']}: could not normalize output: {exc}")

    relationships = CorrelationEngine.correlate(case_id, run_id, evidence)
    events = TimelineEngine.build_events(case_id, run_id, evidence)
    hypotheses = HypothesisEngine.generate(case_id, run_id, evidence, relationships)
    database.store_derived_data(
        run_id,
        [record.model_dump() for record in evidence],
        [record.model_dump() for record in relationships],
        [record.model_dump() for record in events],
        [record.model_dump() for record in hypotheses],
    )
    return {
        "evidence_count": len(evidence),
        "relationship_count": len(relationships),
        "event_count": len(events),
        "hypothesis_count": len(hypotheses),
        "processing_errors": processing_errors,
    }