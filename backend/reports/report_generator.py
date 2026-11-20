import json
from typing import Any

from backend.evidence.normalizer import entity_label


def generate_report(
    case: dict[str, Any],
    run: dict[str, Any],
    summary: dict[str, Any],
    evidence: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
    events: list[dict[str, Any]],
    hypotheses: list[dict[str, Any]],
) -> str:
    lines = [
        "# CyberTrace Investigation Report",
        "",
        "> This report distinguishes observed artifacts, correlated relationships, and investigator-facing hypotheses. Correlation does not establish causation or compromise.",
        "> Every hypothesis requires analyst validation; it is not a confirmed attack finding.",
        "",
        "## Case information",
        "",
        f"- Case: {case['name']} (`{case['case_id']}`)",
        f"- Source image: {run.get('image_filename') or 'Not recorded'}",
        f"- Source image size (bytes): {case.get('image_size_bytes') if case.get('image_size_bytes') is not None else 'Not recorded'}",
        f"- Source image SHA-256: `{run.get('image_sha256') or 'Not recorded'}`",
        f"- Logical image ID: `{case.get('logical_image_id') or 'Not recorded'}`",
        f"- Storage type: {case.get('storage_type') or 'legacy/unknown'}",
        f"- Verification status: {case.get('verification_status') or 'Not recorded'}",
        f"- Analysis run: `{run['run_id']}`",
        f"- Run status: {run['status']}",
        f"- Started: {run.get('started_at') or 'Not recorded'}",
        f"- Completed: {run.get('completed_at') or 'Not recorded'}",
        "",
        "## Analysis summary",
        "",
        f"- Observed evidence records: {summary['evidence_count']}",
        f"- Correlated relationships: {summary['relationship_count']}",
        f"- Evidence-linked timeline events: {summary['event_count']}",
        f"- Possible attack-sequence hypotheses: {summary['hypothesis_count']}",
        f"- Process artifacts: {summary['process_count']}",
        f"- Network artifacts: {summary['network_count']}",
        f"- DLL artifacts: {summary['dll_count']}",
        f"- Command-line artifacts: {summary['command_count']}",
        f"- Memory-plugin artifacts: {summary['memory_findings_count']}",
        "",
        "## Process findings (observed)",
        "",
    ]
    process_rows = [record for record in evidence if record["type"] == "process"]
    if not process_rows:
        lines.append("No process artifacts were extracted for this run.")
    else:
        for record in process_rows:
            lines.append(
                f"- {entity_label(record)} — `{record['evidence_id']}` "
                f"from `{record['source_plugin']}`"
            )

    lines.extend(["", "## Network findings (observed)", ""])
    network_rows = [record for record in evidence if record["type"] == "network"]
    if not network_rows:
        lines.append("No network artifacts were extracted for this run.")
    else:
        for record in network_rows:
            lines.append(
                f"- {entity_label(record)} — `{record['evidence_id']}` "
                f"from `{record['source_plugin']}`"
            )

    lines.extend(["", "## Timeline", ""])
    if not events:
        lines.append("No evidence-linked timeline events were generated.")
    else:
        for event in events:
            lines.append(
                f"- {event.get('timestamp') or 'Time unavailable'} — "
                f"{event['event_type']}: {event['description']} "
                f"(`{event['evidence_id']}`, `{event['source_plugin']}`)"
            )

    lines.extend(["", "## Correlated relationships", ""])
    if not relationships:
        lines.append("No deterministic relationships matched the available artifacts.")
    else:
        by_id = {record["evidence_id"]: record for record in evidence}
        for relationship in relationships:
            source = by_id.get(relationship["source_evidence_id"], {})
            target = by_id.get(relationship["target_evidence_id"], {})
            lines.extend(
                [
                    f"### {relationship['relationship_type']}",
                    "",
                    f"- From: {entity_label(source) if source else relationship['source_evidence_id']}",
                    f"- To: {entity_label(target) if target else relationship['target_evidence_id']}",
                    f"- Reason: {relationship['reason']}",
                    f"- Source plugin: `{relationship['source_plugin']}`",
                    f"- Evidence IDs: `{relationship['source_evidence_id']}`, `{relationship['target_evidence_id']}`",
                    f"- Fields used for deterministic join: `{json.dumps(relationship.get('matched_fields') or {}, sort_keys=True)}`",
                    f"- Confidence class: {relationship['confidence']}",
                    "",
                ]
            )

    lines.extend(["## Possible Attack Sequence", ""])
    if not hypotheses:
        lines.append(
            "No hypothesis met the current deterministic rule requirements. This is not evidence that no suspicious activity occurred."
        )
    for hypothesis in hypotheses:
        lines.extend(
            [
                f"### {hypothesis['title']} — `{hypothesis['hypothesis_id']}`",
                "",
                hypothesis["description"],
                "",
                f"Rationale: {hypothesis['rationale']}",
                "",
            ]
        )
        for index, step in enumerate(hypothesis["steps"], start=1):
            lines.extend(
                [
                    f"{index}. **{step['stage']}** — {step['description']}",
                    f"   - Supporting evidence: {', '.join(step['evidence_ids'])}",
                    f"   - Supporting relationships: {', '.join(step['relationship_ids']) or 'None'}",
                ]
            )
        lines.extend(["", "Limitations:"])
        lines.extend(f"- {item}" for item in hypothesis["limitations"])
        lines.append("")

    lines.extend(
        [
            "## Plugin execution",
            "",
            "| Plugin | Status | Exit code | Duration (seconds) |",
            "|---|---:|---:|---:|",
        ]
    )
    for result in run["plugin_results"]:
        lines.append(
            f"| `{result['plugin']}` | {result['status']} | "
            f"{result.get('exit_code') if result.get('exit_code') is not None else '—'} | "
            f"{result.get('duration_seconds', '—')} |"
        )
        if result.get("error"):
            lines.append(f"\n  Error: {result['error']}")

    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "- A memory image is a point-in-time source and may not contain a complete history.",
            "- Only artifacts emitted by the selected Volatility 3 plugins are included.",
            "- A missing or unparseable timestamp is not inferred or replaced.",
            "- PID joins show identifier matches; they do not prove causation.",
            "- Possible-sequence hypotheses are deterministic review aids, not attack verdicts.",
            "- This report does not claim completeness or a measured accuracy rate.",
            "",
        ]
    )
    return "\n".join(lines)