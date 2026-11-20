from datetime import datetime, timezone

from backend.evidence.normalizer import entity_label
from backend.evidence.schema import EvidenceRecord, TimelineEvent


EVENT_TYPES = {
    "process": "Process observation",
    "network": "Network artifact",
    "dll": "DLL association",
    "command": "Command-line artifact",
    "memory": "Memory artifact",
    "system": "System information",
}


def normalized_timestamp(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip()
    if candidate.upper().endswith(" UTC"):
        candidate = f"{candidate[:-4].strip()}+00:00"
    else:
        candidate = candidate.replace(" UTC", "")
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc)
    return parsed.isoformat()


def timeline_sort_key(event: dict | TimelineEvent) -> tuple[int, str, str]:
    timestamp = (
        event.get("timestamp")
        if isinstance(event, dict)
        else event.timestamp
    )
    event_id = event.get("event_id", "") if isinstance(event, dict) else event.event_id
    if not timestamp:
        return (2, "", event_id)
    try:
        parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    except ValueError:
        return (2, "", event_id)
    if parsed.tzinfo is None:
        return (1, parsed.isoformat(), event_id)
    return (0, parsed.astimezone(timezone.utc).isoformat(), event_id)


class TimelineEngine:
    @staticmethod
    def build_events(
        case_id: str,
        run_id: str,
        evidence: list[EvidenceRecord],
    ) -> list[TimelineEvent]:
        events = []
        for index, record in enumerate(evidence, start=1):
            timestamp = normalized_timestamp(record.timestamp)
            label = entity_label(record)
            if timestamp is None:
                label = f"{label} [timestamp_unavailable: true]"
            events.append(
                TimelineEvent(
                    event_id=f"EVT-{run_id}-{index:04d}",
                    case_id=case_id,
                    run_id=run_id,
                    evidence_id=record.evidence_id,
                    timestamp=timestamp,
                    event_type=EVENT_TYPES[record.type],
                    description=label,
                    related_pid=record.pid,
                    source_plugin=record.source_plugin,
                )
            )
        return sorted(events, key=timeline_sort_key)
