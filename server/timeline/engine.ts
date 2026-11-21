import { entityLabel } from "../evidence/normalizer.ts";
import type { EvidenceRecord, EvidenceType, TimelineEvent } from "../types.ts";

export const EVENT_TYPES: Record<EvidenceType, string> = {
  process: "Process observation",
  network: "Network artifact",
  dll: "DLL association",
  command: "Command-line artifact",
  memory: "Memory artifact",
  system: "System information",
};

const TZ_SUFFIX_RE = /(Z|[+-]\d{2}:\d{2})$/i;

export function normalizedTimestamp(value: string | null | undefined): string | null {
  if (!value) return null;
  let candidate = value.trim();
  if (candidate.toUpperCase().endsWith(" UTC")) {
    candidate = `${candidate.slice(0, -4).trim()}+00:00`;
  } else {
    candidate = candidate.replace(" UTC", "");
  }
  const normalizedSpace = candidate.replace(" ", "T");
  const hasTz = TZ_SUFFIX_RE.test(normalizedSpace);
  const parsed = new Date(hasTz ? normalizedSpace : `${normalizedSpace}Z`);
  if (Number.isNaN(parsed.getTime())) return null;
  if (hasTz) {
    return parsed.toISOString();
  }
  // Preserve naive ISO format without inventing a timezone offset
  return parsed.toISOString().replace(/Z$/, "");
}

export function compareTimelineEvents(a: TimelineEvent, b: TimelineEvent): number {
  const key = (ev: TimelineEvent): [number, string, string] => {
    if (!ev.timestamp) return [2, "", ev.event_id];
    const hasTz = TZ_SUFFIX_RE.test(ev.timestamp);
    const parsed = new Date(hasTz ? ev.timestamp : `${ev.timestamp}Z`);
    if (Number.isNaN(parsed.getTime())) return [2, "", ev.event_id];
    if (!hasTz) return [1, parsed.toISOString().replace(/Z$/, ""), ev.event_id];
    return [0, parsed.toISOString(), ev.event_id];
  };

  const [aRank, aTs, aId] = key(a);
  const [bRank, bTs, bId] = key(b);
  if (aRank !== bRank) return aRank - bRank;
  if (aTs !== bTs) return aTs < bTs ? -1 : 1;
  return aId < bId ? -1 : aId > bId ? 1 : 0;
}

export class TimelineEngine {
  static buildEvents(
    caseId: string,
    runId: string,
    evidence: EvidenceRecord[]
  ): TimelineEvent[] {
    const events: TimelineEvent[] = evidence.map((record, idx) => {
      const timestamp = normalizedTimestamp(record.timestamp);
      let label = entityLabel(record);
      if (timestamp === null) {
        label = `${label} [timestamp_unavailable: true]`;
      }
      const seq = String(idx + 1).padStart(4, "0");
      return {
        event_id: `EVT-${runId}-${seq}`,
        case_id: caseId,
        run_id: runId,
        evidence_id: record.evidence_id,
        timestamp,
        event_type: EVENT_TYPES[record.type],
        description: label,
        related_pid: record.pid,
        source_plugin: record.source_plugin,
        confidence: "observed",
      };
    });
    return events.sort(compareTimelineEvents);
  }
}
