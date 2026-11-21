import type { EvidenceRecord, RelationshipRecord, RelationshipType } from "../types.ts";

export class CorrelationEngine {
  static correlate(
    caseId: string,
    runId: string,
    evidence: EvidenceRecord[]
  ): RelationshipRecord[] {
    const processesByPid = new Map<string, EvidenceRecord>();
    for (const record of evidence) {
      if (record.type !== "process" || !record.pid) continue;
      const existing = processesByPid.get(record.pid);
      if (
        !existing ||
        (record.source_plugin === "windows.pstree" &&
          existing.source_plugin !== "windows.pstree")
      ) {
        processesByPid.set(record.pid, record);
      }
    }

    const relations: RelationshipRecord[] = [];
    const seen = new Set<string>();

    const add = (
      source: EvidenceRecord,
      target: EvidenceRecord,
      relationType: RelationshipType,
      reason: string,
      sourcePlugin: string,
      matchedFields: Record<string, unknown>
    ): void => {
      const key = `${source.evidence_id}::${target.evidence_id}::${relationType}`;
      if (seen.has(key)) return;
      seen.add(key);
      const seq = String(relations.length + 1).padStart(4, "0");
      relations.push({
        relationship_id: `REL-${runId}-${seq}`,
        case_id: caseId,
        run_id: runId,
        source_evidence_id: source.evidence_id,
        target_evidence_id: target.evidence_id,
        relationship_type: relationType,
        reason,
        source_plugin: sourcePlugin,
        matched_fields: matchedFields,
        confidence: "correlated",
      });
    };

    for (const child of processesByPid.values()) {
      if (!child.ppid) continue;
      const parent = processesByPid.get(child.ppid);
      if (parent && parent.evidence_id !== child.evidence_id) {
        const childStart = child.artifact?.CreateTime ?? child.artifact?.create_time;
        const parentExit = parent.artifact?.ExitTime ?? parent.artifact?.exit_time;
        let temporalNote = "";
        if (childStart && parentExit) {
          temporalNote =
            " Temporal overlap could not be verified from available " +
            "CreateTime/ExitTime fields; relationship retained with " +
            "explicit PID-reuse caveat.";
        }
        const matched: Record<string, string> = {
          "child.ppid": child.ppid,
          "parent.pid": parent.pid || "",
        };
        if (temporalNote) {
          matched.pid_reuse_caveat = "true";
        }
        add(
          parent,
          child,
          "PARENT_CHILD",
          `Child evidence ${child.evidence_id} reports PPID ${child.ppid}; ` +
            `parent evidence ${parent.evidence_id} reports PID ${parent.pid}.${temporalNote}`,
          child.source_plugin,
          matched
        );
      }
    }

    const relationSpecs: Array<
      [EvidenceRecord["type"], RelationshipType, string]
    > = [
      ["network", "PROCESS_CONNECTS_TO", "network connection"],
      ["dll", "PROCESS_LOADS_DLL", "DLL association"],
      ["command", "PROCESS_EXECUTED_WITH_COMMAND", "command-line association"],
    ];

    for (const [artifactType, relationType, description] of relationSpecs) {
      for (const target of evidence) {
        if (target.type !== artifactType || !target.pid) continue;
        const proc = processesByPid.get(target.pid);
        if (proc) {
          add(
            proc,
            target,
            relationType,
            `Process evidence ${proc.evidence_id} and ${description} ` +
              `evidence ${target.evidence_id} both report PID ${target.pid}.`,
            target.source_plugin,
            {
              "process.pid": proc.pid,
              [`${artifactType}.pid`]: target.pid,
            }
          );
        }
      }
    }

    return relations;
  }
}
