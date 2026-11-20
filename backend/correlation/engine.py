import networkx as nx

from backend.evidence.schema import EvidenceRecord, RelationshipRecord


class CorrelationEngine:
    """Build only direct, deterministic joins supported by the extracted fields."""

    @staticmethod
    def correlate(
        case_id: str,
        run_id: str,
        evidence: list[EvidenceRecord],
    ) -> list[RelationshipRecord]:
        graph = nx.DiGraph()
        by_id = {record.evidence_id: record for record in evidence}
        for record in evidence:
            graph.add_node(record.evidence_id, type=record.type, pid=record.pid)

        processes_by_pid: dict[str, EvidenceRecord] = {}
        for record in evidence:
            if record.type != "process" or not record.pid:
                continue
            existing = processes_by_pid.get(record.pid)
            if existing is None or (
                record.source_plugin == "windows.pstree"
                and existing.source_plugin != "windows.pstree"
            ):
                processes_by_pid[record.pid] = record

        relations: list[RelationshipRecord] = []
        seen: set[tuple[str, str, str]] = set()

        def add(
            source: EvidenceRecord,
            target: EvidenceRecord,
            relation_type: str,
            reason: str,
            source_plugin: str,
            matched_fields: dict[str, str],
        ) -> None:
            key = (source.evidence_id, target.evidence_id, relation_type)
            if key in seen:
                return
            seen.add(key)
            relation_id = f"REL-{run_id}-{len(relations) + 1:04d}"
            relation = RelationshipRecord(
                relationship_id=relation_id,
                case_id=case_id,
                run_id=run_id,
                source_evidence_id=source.evidence_id,
                target_evidence_id=target.evidence_id,
                relationship_type=relation_type,  # type: ignore[arg-type]
                reason=reason,
                source_plugin=source_plugin,
                matched_fields=matched_fields,
            )
            relations.append(relation)
            graph.add_edge(
                source.evidence_id,
                target.evidence_id,
                relationship_id=relation_id,
                relationship_type=relation_type,
            )

        for child in processes_by_pid.values():
            if not child.ppid:
                continue
            parent = processes_by_pid.get(child.ppid)
            if parent and parent.evidence_id != child.evidence_id:
                child_start = (child.artifact or {}).get("CreateTime") or (
                    child.artifact or {}
                ).get("create_time")
                parent_exit = (parent.artifact or {}).get("ExitTime") or (
                    parent.artifact or {}
                ).get("exit_time")
                temporal_note = ""
                if child_start and parent_exit:
                    temporal_note = (
                        " Temporal overlap could not be verified from available "
                        "CreateTime/ExitTime fields; relationship retained with "
                        "explicit PID-reuse caveat."
                    )
                matched = {"child.ppid": child.ppid, "parent.pid": parent.pid}
                if temporal_note:
                    matched["pid_reuse_caveat"] = "true"
                add(
                    parent,
                    child,
                    "PARENT_CHILD",
                    (
                        f"Child evidence {child.evidence_id} reports PPID {child.ppid}; "
                        f"parent evidence {parent.evidence_id} reports PID {parent.pid}."
                        f"{temporal_note}"
                    ),
                    child.source_plugin,
                    matched,
                )

        relation_specs = (
            ("network", "PROCESS_CONNECTS_TO", "network connection"),
            ("dll", "PROCESS_LOADS_DLL", "DLL association"),
            ("command", "PROCESS_EXECUTED_WITH_COMMAND", "command-line association"),
        )
        for artifact_type, relation_type, description in relation_specs:
            for target in evidence:
                if target.type != artifact_type or not target.pid:
                    continue
                process = processes_by_pid.get(target.pid)
                if process:
                    add(
                        process,
                        target,
                        relation_type,
                        (
                            f"Process evidence {process.evidence_id} and {description} "
                            f"evidence {target.evidence_id} both report PID {target.pid}."
                        ),
                        target.source_plugin,
                        {
                            "process.pid": process.pid,
                            f"{artifact_type}.pid": target.pid,
                        },
                    )

        # Retain the graph as the correlation engine's explicit model; its nodes
        # and edges are fully represented by the evidence and relationship lists.
        if graph.number_of_nodes() != len(by_id):
            raise RuntimeError("Correlation graph does not match its evidence set")
        return relations