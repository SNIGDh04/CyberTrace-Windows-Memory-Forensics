from collections import defaultdict

from backend.evidence.normalizer import entity_label
from backend.evidence.schema import (
    EvidenceRecord,
    HypothesisRecord,
    HypothesisStep,
    RelationshipRecord,
)


class HypothesisEngine:
    LIMITATIONS = [
        "Shared identifiers establish artifact correlation, not causation.",
        "A process, command line, DLL, or network endpoint is not by itself proof of malicious activity.",
        "Memory captures may omit events, timestamps, or artifacts that were not resident at capture time.",
        "Step grouping does not imply chronology unless source artifacts provide comparable timestamps.",
    ]

    @classmethod
    def generate(
        cls,
        case_id: str,
        run_id: str,
        evidence: list[EvidenceRecord],
        relationships: list[RelationshipRecord],
    ) -> list[HypothesisRecord]:
        by_id = {record.evidence_id: record for record in evidence}
        by_process: dict[str, dict[str, list[RelationshipRecord]]] = defaultdict(
            lambda: defaultdict(list)
        )
        parent_edges: dict[str, list[RelationshipRecord]] = defaultdict(list)
        for relationship in relationships:
            if relationship.relationship_type == "PARENT_CHILD":
                parent_edges[relationship.target_evidence_id].append(relationship)
                by_process[relationship.source_evidence_id]["child"].append(relationship)
                continue
            category = {
                "PROCESS_EXECUTED_WITH_COMMAND": "command",
                "PROCESS_CONNECTS_TO": "network",
                "PROCESS_LOADS_DLL": "dll",
            }.get(relationship.relationship_type)
            if category:
                by_process[relationship.source_evidence_id][category].append(relationship)

        hypotheses: list[HypothesisRecord] = []
        for process in evidence:
            if process.type != "process":
                continue
            links = by_process.get(process.evidence_id, {})
            network_links = links.get("network", [])
            command_links = links.get("command", [])
            child_links = links.get("child", [])
            # Only generate a sequence when both an execution/process relationship
            # and a PID-linked network artifact are directly supported.
            if not network_links or not (command_links or child_links):
                continue

            steps: list[HypothesisStep] = []
            supporting_evidence = {process.evidence_id}
            supporting_relationships: set[str] = set()
            incoming_parent = parent_edges.get(process.evidence_id, [])
            for relationship in incoming_parent:
                parent = by_id.get(relationship.source_evidence_id)
                if parent:
                    steps.append(
                        HypothesisStep(
                            stage="Parent/child process relationship",
                            description=(
                                f"{entity_label(parent)} is linked to {entity_label(process)} "
                                "by matching PID/PPID fields."
                            ),
                            evidence_ids=[
                                relationship.source_evidence_id,
                                relationship.target_evidence_id,
                            ],
                            relationship_ids=[relationship.relationship_id],
                        )
                    )
                    supporting_evidence.update(
                        [
                            relationship.source_evidence_id,
                            relationship.target_evidence_id,
                        ]
                    )
                    supporting_relationships.add(relationship.relationship_id)

            steps.append(
                HypothesisStep(
                    stage="Observed process",
                    description=entity_label(process),
                    evidence_ids=[process.evidence_id],
                )
            )
            for category, stage, verb in (
                ("command", "Command-line association", "has command-line evidence"),
                ("child", "Child process relationship", "is linked to a child process"),
                ("dll", "DLL association", "has an associated DLL artifact"),
                ("network", "Network association", "has a PID-linked network artifact"),
            ):
                for relationship in links.get(category, []):
                    target = by_id.get(relationship.target_evidence_id)
                    if not target:
                        continue
                    steps.append(
                        HypothesisStep(
                            stage=stage,
                            description=f"{entity_label(process)} {verb}: {entity_label(target)}.",
                            evidence_ids=[
                                relationship.source_evidence_id,
                                relationship.target_evidence_id,
                            ],
                            relationship_ids=[relationship.relationship_id],
                        )
                    )
                    supporting_evidence.update(
                        [
                            relationship.source_evidence_id,
                            relationship.target_evidence_id,
                        ]
                    )
                    supporting_relationships.add(relationship.relationship_id)

            has_command = bool(command_links)
            rationale = (
                "Generated by deterministic rules because the same observed PID has "
                f"{'command-line evidence' if has_command else 'a child-process relationship'} "
                "and a correlated network artifact. This is an investigator-review "
                "hypothesis, not a compromise verdict."
            )
            hypotheses.append(
                HypothesisRecord(
                    hypothesis_id=f"HYP-{run_id}-{len(hypotheses) + 1:04d}",
                    case_id=case_id,
                    run_id=run_id,
                    description=(
                        "Observed process execution-related artifacts and network "
                        "activity share a process identifier."
                    ),
                    rationale=rationale,
                    limitations=list(cls.LIMITATIONS),
                    supporting_evidence_ids=sorted(supporting_evidence),
                    supporting_relationship_ids=sorted(supporting_relationships),
                    steps=steps,
                )
            )
        return hypotheses