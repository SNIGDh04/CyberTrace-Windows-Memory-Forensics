from typing import Any, Literal

from pydantic import BaseModel, Field


EvidenceType = Literal["process", "network", "dll", "command", "memory", "system"]


class EvidenceRecord(BaseModel):
    evidence_id: str
    case_id: str
    run_id: str
    type: EvidenceType
    source_plugin: str
    source_row: int
    pid: str | None = None
    ppid: str | None = None
    process_name: str | None = None
    timestamp: str | None = None
    artifact: dict[str, Any] = Field(default_factory=dict)
    raw_output_path: str | None = None
    confidence: Literal["observed"] = "observed"


class RelationshipRecord(BaseModel):
    relationship_id: str
    case_id: str
    run_id: str
    source_evidence_id: str
    target_evidence_id: str
    relationship_type: Literal[
        "PARENT_CHILD",
        "PROCESS_CONNECTS_TO",
        "PROCESS_LOADS_DLL",
        "PROCESS_EXECUTED_WITH_COMMAND",
    ]
    reason: str
    source_plugin: str
    matched_fields: dict[str, Any] = Field(default_factory=dict)
    confidence: Literal["correlated"] = "correlated"


class TimelineEvent(BaseModel):
    event_id: str
    case_id: str
    run_id: str
    evidence_id: str
    timestamp: str | None = None
    event_type: str
    description: str
    related_pid: str | None = None
    source_plugin: str
    confidence: Literal["observed"] = "observed"


class HypothesisStep(BaseModel):
    stage: str
    description: str
    evidence_ids: list[str]
    relationship_ids: list[str] = Field(default_factory=list)


class HypothesisRecord(BaseModel):
    hypothesis_id: str
    case_id: str
    run_id: str
    title: Literal["Possible Attack Sequence"] = "Possible Attack Sequence"
    description: str
    confidence: Literal["hypothesis"] = "hypothesis"
    rationale: str
    limitations: list[str]
    supporting_evidence_ids: list[str]
    supporting_relationship_ids: list[str]
    steps: list[HypothesisStep]
    review_state: Literal["unreviewed", "confirmed", "dismissed"] = "unreviewed"
