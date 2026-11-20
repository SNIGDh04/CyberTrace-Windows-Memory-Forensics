# CyberTrace benchmarking plan

CyberTrace has no measured accuracy or performance results yet. Do not fill result cells from synthetic fixtures or estimates. Use authorized captures and a reviewed reference set for any accuracy measurement.

## Measurement protocol

For each experiment, record the capture identifier and authorization, operating-system/build metadata when known, capture format and size, Volatility version, CyberTrace commit, selected plugins, symbol availability, machine configuration, elapsed time, and ground-truth source. Keep raw plugin output and the reviewer-approved labels with the experiment record. Separate extraction failures from missing source artifacts.

| Measure | Proposed calculation | Required reference | Result |
|---|---|---|---|
| Artifact coverage | Distinct supported artifact classes extracted per selected plugin | Authorized capture and plugin selection | Not measured |
| Extraction completeness | Correctly extracted labeled artifacts / all labeled expected artifacts | Ground-truth artifact inventory | Not measured |
| Temporal ordering | Correctly ordered comparable event pairs / labeled comparable pairs | Trusted event timestamps or reference ordering | Not measured |
| Relationship accuracy | Correct deterministic relationships / all evaluated relationships | Analyst-reviewed relationship labels | Not measured |
| Reconstruction accuracy | Supported sequence steps / labeled expected steps | Analyst-reviewed sequence ground truth | Not measured |
| Evidence traceability | Claims with source Evidence IDs and provenance / all claims | Generated report and evidence review | Not measured |
| False relationship rate | Incorrect relationships / all reviewed relationships | Analyst-reviewed relationship labels | Not measured |
| Investigation time | Time for the same task with manual tooling and CyberTrace | Repeatable task instructions and recorded timings | Not measured |
| Explainability | Relationships and hypotheses with explicit rationale and source IDs / generated items | Stored relationships and hypotheses | Not measured |
| LLM independence | Core pipeline completion with no LLM configured | Run configuration and execution record | Core pipeline uses no LLM; no comparative score |

Do not combine captures with different coverage or ground-truth quality into one accuracy score without documenting the method. Report denominators, exclusions, and uncertainty alongside any future result.

## Capability comparison plan

This table defines a comparison scope; it does not assert comparative performance. External tools have not been evaluated in a controlled experiment.

| Tool | Intended comparison scope | Evaluation status |
|---|---|---|
| Volatility 3 | Plugin extraction coverage and raw artifact availability | Not assessed |
| Timesketch | Timeline review and investigator workflow | Not assessed |
| volGPT | Optional explanation behavior; not a dependency of CyberTrace's core pipeline | Not assessed |
| DFIR-Chain | Evidence relationship and reconstruction workflow | Not assessed |
| CyberTrace | Evidence provenance, deterministic joins, evidence-linked timelines, graph, and possible-sequence review | Implemented; real-capture metrics not measured |

Any conclusion that one tool is more accurate, complete, or efficient requires comparable inputs, documented ground truth, and repeatable measurements.