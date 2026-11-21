export type EvidenceType =
  | "process"
  | "network"
  | "dll"
  | "command"
  | "memory"
  | "system";

export type RelationshipType =
  | "PARENT_CHILD"
  | "PROCESS_CONNECTS_TO"
  | "PROCESS_LOADS_DLL"
  | "PROCESS_EXECUTED_WITH_COMMAND";

export type ReviewState = "unreviewed" | "confirmed" | "dismissed";

export interface EvidenceRecord {
  evidence_id: string;
  case_id: string;
  run_id: string;
  type: EvidenceType;
  source_plugin: string;
  source_row: number;
  pid: string | null;
  ppid: string | null;
  process_name: string | null;
  timestamp: string | null;
  artifact: Record<string, unknown>;
  raw_output_path: string | null;
  confidence: "observed";
  created_at?: string;
}

export interface RelationshipRecord {
  relationship_id: string;
  case_id: string;
  run_id: string;
  source_evidence_id: string;
  target_evidence_id: string;
  relationship_type: RelationshipType;
  reason: string;
  source_plugin: string;
  matched_fields: Record<string, unknown>;
  confidence: "correlated";
  created_at?: string;
}

export interface TimelineEvent {
  event_id: string;
  case_id: string;
  run_id: string;
  evidence_id: string;
  timestamp: string | null;
  event_type: string;
  description: string;
  related_pid: string | null;
  source_plugin: string;
  confidence: "observed";
  created_at?: string;
}

export interface HypothesisStep {
  stage: string;
  description: string;
  evidence_ids: string[];
  relationship_ids: string[];
}

export interface HypothesisRecord {
  hypothesis_id: string;
  case_id: string;
  run_id: string;
  title: "Possible Attack Sequence";
  description: string;
  confidence: "hypothesis";
  rationale: string;
  limitations: string[];
  supporting_evidence_ids: string[];
  supporting_relationship_ids: string[];
  steps: HypothesisStep[];
  review_state: ReviewState;
  created_at?: string;
}

export interface CaseRecord {
  case_id: string;
  name: string;
  original_filename: string | null;
  stored_path: string | null;
  image_size_bytes: number | null;
  image_sha256: string | null;
  created_at: string;
  updated_at: string;
}

export interface ImageStorageRecord {
  logical_image_id: string;
  case_id: string;
  storage_type: "browser_upload" | "mounted_import";
  file_path: string;
  file_size_bytes: number;
  sha256_hash: string;
  verification_status: "pending" | "verified" | "failed";
  original_filename: string | null;
  created_at: string;
}

export interface PluginResult {
  plugin: string;
  status: string;
  exit_code?: number | null;
  duration_seconds?: number;
  error?: string | null;
  parse_error?: string | null;
  stdout_path?: string | null;
  stderr_path?: string | null;
  structured_output_path?: string | null;
  parsed_output?: unknown;
}

export interface AnalysisRun {
  run_id: string;
  case_id: string;
  status: string;
  requested_plugins: string[];
  plugin_results: PluginResult[];
  image_path: string | null;
  image_filename: string | null;
  image_sha256: string | null;
  error: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface CaseSummary {
  evidence_count: number;
  process_count: number;
  network_count: number;
  dll_count: number;
  command_count: number;
  memory_findings_count: number;
  system_count: number;
  relationship_count: number;
  event_count: number;
  hypothesis_count: number;
  by_type: Record<string, number>;
}
