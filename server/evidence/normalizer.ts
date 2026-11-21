import type { EvidenceRecord, EvidenceType } from "../types.ts";

export const PLUGIN_TYPES: Record<string, EvidenceType> = {
  "windows.info": "system",
  "windows.pslist": "process",
  "windows.pstree": "process",
  "windows.cmdline": "command",
  "windows.netscan": "network",
  "windows.dlllist": "dll",
  "windows.malfind": "memory",
};

function keyNorm(value: unknown): string {
  return String(value ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
}

function columnNames(columns: unknown): string[] {
  if (!Array.isArray(columns)) return [];
  return columns.map((col) => {
    if (col && typeof col === "object" && !Array.isArray(col)) {
      const obj = col as Record<string, unknown>;
      return String(obj.name ?? obj.Name ?? "");
    }
    return String(col ?? "");
  });
}

function zipToObject(columns: string[], values: unknown[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const len = Math.min(columns.length, values.length);
  for (let i = 0; i < len; i++) {
    out[columns[i]] = values[i];
  }
  return out;
}

function rowMapping(row: unknown, columns: string[]): Record<string, unknown> | null {
  if (row && typeof row === "object" && !Array.isArray(row)) {
    const obj = row as Record<string, unknown>;
    if (Array.isArray(obj.values) && columns.length > 0) {
      return zipToObject(columns, obj.values);
    }
    if (Array.isArray(obj.data) && columns.length > 0) {
      return zipToObject(columns, obj.data);
    }
    const mapped: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
      if (k !== "__children") {
        mapped[k] = v;
      }
    }
    return Object.keys(mapped).length > 0 ? mapped : null;
  }
  if (Array.isArray(row)) {
    let values = [...row];
    if (
      columns.length > 0 &&
      values.length === columns.length + 1 &&
      typeof values[0] === "number" &&
      Number.isInteger(values[0])
    ) {
      values = values.slice(1);
    }
    if (columns.length > 0 && values.length === columns.length) {
      return zipToObject(columns, values);
    }
    const mapped: Record<string, unknown> = {};
    values.forEach((v, idx) => {
      mapped[`column_${idx + 1}`] = v;
    });
    return Object.keys(mapped).length > 0 ? mapped : null;
  }
  return null;
}

export function rowsFromPayload(payload: unknown): Record<string, unknown>[] {
  let rows: unknown;
  let columns: string[] = [];

  if (Array.isArray(payload)) {
    rows = payload;
  } else if (payload && typeof payload === "object") {
    const obj = payload as Record<string, unknown>;
    columns = columnNames(obj.columns);
    if (obj.rows === undefined || obj.rows === null) {
      return [obj];
    }
    rows = obj.rows;
  } else {
    return [];
  }

  if (!Array.isArray(rows)) return [];

  const normalized: Record<string, unknown>[] = [];
  const appendRow = (row: unknown): void => {
    const mapped = rowMapping(row, columns);
    if (mapped) normalized.push(mapped);
    if (row && typeof row === "object" && !Array.isArray(row)) {
      const obj = row as Record<string, unknown>;
      const children = obj.__children ?? obj.children ?? [];
      if (Array.isArray(children)) {
        for (const child of children) {
          appendRow(child);
        }
      }
    }
  };

  for (const row of rows) {
    appendRow(row);
  }
  return normalized;
}

function fieldValue(row: Record<string, unknown>, ...aliases: string[]): unknown {
  const indexed = new Map<string, unknown>();
  for (const [k, v] of Object.entries(row)) {
    indexed.set(keyNorm(k), v);
  }
  for (const alias of aliases) {
    const norm = keyNorm(alias);
    if (indexed.has(norm)) {
      return indexed.get(norm);
    }
  }
  return null;
}

const ABSENT_VALUES = new Set(["", "-", "n/a", "none", "null", "unknown"]);

function present(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  return !ABSENT_VALUES.has(String(value).trim().toLowerCase());
}

function asText(value: unknown): string | null {
  if (!present(value)) return null;
  if (typeof value === "object") return JSON.stringify(value);
  return String(value).trim();
}

function extractTimestamp(row: Record<string, unknown>): string | null {
  return asText(
    fieldValue(
      row,
      "CreateTime",
      "Created",
      "StartTime",
      "Timestamp",
      "TimeCreated",
      "Time",
      "Date"
    )
  );
}

export function normalizePluginOutput(
  payload: unknown,
  options: {
    caseId: string;
    runId: string;
    plugin: string;
    rawOutputPath: string | null;
    firstSequence?: number;
  }
): EvidenceRecord[] {
  const evidenceType = PLUGIN_TYPES[options.plugin];
  if (!evidenceType) {
    throw new Error(`Unsupported Volatility plugin: ${options.plugin}`);
  }
  const firstSeq = options.firstSequence ?? 1;
  const rows = rowsFromPayload(payload);
  const records: EvidenceRecord[] = [];

  rows.forEach((row, idx) => {
    const rowNumber = idx + 1;
    const seq = String(firstSeq + rowNumber - 1).padStart(4, "0");
    records.push({
      evidence_id: `EV-${options.runId}-${seq}`,
      case_id: options.caseId,
      run_id: options.runId,
      type: evidenceType,
      source_plugin: options.plugin,
      source_row: rowNumber,
      pid: asText(fieldValue(row, "PID", "ProcessId", "Process ID")),
      ppid: asText(fieldValue(row, "PPID", "ParentPID", "ParentProcessId", "Parent PID")),
      process_name: asText(
        fieldValue(row, "ImageFileName", "ProcessName", "Process", "Owner", "Name")
      ),
      timestamp: extractTimestamp(row),
      artifact: row,
      raw_output_path: options.rawOutputPath,
      confidence: "observed",
    });
  });

  return records;
}

export function systemInformation(records: EvidenceRecord[]): Record<string, string> {
  const labels: Record<string, string> = {
    os: "OS",
    windowsversion: "Windows version",
    productname: "Product name",
    ntmajorversion: "NT major version",
    ntminorversion: "NT minor version",
    ntbuildnumber: "Build number",
    ntproducttype: "Product type",
    systemroot: "System root",
  };
  const result: Record<string, string> = {};
  for (const record of records) {
    if (record.type !== "system") continue;
    const artifact = record.artifact || {};
    const variable = asText(fieldValue(artifact, "Variable", "Name", "Key"));
    const value = asText(fieldValue(artifact, "Value", "Data"));
    const normalized = variable ? keyNorm(variable) : "";
    if (normalized in labels && value) {
      result[labels[normalized]] = value;
    }
  }
  return result;
}

export function entityLabel(record: Partial<EvidenceRecord>): string {
  const artifact = record.artifact || {};
  const kind = record.type || "evidence";
  const processName = record.process_name;
  const pid = record.pid;

  if (kind === "process") {
    return `${processName || "Process"} (PID ${pid || "unknown"})`;
  }
  if (kind === "network") {
    const remote = asText(fieldValue(artifact, "ForeignAddr", "RemoteAddress", "RemoteAddr"));
    const remotePort = asText(fieldValue(artifact, "ForeignPort", "RemotePort"));
    const local = asText(fieldValue(artifact, "LocalAddr", "LocalAddress"));
    const localPort = asText(fieldValue(artifact, "LocalPort"));
    let endpoint = remote && remotePort ? `${remote}:${remotePort}` : remote;
    if (!endpoint) {
      endpoint = local && localPort ? `${local}:${localPort}` : local;
    }
    return endpoint
      ? `Network endpoint ${endpoint}`
      : `Network artifact (PID ${pid || "unknown"})`;
  }
  if (kind === "dll") {
    const dllPath = asText(fieldValue(artifact, "MappedPath", "Path", "Name", "BaseDllName"));
    return dllPath ? `DLL ${dllPath}` : `DLL artifact (PID ${pid || "unknown"})`;
  }
  if (kind === "command") {
    const command = asText(fieldValue(artifact, "Args", "CommandLine", "Command"));
    return command
      ? `Command ${command.slice(0, 100)}`
      : `Command artifact (PID ${pid || "unknown"})`;
  }
  if (kind === "memory") {
    const protection = asText(fieldValue(artifact, "Protection"));
    return protection
      ? `Memory region ${protection}`
      : `Memory artifact (PID ${pid || "unknown"})`;
  }
  return `System artifact from ${record.source_plugin || "Volatility"}`;
}
