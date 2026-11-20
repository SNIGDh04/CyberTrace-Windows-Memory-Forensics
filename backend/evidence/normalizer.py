import re
from typing import Any

from backend.evidence.schema import EvidenceRecord, EvidenceType


PLUGIN_TYPES: dict[str, EvidenceType] = {
    "windows.info": "system",
    "windows.pslist": "process",
    "windows.pstree": "process",
    "windows.cmdline": "command",
    "windows.netscan": "network",
    "windows.dlllist": "dll",
    "windows.malfind": "memory",
}


def _key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _column_names(columns: Any) -> list[str]:
    if not isinstance(columns, list):
        return []
    names = []
    for column in columns:
        if isinstance(column, dict):
            names.append(str(column.get("name") or column.get("Name") or ""))
        else:
            names.append(str(column))
    return names


def _row_mapping(row: Any, columns: list[str]) -> dict[str, Any] | None:
    if isinstance(row, dict):
        values = row.get("values")
        if isinstance(values, list) and columns:
            return dict(zip(columns, values))
        data = row.get("data")
        if isinstance(data, list) and columns:
            return dict(zip(columns, data))
        return {str(key): value for key, value in row.items() if key != "__children"}
    if isinstance(row, (list, tuple)):
        values = list(row)
        # Some tree renderers prepend a nesting depth before the tabular cells.
        if columns and len(values) == len(columns) + 1 and isinstance(values[0], int):
            values = values[1:]
        if columns and len(values) == len(columns):
            return dict(zip(columns, values))
        return {f"column_{index + 1}": value for index, value in enumerate(values)}
    return None


def rows_from_payload(payload: Any) -> list[dict[str, Any]]:
    """Convert common Volatility JSON table shapes to row mappings."""
    if isinstance(payload, list):
        rows = payload
        columns: list[str] = []
    elif isinstance(payload, dict):
        columns = _column_names(payload.get("columns"))
        rows = payload.get("rows")
        if rows is None:
            # A JSON object containing a single artifact is still useful evidence.
            return [payload]
    else:
        return []

    if not isinstance(rows, list):
        return []

    normalized: list[dict[str, Any]] = []

    def append_row(row: Any) -> None:
        mapped = _row_mapping(row, columns)
        if mapped:
            normalized.append(mapped)
        if isinstance(row, dict):
            children = row.get("__children") or row.get("children") or []
            if isinstance(children, list):
                for child in children:
                    append_row(child)

    for row in rows:
        append_row(row)
    return normalized


def _field(row: dict[str, Any], *aliases: str) -> Any:
    indexed = {_key(key): value for key, value in row.items()}
    for alias in aliases:
        normalized_alias = _key(alias)
        if normalized_alias in indexed:
            return indexed[normalized_alias]
    return None


def _present(value: Any) -> bool:
    return value is not None and str(value).strip().lower() not in {
        "",
        "-",
        "n/a",
        "none",
        "null",
        "unknown",
    }


def _text(value: Any) -> str | None:
    if not _present(value):
        return None
    if isinstance(value, (dict, list)):
        return str(value)
    return str(value).strip()


def _timestamp(row: dict[str, Any]) -> str | None:
    return _text(
        _field(
            row,
            "CreateTime",
            "Created",
            "StartTime",
            "Timestamp",
            "TimeCreated",
            "Time",
            "Date",
        )
    )


def normalize_plugin_output(
    payload: Any,
    *,
    case_id: str,
    run_id: str,
    plugin: str,
    raw_output_path: str | None,
    first_sequence: int = 1,
) -> list[EvidenceRecord]:
    evidence_type = PLUGIN_TYPES.get(plugin)
    if evidence_type is None:
        raise ValueError(f"Unsupported Volatility plugin: {plugin}")

    records: list[EvidenceRecord] = []
    for row_number, row in enumerate(rows_from_payload(payload), start=1):
        pid = _text(_field(row, "PID", "ProcessId", "Process ID"))
        ppid = _text(_field(row, "PPID", "ParentPID", "ParentProcessId", "Parent PID"))
        process_name = _text(
            _field(row, "ImageFileName", "ProcessName", "Process", "Owner", "Name")
        )
        evidence_id = f"EV-{run_id}-{first_sequence + row_number - 1:04d}"
        records.append(
            EvidenceRecord(
                evidence_id=evidence_id,
                case_id=case_id,
                run_id=run_id,
                type=evidence_type,
                source_plugin=plugin,
                source_row=row_number,
                pid=pid,
                ppid=ppid,
                process_name=process_name,
                timestamp=_timestamp(row),
                artifact=row,
                raw_output_path=raw_output_path,
            )
        )
    return records


def system_information(records: list[EvidenceRecord | dict[str, Any]]) -> dict[str, str]:
    """Expose only OS-identification values directly emitted by windows.info."""
    labels = {
        "os": "OS",
        "windowsversion": "Windows version",
        "productname": "Product name",
        "ntmajorversion": "NT major version",
        "ntminorversion": "NT minor version",
        "ntbuildnumber": "Build number",
        "ntproducttype": "Product type",
        "systemroot": "System root",
    }
    result: dict[str, str] = {}
    for record in records:
        get = record.get if isinstance(record, dict) else lambda key, default=None: getattr(record, key, default)
        if get("type") != "system":
            continue
        artifact = get("artifact", {}) or {}
        variable = _text(_field(artifact, "Variable", "Name", "Key"))
        value = _text(_field(artifact, "Value", "Data"))
        normalized = _key(variable) if variable else ""
        if normalized in labels and value:
            result[labels[normalized]] = value
    return result


def entity_label(record: EvidenceRecord | dict[str, Any]) -> str:
    get = record.get if isinstance(record, dict) else lambda key, default=None: getattr(record, key, default)
    artifact = get("artifact", {}) or {}
    kind = get("type", "evidence")
    process_name = get("process_name")
    pid = get("pid")

    if kind == "process":
        return f"{process_name or 'Process'} (PID {pid or 'unknown'})"
    if kind == "network":
        remote = _text(_field(artifact, "ForeignAddr", "RemoteAddress", "RemoteAddr"))
        remote_port = _text(_field(artifact, "ForeignPort", "RemotePort"))
        local = _text(_field(artifact, "LocalAddr", "LocalAddress"))
        local_port = _text(_field(artifact, "LocalPort"))
        endpoint = f"{remote}:{remote_port}" if remote and remote_port else remote
        endpoint = endpoint or (f"{local}:{local_port}" if local and local_port else local)
        return f"Network endpoint {endpoint}" if endpoint else f"Network artifact (PID {pid or 'unknown'})"
    if kind == "dll":
        path = _text(_field(artifact, "MappedPath", "Path", "Name", "BaseDllName"))
        return f"DLL {path}" if path else f"DLL artifact (PID {pid or 'unknown'})"
    if kind == "command":
        command = _text(_field(artifact, "Args", "CommandLine", "Command"))
        return f"Command {command[:100]}" if command else f"Command artifact (PID {pid or 'unknown'})"
    if kind == "memory":
        protection = _text(_field(artifact, "Protection"))
        return f"Memory region {protection}" if protection else f"Memory artifact (PID {pid or 'unknown'})"
    return f"System artifact from {get('source_plugin', 'Volatility')}"