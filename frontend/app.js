const state = {
  cases: [],
  selectedCaseId: null,
  selectedRunId: null,
  caseAnalyses: [],
  supportedPlugins: [],
  maxUploadBytes: 0,
  activeRunId: null,
  pollTimer: null,
  currentView: "overview",
  evidencePage: 1,
  evidencePageSize: 25,
  evidenceTotal: 0,
  graph: { nodes: [], edges: [], truncated: false },
  searchTimer: null,
};

const elements = {
  caseList: document.querySelector("#case-list"),
  caseCount: document.querySelector("#case-count"),
  caseTitle: document.querySelector("#active-case-title"),
  caseState: document.querySelector("#case-state"),
  caseDetail: document.querySelector("#case-detail"),
  analysisPanel: document.querySelector("#analysis-panel"),
  analysisState: document.querySelector("#analysis-state"),
  analysisSummary: document.querySelector("#analysis-summary"),
  analysisMetrics: document.querySelector("#analysis-metrics"),
  pluginResults: document.querySelector("#plugin-results"),
  dialog: document.querySelector("#case-dialog"),
  caseForm: document.querySelector("#case-form"),
  caseName: document.querySelector("#case-name"),
  caseFormError: document.querySelector("#case-form-error"),
  toastRegion: document.querySelector("#toast-region"),
  globalSearch: document.querySelector("#global-search"),
  searchResults: document.querySelector("#global-search-results"),
  processTree: document.querySelector("#process-tree"),
  evidenceTable: document.querySelector("#evidence-table-body"),
  timelineList: document.querySelector("#timeline-list"),
  hypothesisList: document.querySelector("#hypothesis-list"),
  graph: document.querySelector("#evidence-graph"),
  graphEmpty: document.querySelector("#graph-empty"),
  inspector: document.querySelector("#inspector-content"),
};

const pluginLabels = {
  "windows.info": "System information",
  "windows.pslist": "Process list",
  "windows.pstree": "Process tree",
  "windows.cmdline": "Command lines",
  "windows.netscan": "Network connections",
  "windows.dlllist": "Loaded DLLs",
  "windows.malfind": "Memory findings",
};

const viewLabels = {
  overview: {
    breadcrumb: "Case workspace",
    title: "Investigation workspace",
    subtitle: "Create a case, attach a memory image, and run selected Volatility 3 plugins.",
  },
  processes: {
    breadcrumb: "Process explorer",
    title: "Process explorer",
    subtitle: "Review process observations and PID/PPID relationships from the selected run.",
  },
  evidence: {
    breadcrumb: "Evidence",
    title: "Evidence records",
    subtitle: "Filter observed artifacts while retaining their plugin and raw-output provenance.",
  },
  graph: {
    breadcrumb: "Evidence graph",
    title: "Evidence graph",
    subtitle: "Explore deterministic links and inspect the source artifacts behind each edge.",
  },
  timeline: {
    breadcrumb: "Timeline",
    title: "Forensic timeline",
    subtitle: "Review evidence-linked timestamps without filling gaps or inferring event times.",
  },
  reconstruction: {
    breadcrumb: "Reconstruction",
    title: "Possible Attack Sequence",
    subtitle: "Deterministic investigator-review hypotheses, not conclusions of compromise.",
  },
  report: {
    breadcrumb: "Report",
    title: "Investigation report",
    subtitle: "Export findings, sources, correlation reasons, hypotheses, and limitations.",
  },
  benchmarks: {
    breadcrumb: "Benchmarks",
    title: "Benchmarking",
    subtitle: "A measurement plan with no invented results or unsupported accuracy claims.",
  },
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

function formatBytes(bytes) {
  if (bytes === null || bytes === undefined) return "Not uploaded";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = -1;
  do {
    value /= 1024;
    unit += 1;
  } while (value >= 1024 && unit < units.length - 1);
  return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[unit]}`;
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "—"
    : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function statusLabel(value) {
  return ({
    ready: "READY",
    queued: "QUEUED",
    running: "RUNNING",
    completed: "COMPLETED",
    partial: "PARTIAL",
    failed: "FAILED",
  })[value] || "NOT STARTED";
}

function setBadge(element, status, fallback = "NOT STARTED") {
  element.className = `state-badge ${["ready", "running", "completed", "partial", "failed"].includes(status) ? status : ""}`;
  element.innerHTML = `<span></span> ${escapeHtml(status ? statusLabel(status) : fallback)}`;
}

function toast(message, isError = false) {
  const item = document.createElement("div");
  item.className = `toast${isError ? " error" : ""}`;
  item.textContent = message;
  elements.toastRegion.append(item);
  window.setTimeout(() => item.remove(), 4200);
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json")
    ? await response.json()
    : await response.text();
  if (!response.ok) {
    const detail = typeof payload === "object" ? payload.detail : payload;
    throw new Error(detail || `Request failed (${response.status})`);
  }
  return payload;
}

function caseRunQuery(extra = {}) {
  const params = new URLSearchParams({ case_id: state.selectedCaseId || "" });
  if (state.selectedRunId) params.set("run_id", state.selectedRunId);
  Object.entries(extra).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") params.set(key, value);
  });
  return params;
}

async function loadHealth() {
  try {
    const health = await api("/api/health");
    const dot = document.querySelector("#volatility-dot");
    const label = document.querySelector("#volatility-status");
    const detail = document.querySelector("#volatility-detail");
    dot.className = `status-dot ${health.volatility_available ? "online" : "offline"}`;
    label.textContent = health.volatility_available ? "Volatility 3 ready" : "Volatility unavailable";
    detail.textContent = health.volatility_executable || "Install Volatility 3 to analyze images";
    state.supportedPlugins = health.supported_plugins || [];
    state.maxUploadBytes = health.max_upload_bytes || 0;
    try {
      const storage = await api("/api/storage/config");
      state.storageConfig = storage;
      if (storage.effective_limit_bytes) {
        state.maxUploadBytes = storage.effective_limit_bytes;
      }
    } catch (_) {
      state.storageConfig = null;
    }
    document.querySelector("#plugin-chip-list").innerHTML = state.supportedPlugins
      .map((plugin) => `<span class="plugin-chip">${escapeHtml(plugin)}</span>`)
      .join("");
  } catch (error) {
    document.querySelector("#volatility-status").textContent = "API unavailable";
    document.querySelector("#volatility-detail").textContent = "Check the application server";
    document.querySelector("#volatility-dot").className = "status-dot offline";
    toast(error.message, true);
  }
}

async function loadCases() {
  try {
    state.cases = await api("/api/cases");
    renderCases();
    if (!state.selectedCaseId && state.cases.length) {
      await selectCase(state.cases[0].case_id);
    } else if (state.selectedCaseId) {
      const current = state.cases.find((item) => item.case_id === state.selectedCaseId);
      if (current) renderCaseDetail(current);
    }
  } catch (error) {
    elements.caseList.innerHTML = `<div class="case-list-empty"><span class="empty-dash">!</span><span>${escapeHtml(error.message)}</span></div>`;
  }
}

function renderCases() {
  elements.caseCount.textContent = `${state.cases.length} ${state.cases.length === 1 ? "case" : "cases"}`;
  if (!state.cases.length) {
    elements.caseList.innerHTML = `<div class="case-list-empty"><span class="empty-dash">—</span><span>No cases yet. Create one to begin an investigation.</span></div>`;
    return;
  }
  elements.caseList.innerHTML = state.cases.map((item) => `
    <button type="button" class="case-row${item.case_id === state.selectedCaseId ? " selected" : ""}" data-case-id="${escapeHtml(item.case_id)}">
      <span class="case-icon" aria-hidden="true">⌕</span>
      <span class="case-row-copy">
        <strong>${escapeHtml(item.name)}</strong>
        <small>${escapeHtml(item.case_id)} · ${escapeHtml(formatDate(item.created_at))}</small>
      </span>
      <span class="case-row-state${item.has_image ? " ready" : ""}">${item.has_image ? "IMAGE READY" : "NO IMAGE"}</span>
    </button>`).join("");

  elements.caseList.querySelectorAll("[data-case-id]").forEach((button) => {
    button.addEventListener("click", () => selectCase(button.dataset.caseId));
  });
}

async function selectCase(caseId) {
  state.selectedCaseId = caseId;
  state.selectedRunId = null;
  state.caseAnalyses = [];
  state.activeRunId = null;
  window.clearTimeout(state.pollTimer);
  const item = state.cases.find((entry) => entry.case_id === caseId);
  if (!item) return;
  renderCases();
  renderCaseDetail(item);
  elements.analysisPanel.hidden = true;
  clearInvestigationViews();
  try {
    state.caseAnalyses = await api(`/api/cases/${encodeURIComponent(caseId)}/analyses`);
    if (state.caseAnalyses.length) {
      await loadRun(state.caseAnalyses[0].run_id);
    } else {
      renderRunHistory();
    }
  } catch (error) {
    toast(error.message, true);
  }
}

function renderCaseDetail(item) {
  if (!item) return;
  elements.caseTitle.textContent = item.name;
  setBadge(elements.caseState, item.has_image ? "ready" : null, item.has_image ? "IMAGE ATTACHED" : "SETUP REQUIRED");
  elements.caseDetail.innerHTML = `
    <div class="case-detail-content">
      <div class="case-meta-grid">
        <div class="meta-cell"><span>CASE ID</span><strong>${escapeHtml(item.case_id)}</strong></div>
        <div class="meta-cell"><span>CREATED</span><strong>${escapeHtml(formatDate(item.created_at))}</strong></div>
        <div class="meta-cell"><span>MEMORY IMAGE</span><strong>${escapeHtml(item.original_filename || "Not uploaded")}</strong></div>
        <div class="meta-cell"><span>IMAGE SIZE</span><strong>${escapeHtml(formatBytes(item.image_size_bytes))}</strong></div>
        <div class="meta-cell"><span>SHA-256</span><strong class="hash" title="${escapeHtml(item.image_sha256 || "")}">${escapeHtml(item.image_sha256 || "Generated when uploaded")}</strong></div>
        <div class="meta-cell"><span>LOGICAL IMAGE ID</span><strong>${escapeHtml(item.logical_image_id || "—")}</strong></div>
        <div class="meta-cell"><span>STORAGE MODE</span><strong>${escapeHtml(item.storage_type || (item.has_image ? "legacy" : "—"))}</strong></div>
        <div class="meta-cell"><span>VERIFICATION</span><strong>${escapeHtml(item.verification_status || (item.has_image ? "verified" : "—"))}</strong></div>
        <div class="meta-cell"><span>OUTPUT TYPE</span><strong>Evidence + raw plugin output</strong></div>
      </div>
      <div id="analysis-history-slot"></div>
      <div class="image-drop${item.has_image ? " has-image" : ""}">
        <div class="image-drop-title">
          <div>
            <h3>${item.has_image ? "Memory image attached" : "Attach a Windows memory image"}</h3>
            <p>${item.has_image ? "A replacement image applies to future runs; previous runs retain their source hash." : `SHA-256 is calculated during upload. Maximum size: ${escapeHtml(formatBytes(state.maxUploadBytes))}.`}</p>
          </div>
          <label class="upload-label" for="image-file">${item.has_image ? "Replace image" : "Choose image"}</label>
          <input class="file-input" id="image-file" type="file" aria-label="Select a memory image" accept=".raw,.mem,.dmp,.vmem,application/octet-stream" />
        </div>
        <div id="upload-progress-slot"></div>
        <p id="upload-error" class="upload-error" hidden></p>
      </div>
      <div class="plugins-heading">
        <strong>Select Volatility plugins</strong>
        <button class="text-button" id="select-all-plugins" type="button">Select all</button>
      </div>
      <div class="plugin-checks">
        ${state.supportedPlugins.map((plugin) => `
          <label class="plugin-option">
            <input type="checkbox" name="plugin" value="${escapeHtml(plugin)}" checked />
            <span>${escapeHtml(plugin)}</span>
          </label>`).join("")}
      </div>
      <div class="analysis-actions">
        <p>Plugins run independently. Raw output, errors, and source-image hashes are retained per run.</p>
        <button class="button button-primary" id="analyze-button" type="button"${item.has_image ? "" : " disabled"}>
          Run selected plugins
        </button>
      </div>
    </div>`;

  document.querySelector("#image-file").addEventListener("change", (event) => uploadImage(item.case_id, event.target.files?.[0]));
  document.querySelector("#select-all-plugins").addEventListener("click", () => {
    const boxes = [...document.querySelectorAll('input[name="plugin"]')];
    const shouldCheck = boxes.some((box) => !box.checked);
    boxes.forEach((box) => { box.checked = shouldCheck; });
    document.querySelector("#select-all-plugins").textContent = shouldCheck ? "Clear selection" : "Select all";
  });
  document.querySelector("#analyze-button").addEventListener("click", () => startAnalysis(item.case_id));
  renderRunHistory();
}

function renderRunHistory() {
  const slot = document.querySelector("#analysis-history-slot");
  if (!slot) return;
  if (!state.caseAnalyses.length) {
    slot.innerHTML = "";
    return;
  }
  slot.innerHTML = `
    <div class="run-history">
      <label for="analysis-run-select">ANALYSIS RUN</label>
      <select id="analysis-run-select" aria-label="Choose an analysis run">
        ${state.caseAnalyses.map((run) => `
          <option value="${escapeHtml(run.run_id)}"${run.run_id === state.selectedRunId ? " selected" : ""}>
            ${escapeHtml(run.run_id)} · ${escapeHtml(statusLabel(run.status))} · ${escapeHtml(formatDate(run.created_at))}
          </option>`).join("")}
      </select>
      <span>Each run is scoped to its recorded image SHA-256.</span>
    </div>`;
  document.querySelector("#analysis-run-select").addEventListener("change", (event) => {
    loadRun(event.target.value);
  });
}

async function loadRun(runId) {
  if (!state.selectedCaseId || !runId) return;
  window.clearTimeout(state.pollTimer);
  state.selectedRunId = runId;
  state.activeRunId = null;
  renderRunHistory();
  try {
    const run = await api(`/api/analyses/${encodeURIComponent(runId)}`);
    if (run.case_id && run.case_id !== state.selectedCaseId) {
      throw new Error("Analysis run does not belong to the selected case.");
    }
    renderAnalysis(run);
    if (run.status === "queued" || run.status === "running") {
      state.activeRunId = run.run_id;
      clearInvestigationViews();
      beginPolling(run.run_id);
    } else {
      await loadInvestigationData();
    }
  } catch (error) {
    toast(error.message, true);
  }
}

async function uploadImage(caseId, file) {
  if (!file) return;
  const errorElement = document.querySelector("#upload-error");
  errorElement.hidden = true;
  if (state.maxUploadBytes && file.size > state.maxUploadBytes) {
    errorElement.textContent = `File exceeds the configured ${formatBytes(state.maxUploadBytes)} upload limit.`;
    errorElement.hidden = false;
    return;
  }
  document.querySelector("#upload-progress-slot").innerHTML = `<div class="upload-progress" role="status" aria-label="Uploading image"><span></span></div>`;
  try {
    const formData = new FormData();
    formData.append("file", file);
    await api(`/api/cases/${encodeURIComponent(caseId)}/image`, { method: "POST", body: formData });
    toast("Memory image uploaded and SHA-256 recorded.");
    state.cases = await api("/api/cases");
    renderCases();
    const updated = state.cases.find((entry) => entry.case_id === caseId);
    if (updated) renderCaseDetail(updated);
  } catch (error) {
    errorElement.textContent = error.message;
    errorElement.hidden = false;
  } finally {
    const progress = document.querySelector("#upload-progress-slot");
    if (progress) progress.innerHTML = "";
  }
}

async function startAnalysis(caseId) {
  const plugins = [...document.querySelectorAll('input[name="plugin"]:checked')].map((input) => input.value);
  if (!plugins.length) {
    toast("Select at least one plugin.", true);
    return;
  }
  const button = document.querySelector("#analyze-button");
  button.disabled = true;
  button.textContent = "Starting analysis…";
  try {
    const run = await api("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ case_id: caseId, plugins }),
    });
    state.selectedRunId = run.run_id;
    state.activeRunId = run.run_id;
    state.caseAnalyses = [
      run,
      ...state.caseAnalyses.filter((item) => item.run_id !== run.run_id),
    ];
    renderRunHistory();
    renderAnalysis(run);
    clearInvestigationViews();
    elements.analysisPanel.hidden = false;
    elements.analysisPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
    beginPolling(run.run_id);
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
    button.textContent = "Run selected plugins";
  }
}

function beginPolling(runId) {
  window.clearTimeout(state.pollTimer);
  pollAnalysis(runId);
}

async function pollAnalysis(runId) {
  if (state.activeRunId !== runId || state.selectedRunId !== runId) return;
  try {
    const run = await api(`/api/analyses/${encodeURIComponent(runId)}`);
    renderAnalysis(run);
    if (run.status === "queued" || run.status === "running") {
      state.pollTimer = window.setTimeout(() => pollAnalysis(runId), 2500);
    } else {
      state.activeRunId = null;
      state.caseAnalyses = await api(`/api/cases/${encodeURIComponent(state.selectedCaseId)}/analyses`);
      renderRunHistory();
      await loadInvestigationData();
    }
  } catch (error) {
    toast(error.message, true);
  }
}

function renderAnalysis(run) {
  elements.analysisPanel.hidden = false;
  setBadge(elements.analysisState, run.status);
  const items = run.plugin_results || [];
  const complete = items.filter((item) => item.status === "completed").length;
  const failed = items.filter((item) => item.status === "failed").length;
  const queued = items.filter((item) => item.status === "queued").length;
  const running = items.filter((item) => item.status === "running").length;
  const active = queued + running;
  elements.analysisSummary.innerHTML = `
    <span>Run <strong>${escapeHtml(run.run_id)}</strong></span>
    <span>Source image <strong>${escapeHtml(run.source_image_filename || "Not recorded")}</strong></span>
    <span>Plugins <strong>${items.length}</strong></span>
    <span>Completed <strong>${complete}</strong></span>
    <span>Failed <strong>${failed}</strong></span>
    ${active ? `<span>Pending <strong>${active}</strong></span>` : ""}
    <span>Started <strong>${escapeHtml(formatDate(run.started_at))}</strong></span>
    <span>Completed at <strong>${escapeHtml(formatDate(run.completed_at))}</strong></span>
    <span>Source SHA-256 <strong title="${escapeHtml(run.source_image_sha256 || "")}">${escapeHtml(run.source_image_sha256 ? `${run.source_image_sha256.slice(0, 16)}…` : "Not recorded")}</strong></span>`;
  const summary = run.evidence_summary || {};
  elements.analysisMetrics.innerHTML = [
    ["Evidence", summary.evidence_count],
    ["Processes", summary.process_count],
    ["Network", summary.network_count],
    ["DLLs", summary.dll_count],
    ["Memory-plugin artifacts", summary.memory_findings_count],
    ["Relationships", summary.relationship_count],
    ["Timeline events", summary.event_count],
    ["Hypotheses", summary.hypothesis_count],
  ].map(([label, value]) => `
    <div class="metric-card"><span>${escapeHtml(label)}</span><strong>${Number(value || 0)}</strong></div>
  `).join("");
  const globalError = run.error ? `<p class="analysis-global-error">${escapeHtml(run.error)}</p>` : "";
  elements.pluginResults.innerHTML = globalError + items.map((item) => `
    <article class="plugin-result">
      <span class="plugin-result-name" title="${escapeHtml(pluginLabels[item.plugin] || item.plugin)}">${escapeHtml(item.plugin)}</span>
      <span class="plugin-result-status ${escapeHtml(item.status)}">${escapeHtml(statusLabel(item.status))}${item.exit_code === null || item.exit_code === undefined ? "" : ` · EXIT ${escapeHtml(item.exit_code)}`}</span>
      ${item.duration_seconds !== undefined ? `<span class="plugin-result-duration">${escapeHtml(item.duration_seconds)}s</span>` : ""}
      ${item.error ? `<div class="plugin-error">${escapeHtml(item.error)}</div>` : ""}
      ${item.parse_error ? `<div class="plugin-error">JSON parsing: ${escapeHtml(item.parse_error)}</div>` : ""}
      ${item.raw_output_url || item.raw_error_url || item.structured_output_url ? `<div class="plugin-output-links">
        ${item.structured_output_url ? `<a href="${escapeHtml(item.structured_output_url)}" target="_blank" rel="noopener">View structured JSON</a>` : ""}
        ${item.raw_output_url ? `<a href="${escapeHtml(item.raw_output_url)}" target="_blank" rel="noopener">View raw output</a>` : ""}
        ${item.raw_error_url ? `<a href="${escapeHtml(item.raw_error_url)}" target="_blank" rel="noopener">View stderr</a>` : ""}
      </div>` : ""}
    </article>`).join("");
}

function clearInvestigationViews() {
  state.graph = { nodes: [], edges: [], truncated: false };
  document.querySelector("#analysis-metrics").innerHTML = "";
  document.querySelector("#process-count").textContent = "0 processes";
  document.querySelector("#evidence-count").textContent = "0 records";
  document.querySelector("#graph-count").textContent = "0 nodes · 0 edges";
  document.querySelector("#timeline-count").textContent = "0 events";
  elements.processTree.innerHTML = `<div class="empty-module">Complete an analysis to view process artifacts.</div>`;
  elements.evidenceTable.innerHTML = `<tr><td colspan="6" class="empty-table">No evidence loaded.</td></tr>`;
  elements.timelineList.innerHTML = `<div class="empty-module">Complete an analysis to build the timeline.</div>`;
  elements.hypothesisList.innerHTML = `<div class="empty-module">Complete an analysis to evaluate the deterministic sequence rules.</div>`;
  elements.graph.innerHTML = "";
  elements.graphEmpty.hidden = false;
  elements.graphEmpty.textContent = "Complete an analysis to build an evidence graph.";
  elements.inspector.innerHTML = "<p>Select a graph node, edge, or evidence record to inspect its source.</p>";
  document.querySelector("#download-report").disabled = true;
  document.querySelector("#evidence-page-label").textContent = "Page 1";
}

async function loadInvestigationData() {
  if (!state.selectedCaseId || !state.selectedRunId) {
    clearInvestigationViews();
    return;
  }
  const caseId = encodeURIComponent(state.selectedCaseId);
  const runId = encodeURIComponent(state.selectedRunId);
  const base = `case_id=${caseId}&run_id=${runId}`;
  try {
    const [summary, processes, graph, timeline, hypotheses] = await Promise.all([
      api(`/api/cases/${caseId}/summary?run_id=${runId}`),
      api(`/api/processes?${base}&page=1&page_size=500`),
      api(`/api/graph?${base}&limit=200`),
      api(`/api/timeline?${base}&page=1&page_size=500`),
      api(`/api/hypotheses?${base}`),
    ]);
    renderSummary(summary);
    renderProcesses(processes.items || []);
    state.graph = graph;
    renderGraph(graph);
    renderTimeline(timeline.items || [], timeline.total || 0);
    renderHypotheses(hypotheses || []);
    state.evidencePage = 1;
    document.querySelector("#download-report").disabled = false;
    await loadEvidencePage();
  } catch (error) {
    toast(`Could not load investigation data: ${error.message}`, true);
  }
}

function renderSummary(summary) {
  document.querySelector("#process-count").textContent = `${summary.process_count || 0} processes`;
  document.querySelector("#timeline-count").textContent = `${summary.event_count || 0} events`;
  const osValues = Object.entries(summary.os_info || {}).map(([key, value]) => `${key}: ${value}`);
  document.querySelector("#os-summary").textContent = osValues.length
    ? `OS information from windows.info: ${osValues.join(" · ")}`
    : "OS information was not available in windows.info output for this run.";
}

function artifactText(record) {
  const artifact = record.artifact || {};
  if (record.type === "process") {
    return record.process_name || artifact.ImageFileName || artifact.Name || "Process";
  }
  if (record.type === "network") {
    const address = artifact.ForeignAddr || artifact.RemoteAddress || artifact.LocalAddr || "Endpoint unavailable";
    const port = artifact.ForeignPort || artifact.RemotePort || artifact.LocalPort;
    return `${address}${port ? `:${port}` : ""}`;
  }
  if (record.type === "command") {
    return artifact.Args || artifact.CommandLine || artifact.Command || "Command line unavailable";
  }
  if (record.type === "dll") {
    return artifact.MappedPath || artifact.Path || artifact.Name || "DLL path unavailable";
  }
  if (record.type === "memory") {
    return artifact.Protection || artifact.Tag || "Memory artifact";
  }
  return artifact.Value || artifact.KernelBase || Object.values(artifact).slice(0, 2).join(" · ") || "System artifact";
}

function renderProcesses(items) {
  const chosenByPid = new Map();
  const noPid = [];
  for (const record of items) {
    if (!record.pid) {
      noPid.push(record);
      continue;
    }
    const current = chosenByPid.get(record.pid);
    if (!current || (record.source_plugin === "windows.pstree" && current.source_plugin !== "windows.pstree")) {
      chosenByPid.set(record.pid, record);
    }
  }
  const processes = [...chosenByPid.values(), ...noPid];
  const query = (document.querySelector("#process-query").value || "").trim().toLowerCase();
  const filtered = query
    ? processes.filter((record) => `${record.process_name || ""} ${record.pid || ""} ${record.ppid || ""} ${record.evidence_id}`.toLowerCase().includes(query))
    : processes;
  if (!filtered.length) {
    elements.processTree.innerHTML = `<div class="empty-module">${processes.length ? "No process records match this filter." : "No process artifacts were extracted for this analysis."}</div>`;
    return;
  }
  const byPid = new Map(filtered.filter((record) => record.pid).map((record) => [record.pid, record]));
  const children = new Map();
  for (const record of filtered) {
    if (record.ppid && byPid.has(record.ppid) && record.ppid !== record.pid) {
      const siblings = children.get(record.ppid) || [];
      siblings.push(record);
      children.set(record.ppid, siblings);
    }
  }
  const compare = (a, b) => String(a.process_name || "").localeCompare(String(b.process_name || ""));
  const roots = filtered.filter((record) => !record.ppid || !byPid.has(record.ppid) || record.ppid === record.pid).sort(compare);
  const visited = new Set();
  let markup = "";
  const draw = (record, depth) => {
    if (visited.has(record.evidence_id) || depth > 30) return;
    visited.add(record.evidence_id);
    markup += `
      <button type="button" class="process-tree-row" style="margin-left:${Math.min(depth, 12) * 16}px" data-evidence-id="${escapeHtml(record.evidence_id)}">
        <span class="tree-branch" aria-hidden="true">${depth ? "└─" : "●"}</span>
        <span class="tree-process">${escapeHtml(record.process_name || "Process name unavailable")}</span>
        <span class="tree-pid">PID ${escapeHtml(record.pid || "—")} · PPID ${escapeHtml(record.ppid || "—")}</span>
        <span class="tree-evidence">${escapeHtml(record.evidence_id)}</span>
        <span class="tree-source">${escapeHtml(record.source_plugin)} · ${escapeHtml(record.timestamp || "Creation time unavailable")}</span>
      </button>`;
    for (const child of (children.get(record.pid) || []).sort(compare)) draw(child, depth + 1);
  };
  roots.forEach((record) => draw(record, 0));
  filtered.filter((record) => !visited.has(record.evidence_id)).sort(compare).forEach((record) => draw(record, 0));
  elements.processTree.innerHTML = markup;
}

async function loadEvidencePage() {
  if (!state.selectedCaseId || !state.selectedRunId) return;
  const params = caseRunQuery({
    type: document.querySelector("#evidence-type-filter").value,
    relationship_type: document.querySelector("#evidence-relationship-filter").value,
    q: document.querySelector("#global-search").value.trim(),
    page: state.evidencePage,
    page_size: state.evidencePageSize,
  });
  try {
    const result = await api(`/api/evidence?${params}`);
    state.evidenceTotal = result.total || 0;
    renderEvidence(result.items || [], result.total || 0);
  } catch (error) {
    toast(error.message, true);
  }
}

function renderEvidence(items, total) {
  document.querySelector("#evidence-count").textContent = `${total} ${total === 1 ? "record" : "records"}`;
  const maxPage = Math.max(1, Math.ceil(total / state.evidencePageSize));
  document.querySelector("#evidence-page-label").textContent = `Page ${state.evidencePage} of ${maxPage}`;
  document.querySelector("#evidence-prev").disabled = state.evidencePage <= 1;
  document.querySelector("#evidence-next").disabled = state.evidencePage >= maxPage;
  if (!items.length) {
    elements.evidenceTable.innerHTML = `<tr><td colspan="6" class="empty-table">${total ? "No records match these filters." : "No evidence artifacts were extracted for this run."}</td></tr>`;
    return;
  }
  elements.evidenceTable.innerHTML = items.map((record) => `
    <tr tabindex="0" role="button" data-evidence-id="${escapeHtml(record.evidence_id)}">
      <td class="table-id">${escapeHtml(record.evidence_id)}</td>
      <td><span class="type-pill">${escapeHtml(record.type)}</span></td>
      <td class="table-code">${escapeHtml(record.pid || "—")} / ${escapeHtml(record.ppid || "—")}</td>
      <td><span class="table-entity" title="${escapeHtml(artifactText(record))}">${escapeHtml(artifactText(record))}</span></td>
      <td class="table-code">${escapeHtml(record.source_plugin)}</td>
      <td class="confidence-pill">${escapeHtml(record.confidence)}</td>
    </tr>`).join("");
}

function renderGraph(graph) {
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  document.querySelector("#graph-count").textContent = `${nodes.length} nodes · ${edges.length} edges${graph.truncated ? " · capped" : ""}`;
  if (!nodes.length) {
    elements.graph.innerHTML = "";
    elements.graphEmpty.hidden = false;
    elements.graphEmpty.textContent = "No graphable evidence artifacts were extracted for this run.";
    return;
  }
  elements.graphEmpty.hidden = true;
  const columns = ["process", "command", "dll", "network", "memory", "system"];
  const positions = new Map();
  const grouped = new Map(columns.map((type) => [type, []]));
  for (const node of nodes) {
    const nodeType = grouped.has(node.type) ? node.type : "system";
    grouped.get(nodeType).push(node);
  }
  const width = Math.max(720, 46 + columns.length * 160);
  const maxRows = Math.max(1, ...[...grouped.values()].map((rows) => rows.length));
  const height = Math.max(300, 60 + maxRows * 86);
  columns.forEach((type, columnIndex) => {
    (grouped.get(type) || []).forEach((node, rowIndex) => {
      positions.set(node.evidence_id, {
        x: 22 + columnIndex * 160,
        y: 31 + rowIndex * 86,
      });
    });
  });
  const edgeMarkup = edges.map((edge, index) => {
    const source = positions.get(edge.source);
    const target = positions.get(edge.target);
    if (!source || !target) return "";
    const x1 = source.x + 63;
    const y1 = source.y + 23;
    const x2 = target.x + 63;
    const y2 = target.y + 23;
    const label = String(edge.relationship_type || "").replaceAll("_", " ").slice(0, 20);
    return `<g class="graph-edge-group" data-edge-index="${index}" tabindex="0" role="button" aria-label="${escapeHtml(edge.relationship_type)} relationship">
      <title>${escapeHtml(edge.reason || edge.relationship_type)}</title>
      <line class="graph-edge" x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}"></line>
      <text class="graph-edge-label" x="${(x1 + x2) / 2}" y="${(y1 + y2) / 2 - 4}" text-anchor="middle">${escapeHtml(label)}</text>
    </g>`;
  }).join("");
  const nodeMarkup = nodes.map((node) => {
    const point = positions.get(node.evidence_id);
    if (!point) return "";
    const label = String(node.label || node.evidence_id);
    const shortLabel = label.length > 19 ? `${label.slice(0, 18)}…` : label;
    const type = columns.includes(node.type) ? node.type : "system";
    return `<g class="graph-node type-${escapeHtml(type)}" data-evidence-id="${escapeHtml(node.evidence_id)}" transform="translate(${point.x},${point.y})" tabindex="0" role="button" aria-label="${escapeHtml(label)}">
      <title>${escapeHtml(label)} · ${escapeHtml(node.evidence_id)}</title>
      <rect class="graph-node-shape" x="0" y="0" width="126" height="48" rx="6"></rect>
      <text class="graph-node-label" x="63" y="19" text-anchor="middle">${escapeHtml(shortLabel)}</text>
      <text class="graph-node-kind" x="63" y="36" text-anchor="middle">${escapeHtml(type.toUpperCase())} · ${escapeHtml(node.evidence_id.slice(-8))}</text>
    </g>`;
  }).join("");
  elements.graph.setAttribute("viewBox", `0 0 ${width} ${height}`);
  elements.graph.style.height = `${height}px`;
  elements.graph.innerHTML = `${edgeMarkup}${nodeMarkup}`;
  elements.graph.querySelectorAll("[data-evidence-id]").forEach((node) => {
    const open = () => showEvidenceInspector(node.dataset.evidenceId);
    node.addEventListener("click", open);
    node.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        open();
      }
    });
  });
  elements.graph.querySelectorAll("[data-edge-index]").forEach((edgeElement) => {
    const open = () => showRelationshipInspector(state.graph.edges[Number(edgeElement.dataset.edgeIndex)]);
    edgeElement.addEventListener("click", open);
    edgeElement.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        open();
      }
    });
  });
}

function renderTimeline(items, total) {
  document.querySelector("#timeline-count").textContent = `${total} ${total === 1 ? "event" : "events"}`;
  const filter = document.querySelector("#timeline-type-filter").value;
  const filtered = filter === "malfind"
    ? items.filter((item) => item.source_plugin === "windows.malfind")
    : filter ? items.filter((item) => item.event_type === filter) : items;
  if (!filtered.length) {
    elements.timelineList.innerHTML = `<div class="empty-module">${total ? "No events match this filter." : "No timestamped or untimed events were extracted for this analysis."}</div>`;
    return;
  }
  elements.timelineList.innerHTML = filtered.map((event) => `
    <article class="timeline-item">
      <time class="timeline-time">${escapeHtml(event.timestamp || "Time unavailable")}</time>
      <span class="timeline-rail"><i class="timeline-marker"></i></span>
      <div class="timeline-copy">
        <strong>${escapeHtml(event.event_type)}</strong>
        <p>${escapeHtml(event.description)}</p>
        <div class="timeline-source">
          <button type="button" class="timeline-evidence" data-evidence-id="${escapeHtml(event.evidence_id)}">${escapeHtml(event.evidence_id)}</button>
          <span>${escapeHtml(event.source_plugin)}</span>
          ${event.related_pid ? `<span>PID ${escapeHtml(event.related_pid)}</span>` : ""}
        </div>
      </div>
    </article>`).join("");
}

function renderHypotheses(hypotheses) {
  if (!hypotheses.length) {
    elements.hypothesisList.innerHTML = `<div class="empty-module">No deterministic rule matched the required process and network evidence. This does not establish that suspicious activity did not occur.</div>`;
    return;
  }
  elements.hypothesisList.innerHTML = hypotheses.map((hypothesis) => `
    <article class="hypothesis-card">
      <div class="section-kicker">${escapeHtml(hypothesis.hypothesis_id)} · HYPOTHESIS</div>
      <h3>${escapeHtml(hypothesis.title)}</h3>
      <p>${escapeHtml(hypothesis.description)}</p>
      <div class="hypothesis-rationale"><strong>Why this sequence was generated:</strong> ${escapeHtml(hypothesis.rationale)}</div>
      <ol class="hypothesis-step-list">
        ${(hypothesis.steps || []).map((step) => `
          <li class="hypothesis-step">
            <div><strong>${escapeHtml(step.stage)}</strong><p>${escapeHtml(step.description)}</p>
              <p>Evidence: ${(step.evidence_ids || []).map((id) => `<button class="evidence-id-link" type="button" data-evidence-id="${escapeHtml(id)}">${escapeHtml(id)}</button>`).join(", ") || "None"}</p>
            </div>
          </li>`).join("")}
      </ol>
      <div class="inspector-section"><h4>SUPPORTING RELATIONSHIPS</h4><p class="inspector-reason">${(hypothesis.supporting_relationship_ids || []).map(escapeHtml).join(", ") || "None"}</p></div>
      <div class="inspector-section"><h4>LIMITATIONS</h4><ul class="hypothesis-limitations">${(hypothesis.limitations || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul></div>
    </article>`).join("");
}

function renderEvidenceInspector(record) {
  if (!record) return;
  const relationships = record.relationships || [];
  const pidEvidence = record.pid_linked_evidence || [];
  const timelineEvents = record.timeline_events || [];
  const memoryFlags = pidEvidence.filter((item) => item.type === "memory");
  elements.inspector.innerHTML = `
    <div class="inspector-section">
      <h4>OBSERVED ARTIFACT</h4>
      <div class="inspector-meta">
        <div><span>EVIDENCE ID</span><strong>${escapeHtml(record.evidence_id)}</strong></div>
        <div><span>TYPE / CLASS</span><strong>${escapeHtml(record.type)} · ${escapeHtml(record.confidence)}</strong></div>
        <div><span>PID / PPID</span><strong>${escapeHtml(record.pid || "—")} / ${escapeHtml(record.ppid || "—")}</strong></div>
        <div><span>PLUGIN</span><strong>${escapeHtml(record.source_plugin)}</strong></div>
        <div><span>ROW</span><strong>${escapeHtml(record.source_row)}</strong></div>
        <div><span>TIMESTAMP</span><strong>${escapeHtml(record.timestamp || "Unavailable")}</strong></div>
      </div>
      ${record.raw_source_url ? `<a class="inspector-link" href="${escapeHtml(record.raw_source_url)}" target="_blank" rel="noopener">Open raw plugin output</a>` : ""}
    </div>
    <div class="inspector-section"><h4>RAW PARSED ROW</h4><pre class="inspector-artifact">${escapeHtml(JSON.stringify(record.artifact || {}, null, 2))}</pre></div>
    ${record.type === "process" ? `
      <div class="inspector-section">
        <h4>SAME-PID ARTIFACTS · ${pidEvidence.length}</h4>
        <p class="inspector-reason">Shared PID is a deterministic join key, not proof of causation.</p>
        ${pidEvidence.length ? pidEvidence.map((item) => `
          <button class="inspector-rel-row" type="button" data-evidence-id="${escapeHtml(item.evidence_id)}">
            ${escapeHtml(item.type.toUpperCase())} · ${escapeHtml(artifactText(item))}<br>
            ${escapeHtml(item.evidence_id)} · ${escapeHtml(item.source_plugin)}
          </button>`).join("") : `<p class="inspector-reason">No other extracted artifacts report this PID.</p>`}
      </div>
      <div class="inspector-section">
        <h4>MEMORY-PLUGIN OBSERVATIONS · ${memoryFlags.length}</h4>
        <p class="inspector-reason">Volatility memory-plugin output is an observed indicator for analyst review, not a malware or compromise verdict.</p>
        ${memoryFlags.length ? memoryFlags.map((item) => `
          <button class="inspector-rel-row" type="button" data-evidence-id="${escapeHtml(item.evidence_id)}">
            ${escapeHtml(artifactText(item))}<br>${escapeHtml(item.evidence_id)} · ${escapeHtml(item.source_plugin)}
          </button>`).join("") : `<p class="inspector-reason">No memory-plugin artifacts reported this PID.</p>`}
      </div>` : ""}
    <div class="inspector-section">
      <h4>TIMELINE EVENTS · ${timelineEvents.length}</h4>
      ${timelineEvents.length ? timelineEvents.map((item) => `
        <p class="inspector-reason">${escapeHtml(item.timestamp || "Time unavailable")} · ${escapeHtml(item.event_type)}<br>${escapeHtml(item.description)}</p>
      `).join("") : `<p class="inspector-reason">No timeline event was generated for this evidence record.</p>`}
    </div>
    <div class="inspector-section"><h4>RECORDED RELATIONSHIPS · ${relationships.length}</h4>
      ${relationships.length ? relationships.map((relationship) => `
        <button class="inspector-rel-row" type="button" data-evidence-id="${escapeHtml(relationship.related_evidence?.evidence_id || "")}">
          ${escapeHtml(relationship.relationship_type)}<br>${escapeHtml(relationship.reason)}
        </button>`).join("") : `<p class="inspector-reason">No deterministic relationship was recorded for this artifact.</p>`}
    </div>`;
  elements.inspector.querySelectorAll(".inspector-rel-row[data-evidence-id]").forEach((button) => {
    button.addEventListener("click", () => showEvidenceInspector(button.dataset.evidenceId));
  });
}

async function showEvidenceInspector(evidenceId) {
  if (!evidenceId) return;
  try {
    const record = await api(`/api/evidence/${encodeURIComponent(evidenceId)}`);
    renderEvidenceInspector(record);
  } catch (error) {
    toast(error.message, true);
  }
}

async function showRelationshipInspector(relationship) {
  if (!relationship) return;
  const sourceId = relationship.source_evidence_id || relationship.source;
  const targetId = relationship.target_evidence_id || relationship.target;
  try {
    const [source, target] = await Promise.all([
      api(`/api/evidence/${encodeURIComponent(sourceId)}`),
      api(`/api/evidence/${encodeURIComponent(targetId)}`),
    ]);
    elements.inspector.innerHTML = `
      <div class="inspector-section">
        <h4>CORRELATED RELATIONSHIP</h4>
        <div class="inspector-meta">
          <div><span>TYPE</span><strong>${escapeHtml(relationship.relationship_type)}</strong></div>
          <div><span>CONFIDENCE CLASS</span><strong>${escapeHtml(relationship.confidence || "correlated")}</strong></div>
          <div><span>RELATIONSHIP ID</span><strong>${escapeHtml(relationship.relationship_id || "—")}</strong></div>
          <div><span>SOURCE PLUGIN</span><strong>${escapeHtml(relationship.source_plugin || "—")}</strong></div>
        </div>
        <p class="inspector-reason">${escapeHtml(relationship.reason || "No correlation reason provided.")}</p>
        <div class="inspector-section"><h4>FIELDS USED FOR JOIN</h4><pre class="inspector-artifact">${escapeHtml(JSON.stringify(relationship.matched_fields || {}, null, 2))}</pre></div>
      </div>
      <div class="inspector-section"><h4>SOURCE EVIDENCE · ${escapeHtml(source.evidence_id)}</h4><p class="inspector-reason">${escapeHtml(artifactText(source))}</p><pre class="inspector-artifact">${escapeHtml(JSON.stringify(source.artifact || {}, null, 2))}</pre><a class="inspector-link" href="${escapeHtml(source.raw_source_url || "#")}" target="_blank" rel="noopener">Open source plugin output</a></div>
      <div class="inspector-section"><h4>TARGET EVIDENCE · ${escapeHtml(target.evidence_id)}</h4><p class="inspector-reason">${escapeHtml(artifactText(target))}</p><pre class="inspector-artifact">${escapeHtml(JSON.stringify(target.artifact || {}, null, 2))}</pre><a class="inspector-link" href="${escapeHtml(target.raw_source_url || "#")}" target="_blank" rel="noopener">Open source plugin output</a></div>`;
  } catch (error) {
    toast(error.message, true);
  }
}

async function performGlobalSearch() {
  const query = elements.globalSearch.value.trim();
  if (!query || !state.selectedCaseId || !state.selectedRunId) {
    elements.searchResults.hidden = true;
    return;
  }
  try {
    const params = caseRunQuery({ q: query });
    const result = await api(`/api/search?${params}`);
    const evidence = result.evidence || [];
    const relationships = result.relationships || [];
    if (!evidence.length && !relationships.length) {
      elements.searchResults.innerHTML = `<div class="search-empty">No matches in this analysis run.</div>`;
    } else {
      elements.searchResults.innerHTML = `
        ${evidence.length ? `<div class="search-result-heading">EVIDENCE · ${result.evidence_total}</div>${evidence.map((record) => `
          <button type="button" class="search-result" data-search-evidence="${escapeHtml(record.evidence_id)}">
            <strong>${escapeHtml(record.evidence_id)} · ${escapeHtml(record.type)}</strong>
            <small>${escapeHtml(artifactText(record))} · ${escapeHtml(record.source_plugin)}</small>
          </button>`).join("")}` : ""}
        ${relationships.length ? `<div class="search-result-heading">RELATIONSHIPS</div>${relationships.map((relationship) => `
          <button type="button" class="search-result" data-search-relationship="${escapeHtml(relationship.relationship_id)}">
            <strong>${escapeHtml(relationship.relationship_type)}</strong>
            <small>${escapeHtml(relationship.reason)}</small>
          </button>`).join("")}` : ""}`;
      elements.searchResults.querySelectorAll("[data-search-evidence]").forEach((button) => {
        button.addEventListener("click", async () => {
          switchView("evidence");
          elements.searchResults.hidden = true;
          await showEvidenceInspector(button.dataset.searchEvidence);
        });
      });
      elements.searchResults.querySelectorAll("[data-search-relationship]").forEach((button) => {
        button.addEventListener("click", async () => {
          const relationship = relationships.find((item) => item.relationship_id === button.dataset.searchRelationship);
          switchView("graph");
          elements.searchResults.hidden = true;
          await showRelationshipInspector(relationship);
        });
      });
    }
    elements.searchResults.hidden = false;
  } catch (error) {
    elements.searchResults.innerHTML = `<div class="search-empty">${escapeHtml(error.message)}</div>`;
    elements.searchResults.hidden = false;
  }
}

function switchView(view) {
  if (!viewLabels[view]) return;
  state.currentView = view;
  document.querySelector("#overview-view").hidden = view !== "overview";
  document.querySelectorAll(".module-view").forEach((section) => {
    section.hidden = section.id !== `${view}-view`;
  });
  document.querySelectorAll(".nav-link[data-view]").forEach((link) => {
    link.classList.toggle("active", link.dataset.view === view);
  });
  document.querySelector("#breadcrumb-page").textContent = viewLabels[view].breadcrumb;
  document.querySelector("#page-title").textContent = viewLabels[view].title;
  document.querySelector("#page-subtitle").textContent = viewLabels[view].subtitle;
  elements.searchResults.hidden = true;
}

function openCaseDialog() {
  elements.caseForm.reset();
  elements.caseFormError.textContent = "";
  elements.dialog.showModal();
  window.setTimeout(() => elements.caseName.focus(), 0);
}

elements.caseForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const name = elements.caseName.value.trim();
  elements.caseFormError.textContent = "";
  if (!name) {
    elements.caseFormError.textContent = "Enter a case name.";
    return;
  }
  const submit = document.querySelector("#create-case-submit");
  submit.disabled = true;
  try {
    const created = await api("/api/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    elements.dialog.close();
    state.selectedCaseId = created.case_id;
    await loadCases();
    await selectCase(created.case_id);
    switchView("overview");
    toast(`Case ${created.case_id} created.`);
  } catch (error) {
    elements.caseFormError.textContent = error.message;
  } finally {
    submit.disabled = false;
  }
});

document.querySelectorAll(".nav-link[data-view]").forEach((link) => {
  link.addEventListener("click", (event) => {
    event.preventDefault();
    switchView(link.dataset.view);
  });
});
document.querySelector("#new-case-button").addEventListener("click", openCaseDialog);
document.querySelector("#empty-create-button").addEventListener("click", openCaseDialog);
document.querySelector("#dialog-close").addEventListener("click", () => elements.dialog.close());
document.querySelector("#dialog-cancel").addEventListener("click", () => elements.dialog.close());
document.querySelector("#evidence-type-filter").addEventListener("change", () => {
  state.evidencePage = 1;
  loadEvidencePage();
});
document.querySelector("#evidence-relationship-filter").addEventListener("change", () => {
  state.evidencePage = 1;
  loadEvidencePage();
});
document.querySelector("#evidence-prev").addEventListener("click", () => {
  state.evidencePage = Math.max(1, state.evidencePage - 1);
  loadEvidencePage();
});
document.querySelector("#evidence-next").addEventListener("click", () => {
  state.evidencePage += 1;
  loadEvidencePage();
});
document.querySelector("#process-query").addEventListener("input", () => {
  api(`/api/processes?${caseRunQuery({ page: 1, page_size: 500 })}`)
    .then((result) => renderProcesses(result.items || []))
    .catch((error) => toast(error.message, true));
});
document.querySelector("#timeline-type-filter").addEventListener("change", () => {
  if (!state.selectedCaseId || !state.selectedRunId) return;
  api(`/api/timeline?${caseRunQuery({ page: 1, page_size: 500 })}`)
    .then((result) => renderTimeline(result.items || [], result.total || 0))
    .catch((error) => toast(error.message, true));
});
elements.evidenceTable.addEventListener("click", (event) => {
  const row = event.target.closest("[data-evidence-id]");
  if (row) showEvidenceInspector(row.dataset.evidenceId);
});
elements.evidenceTable.addEventListener("keydown", (event) => {
  const row = event.target.closest("[data-evidence-id]");
  if (row && (event.key === "Enter" || event.key === " ")) {
    event.preventDefault();
    showEvidenceInspector(row.dataset.evidenceId);
  }
});
elements.processTree.addEventListener("click", (event) => {
  const row = event.target.closest("[data-evidence-id]");
  if (row) showEvidenceInspector(row.dataset.evidenceId);
});
elements.timelineList.addEventListener("click", (event) => {
  const button = event.target.closest("[data-evidence-id]");
  if (button) showEvidenceInspector(button.dataset.evidenceId);
});
elements.hypothesisList.addEventListener("click", (event) => {
  const button = event.target.closest("[data-evidence-id]");
  if (button) showEvidenceInspector(button.dataset.evidenceId);
});
elements.globalSearch.addEventListener("input", () => {
  window.clearTimeout(state.searchTimer);
  state.searchTimer = window.setTimeout(performGlobalSearch, 220);
});
elements.globalSearch.addEventListener("keydown", (event) => {
  if (event.key === "Enter") performGlobalSearch();
  if (event.key === "Escape") elements.searchResults.hidden = true;
});
document.addEventListener("click", (event) => {
  if (!event.target.closest(".global-search-wrap")) elements.searchResults.hidden = true;
});
document.addEventListener("keydown", (event) => {
  if (event.key === "/" && !["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName)) {
    event.preventDefault();
    elements.globalSearch.focus();
  }
});
document.querySelector("#download-report").addEventListener("click", () => {
  if (!state.selectedCaseId || !state.selectedRunId) return;
  const params = new URLSearchParams({
    case_id: state.selectedCaseId,
    run_id: state.selectedRunId,
  });
  window.location.assign(`/api/report?${params}`);
});

loadHealth();
loadCases();