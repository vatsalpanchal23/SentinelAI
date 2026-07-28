function escapeHtml(str) {
  // Finding text (server headers, crawled paths, form actions, cookie
  // names...) comes from whatever the *target* site returns, not from us --
  // treat it as untrusted and never let it land in innerHTML unescaped.
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

function badgeClass(status) {
  const base = "text-xs uppercase tracking-wide px-2 py-0.5 rounded ";
  if (status === "completed") return base + "bg-emerald-500/20 text-emerald-400";
  if (status === "running") return base + "bg-amber-500/20 text-amber-400";
  if (status === "failed") return base + "bg-red-500/20 text-red-400";
  return base + "bg-slate-700 text-slate-300";
}

function formatDuration(seconds) {
  if (seconds === null || seconds === undefined) return "";
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
}

function renderSeverityCounts(data) {
  const riskEl = document.getElementById("risk-score");
  if (riskEl) riskEl.textContent = data.risk_score;

  ["critical", "high", "medium", "low", "info"].forEach((sev) => {
    const el = document.querySelector(`[data-severity-count="${sev}"]`);
    if (el) el.textContent = data.severity_counts[sev] ?? 0;
  });
}

function renderModules(data) {
  data.modules.forEach((m) => {
    const el = document.querySelector(`[data-module-status="${m.name}"]`);
    if (el) {
      el.textContent = m.status;
      el.className = badgeClass(m.status);
    }
    const durEl = document.querySelector(`[data-module-duration="${m.name}"]`);
    if (durEl) durEl.textContent = formatDuration(m.duration_seconds);

    const reasonEl = document.querySelector(`[data-module-failure="${m.name}"]`);
    if (m.status === "failed") {
      if (reasonEl) {
        reasonEl.textContent = m.failure_reason ?? "";
      } else {
        // module just failed for the first time this session -- the
        // failure-reason row wasn't server-rendered, so add it now.
        const row = el?.closest("div.flex")?.parentElement;
        if (row) {
          const div = document.createElement("div");
          div.className = "px-4 pb-2 text-xs text-red-400";
          div.setAttribute("data-module-failure", m.name);
          div.textContent = m.failure_reason ?? "";
          row.insertBefore(div, el.closest("div.flex").nextSibling);
        }
      }
    }
  });
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const SEVERITY_BORDER = {
  critical: "border-red-600",
  high: "border-orange-500",
  medium: "border-amber-500",
  low: "border-lime-600",
  info: "border-slate-600",
};

function findingCard(f) {
  const div = document.createElement("div");
  const border = SEVERITY_BORDER[f.severity] || "border-slate-600";
  div.className = `border-l-4 ${border} rounded-lg px-4 py-3 mb-2 bg-slate-900/40`;
  div.setAttribute("data-finding-id", f.id);
  div.setAttribute("data-severity", f.severity);
  div.innerHTML = `
    <div class="font-medium text-sm">${escapeHtml(f.title)}</div>
    <div class="text-xs text-slate-500 mt-1 uppercase tracking-wide">${escapeHtml(f.severity)} &middot; ${escapeHtml(f.source_modules ?? "")}</div>
    ${f.description ? `<div class="text-xs text-slate-400 mt-2 whitespace-pre-line">${escapeHtml(f.description)}</div>` : ""}
    ${f.recommendation ? `<div class="text-xs text-emerald-400/80 mt-2">Fix: ${escapeHtml(f.recommendation)}</div>` : ""}
  `;
  return div;
}

// Findings only ever grow during a run. Insert each new card in severity
// order (critical first) rather than plain append, so a critical finding
// surfaces to the top immediately instead of wherever it happened to land
// in discovery order.
function renderFindings(data) {
  const container = document.getElementById("findings-list");
  if (!container) return;

  const placeholder = document.getElementById("no-findings-placeholder");
  if (data.findings.length && placeholder) placeholder.remove();
  if (!data.findings.length && !placeholder && !container.children.length) {
    container.innerHTML = '<p class="text-sm text-slate-500" id="no-findings-placeholder">No findings yet.</p>';
    return;
  }

  const seen = new Set(
    Array.from(container.querySelectorAll("[data-finding-id]")).map((el) => el.getAttribute("data-finding-id"))
  );

  data.findings.forEach((f) => {
    if (seen.has(String(f.id))) return;
    const card = findingCard(f);
    const rank = SEVERITY_ORDER[f.severity] ?? 99;
    const existing = Array.from(container.children).find(
      (el) => (SEVERITY_ORDER[el.getAttribute("data-severity")] ?? 99) > rank
    );
    if (existing) {
      container.insertBefore(card, existing);
    } else {
      container.appendChild(card);
    }
  });
}

function applyUpdate(data) {
  const progressBar = document.getElementById("progress-bar");
  if (progressBar) progressBar.style.width = `${data.progress}%`;

  const statusEl = document.getElementById("assessment-status");
  if (statusEl) statusEl.textContent = data.status;

  renderModules(data);
  renderSeverityCounts(data);
  renderFindings(data);

  const reportLink = document.getElementById("report-link");
  if (reportLink) reportLink.style.display = data.report_available ? "inline-block" : "none";
}

function connectAssessmentStream(assessmentId) {
  const warningEl = document.getElementById("connection-warning");
  const source = new EventSource(`/api/assessment/${assessmentId}/stream`);

  source.onmessage = (evt) => {
    if (warningEl) warningEl.style.display = "none";
    try {
      const data = JSON.parse(evt.data);
      applyUpdate(data);
      if (data.status === "completed" || data.status === "failed") {
        source.close();
      }
    } catch (e) {
      console.error("Bad status payload", e);
    }
  };

  source.onerror = () => {
    // EventSource reconnects on its own; just let the user know things are
    // momentarily stale instead of the page silently going quiet.
    if (warningEl) warningEl.style.display = "block";
  };
}

document.addEventListener("DOMContentLoaded", () => {
  const root = document.getElementById("assessment-root");
  if (!root) return;

  const status = root.getAttribute("data-assessment-status");
  if (status === "completed" || status === "failed") return;

  connectAssessmentStream(root.getAttribute("data-assessment-id"));
});
