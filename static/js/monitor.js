// Live monitoring status: polls /api/monitor/status and updates the page in place.
(function () {
  "use strict";

  const root = document.querySelector("[data-monitor-status]");
  if (!root) return;

  const STATES = { running: "Monitoring", paused: "Paused", stopped: "Off" };
  const isMonitorPage = root.hasAttribute("data-monitor-page");
  const analysisId = root.dataset.analysisId ? Number(root.dataset.analysisId) : null;
  const analysisTotal = root.dataset.analysisTotal ? Number(root.dataset.analysisTotal) : null;
  let initialState = null;

  const field = name => document.querySelectorAll(`[data-field="${name}"]`);
  const setText = (name, value) => field(name).forEach(el => { el.textContent = value; });
  const number = n => Number(n).toLocaleString("en-US");
  const fileSize = n => n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : n >= 1024 ? Math.round(n / 1024) + " KB" : n + " B";

  function cell(row, text, className) {
    const td = document.createElement("td");
    if (className) td.className = className;
    if (text instanceof Node) td.append(text); else td.textContent = text;
    row.append(td);
    return td;
  }

  function renderFiles(files) {
    const body = document.querySelector("[data-files]");
    if (!body) return;
    body.innerHTML = "";
    if (!files.length) {
      const row = document.createElement("tr");
      cell(row, "No .log or .txt files in this folder yet. New files appear here automatically.", "muted").colSpan = 7;
      body.append(row);
      return;
    }
    for (const f of files) {
      const row = document.createElement("tr");
      const name = cell(row, "");
      if (f.analysis_id) {
        const a = document.createElement("a");
        a.className = "link"; a.href = "/?analysis_id=" + f.analysis_id; a.textContent = f.name;
        name.append(a);
      } else {
        name.append(f.name);
      }
      if (f.message) {
        const msg = document.createElement("span");
        msg.className = "muted small"; msg.textContent = f.message;
        name.append(document.createElement("br"), msg);
      }
      const badge = document.createElement("span");
      badge.className = "file-status fs-" + f.status; badge.textContent = f.status;
      cell(row, badge);
      cell(row, fileSize(f.size), "num");
      const read = cell(row, "");
      const bar = document.createElement("div"); bar.className = "progress";
      const fill = document.createElement("div"); fill.style.width = f.progress + "%";
      bar.append(fill);
      const pct = document.createElement("span"); pct.className = "muted small"; pct.textContent = f.progress + "%";
      read.append(bar, pct);
      cell(row, number(f.records), "num");
      cell(row, String(f.findings), "num");
      cell(row, f.last_data_at || "-", "mono nowrap");
      body.append(row);
    }
  }

  function update(status) {
    if (initialState === null) initialState = status.state;
    // Different controls are needed for another state: reload the page.
    if (status.state !== initialState) { window.location.reload(); return; }

    setText("files_count", status.files.length);
    setText("total_records", number(status.total_records));
    setText("last_scan_at", status.last_scan_at || "pending");
    setText("last_data_at", status.last_data_at || "none yet");
    field("last_error").forEach(el => { el.textContent = status.last_error || ""; el.hidden = !status.last_error; });
    field("state_badge").forEach(el => {
      const badge = el.querySelector(".state");
      if (badge) {
        badge.className = "state state-" + status.state;
        badge.lastChild.textContent = STATES[status.state];
      }
    });

    if (isMonitorPage) renderFiles(status.files);

    if (analysisId !== null) {
      const file = status.files.find(f => f.analysis_id === analysisId);
      const banner = document.querySelector("[data-new-data]");
      if (file && banner && file.records !== analysisTotal) banner.hidden = false;
    }
  }

  async function poll() {
    try {
      const response = await fetch("/api/monitor/status", { headers: { Accept: "application/json" } });
      if (response.ok) update(await response.json());
    } catch (error) {
      // Server restarting or offline: try again on the next tick.
    }
  }

  poll();
  setInterval(poll, 4000);
})();
