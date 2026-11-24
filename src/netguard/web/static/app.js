(() => {
  "use strict";

  const state = {
    defaults: null,
    samples: [],
    currentResult: null,
    lastRunMode: null, // { type: "sample", sampleId } | { type: "upload", file }
    severityFilter: "ALL",
    searchTerm: "",
    selectedAlertId: null,
  };

  const $ = (id) => document.getElementById(id);

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function showBanner(msg) {
    $("banner-msg").textContent = msg;
    $("alert-banner").classList.remove("hidden");
  }

  function hideBanner() {
    $("alert-banner").classList.add("hidden");
  }

  function setStatus(text, busy = false) {
    $("status-text").textContent = text;
    const pill = $("engine-status");
    if (busy) pill.classList.add("busy");
    else pill.classList.remove("busy");
  }

  function formatBytes(bytes) {
    if (!bytes) return "0 B";
    if (bytes < 1024) return `${bytes} B`;
    return `${(bytes / 1024).toFixed(1)} KB`;
  }

  // ---- Tab Switching ----
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((b) => {
        b.classList.remove("active");
        b.setAttribute("aria-selected", "false");
      });
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      btn.setAttribute("aria-selected", "true");
      $(`tab-${btn.dataset.tab}`).classList.add("active");
    });
  });

  $("banner-close").addEventListener("click", hideBanner);

  // ---- Config Form Binding ----
  function populateConfigForm(defaults) {
    const det = defaults.detector;
    const q = defaults.quarantine;
    $("cfg-scan-window").value = det.scan_window_seconds;
    $("cfg-syn-threshold").value = det.syn_scan_port_threshold;
    $("cfg-stealth-threshold").value = det.stealth_scan_port_threshold;
    $("cfg-cooldown").value = det.alert_cooldown_seconds;
    $("cfg-dns-entropy").value = det.dns_entropy_threshold;
    $("cfg-dns-maxlen").value = det.dns_max_subdomain_len;
    $("cfg-dns-txtlen").value = det.dns_txt_length_threshold;
    $("cfg-half-open").checked = Boolean(det.track_half_open_only);

    $("cfg-q-enabled").checked = true; // Enable dry-run quarantine preview by default in UI
    $("cfg-q-timeout").value = q.timeout_seconds;
    $("cfg-q-minsev").value = q.min_severity;
    $("cfg-q-allowlist").value = (q.allowlist_cidrs || []).join(", ");
  }

  function readConfigsFromForm() {
    const allowlist = $("cfg-q-allowlist").value
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    return {
      detector_config: {
        scan_window_seconds: Number($("cfg-scan-window").value),
        syn_scan_port_threshold: Number($("cfg-syn-threshold").value),
        stealth_scan_port_threshold: Number($("cfg-stealth-threshold").value),
        alert_cooldown_seconds: Number($("cfg-cooldown").value),
        dns_entropy_threshold: Number($("cfg-dns-entropy").value),
        dns_max_subdomain_len: Number($("cfg-dns-maxlen").value),
        dns_txt_length_threshold: Number($("cfg-dns-txtlen").value),
        track_half_open_only: $("cfg-half-open").checked,
      },
      quarantine_config: {
        enabled: $("cfg-q-enabled").checked,
        dry_run: true,
        timeout_seconds: Number($("cfg-q-timeout").value),
        min_severity: $("cfg-q-minsev").value,
        allowlist_cidrs: allowlist,
      },
    };
  }

  $("toggle-config-btn").addEventListener("click", () => {
    $("config-drawer").classList.toggle("hidden");
  });

  $("reset-config-btn").addEventListener("click", () => {
    if (state.defaults) {
      populateConfigForm(state.defaults);
    }
  });

  $("rerun-btn").addEventListener("click", () => {
    if (!state.lastRunMode) return;
    if (state.lastRunMode.type === "sample") {
      analyzeSample(state.lastRunMode.sampleId);
    } else if (state.lastRunMode.type === "upload") {
      analyzeUpload(state.lastRunMode.file);
    }
  });

  // ---- Sample Catalog ----
  function renderSamples() {
    const grid = $("samples-grid");
    if (!state.samples.length) {
      grid.innerHTML = '<div class="muted">No sample PCAPs found. Run <code>netguard generate-samples</code>.</div>';
      return;
    }

    grid.innerHTML = state.samples
      .map((s) => {
        const selected =
          state.lastRunMode &&
          state.lastRunMode.type === "sample" &&
          state.lastRunMode.sampleId === s.sample_id;
        return `
          <div class="sample-card ${selected ? "selected" : ""}" data-sample-id="${escapeHtml(s.sample_id)}">
            <div>
              <div class="sample-cat">${escapeHtml(s.category)}</div>
              <div class="sample-title">${escapeHtml(s.title)}</div>
              <p class="sample-desc">${escapeHtml(s.description)}</p>
            </div>
            <div class="sample-footer">
              <span class="sample-size">${s.exists ? formatBytes(s.size_bytes) : "Missing"}</span>
              <button class="btn btn-primary btn-sm analyze-sample-btn" data-id="${escapeHtml(s.sample_id)}" ${s.exists ? "" : "disabled"}>
                Analyze
              </button>
            </div>
          </div>
        `;
      })
      .join("");

    grid.querySelectorAll(".analyze-sample-btn").forEach((btn) => {
      btn.addEventListener("click", () => analyzeSample(btn.dataset.id));
    });
  }

  // ---- API Calls ----
  async function analyzeSample(sampleId) {
    hideBanner();
    setStatus(`Analyzing ${sampleId}...`, true);
    state.lastRunMode = { type: "sample", sampleId };
    renderSamples();

    try {
      const cfgs = readConfigsFromForm();
      const resp = await fetch("/api/analyze/sample", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sample_id: sampleId, ...cfgs }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "Analysis failed");
      applyAnalysisResult(data);
      setStatus(`Analyzed ${data.source}`);
    } catch (err) {
      showBanner(err.message);
      setStatus("Error");
    }
  }

  async function analyzeUpload(file) {
    hideBanner();
    setStatus(`Uploading ${file.name}...`, true);
    state.lastRunMode = { type: "upload", file };
    $("selected-file-label").textContent = `Loaded: ${file.name} (${formatBytes(file.size)})`;
    renderSamples();

    try {
      const cfgs = readConfigsFromForm();
      const fd = new FormData();
      fd.append("file", file);
      fd.append("detector_config", JSON.stringify(cfgs.detector_config));
      fd.append("quarantine_config", JSON.stringify(cfgs.quarantine_config));

      const resp = await fetch("/api/analyze/upload", { method: "POST", body: fd });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "Upload failed");
      applyAnalysisResult(data);
      setStatus(`Analyzed ${data.source}`);
    } catch (err) {
      showBanner(err.message);
      setStatus("Error");
    }
  }

  // Drag-and-drop Upload
  const dropZone = $("drop-zone");
  const fileInput = $("pcap-file-input");

  fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files[0]) {
      analyzeUpload(e.target.files[0]);
    }
  });
  ["dragenter", "dragover"].forEach((ev) => {
    dropZone.addEventListener(ev, (e) => {
      e.preventDefault();
      dropZone.classList.add("dragover");
    });
  });
  ["dragleave", "drop"].forEach((ev) => {
    dropZone.addEventListener(ev, (e) => {
      e.preventDefault();
      dropZone.classList.remove("dragover");
    });
  });
  dropZone.addEventListener("drop", (e) => {
    const file = e.dataTransfer?.files?.[0];
    if (file) analyzeUpload(file);
  });

  // ---- Result Rendering ----
  function applyAnalysisResult(result) {
    state.currentResult = result;
    state.selectedAlertId = result.alerts.length ? result.alerts[0].alert_id : null;
    $("rerun-btn").disabled = false;
    $("export-json-btn").disabled = false;
    $("export-jsonl-btn").disabled = false;

    const sev = result.severity_counts || {};
    $("kpi-source").textContent = result.source;
    $("kpi-duration").textContent = `Analyzed in ${result.duration_ms} ms`;
    $("kpi-packets").textContent = result.total_packets;

    const activeProtos = Object.entries(result.protocol_counts || {})
      .filter(([, v]) => v > 0)
      .map(([k, v]) => `${k}:${v}`)
      .join(" · ");
    $("kpi-proto-summary").textContent = activeProtos || "No packets";

    $("kpi-alerts").textContent = result.alert_count;
    $("kpi-sev-summary").textContent = `CRITICAL: ${sev.CRITICAL || 0} · HIGH: ${sev.HIGH || 0} · MEDIUM: ${sev.MEDIUM || 0}`;

    const qRecs = result.quarantine_records || [];
    $("kpi-quarantine").textContent = qRecs.length;
    const skipped = qRecs.filter((r) => r.status === "skipped_allowlisted").length;
    const dryRuns = qRecs.filter((r) => r.status === "dry_run").length;
    $("kpi-quarantine-sub").textContent = `${dryRuns} dry-run · ${skipped} allowlist skipped`;

    const tip = result.sample_meta?.demo_tip ? ` — Tip: ${result.sample_meta.demo_tip}` : "";
    $("alerts-subtitle").textContent = `${result.alert_count} alert(s) across ${result.total_packets} packets${tip}`;

    renderAlertsTable();
    renderInspector();
    renderTelemetry(result);
    renderQuarantineLog(result);
  }

  function getFilteredAlerts() {
    if (!state.currentResult) return [];
    const term = state.searchTerm.trim().toLowerCase();
    return state.currentResult.alerts.filter((a) => {
      if (state.severityFilter !== "ALL" && a.severity !== state.severityFilter) return false;
      if (!term) return true;
      const hay = [
        a.alert_id,
        a.alert_type,
        a.severity,
        a.src_ip,
        a.dst_ip,
        a.src_mac,
        a.summary,
        a.mitre_attack?.technique_id,
        a.mitre_attack?.technique_name,
      ]
        .join(" ")
        .toLowerCase();
      return hay.includes(term);
    });
  }

  function renderAlertsTable() {
    const tbody = $("alerts-tbody");
    const alerts = getFilteredAlerts();
    if (!state.currentResult) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-cell">No analysis executed yet.</td></tr>';
      return;
    }
    if (!alerts.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-cell">No alerts match the current filter criteria (0 threats detected).</td></tr>';
      return;
    }

    tbody.innerHTML = alerts
      .map((a) => {
        const selected = a.alert_id === state.selectedAlertId ? "selected-row" : "";
        const src = a.src_ip || a.src_mac || "-";
        const dst = a.dst_ip || a.dst_mac || "-";
        return `
          <tr class="${selected}" data-alert-id="${escapeHtml(a.alert_id)}">
            <td><code>${escapeHtml(a.alert_id)}</code></td>
            <td><span class="badge badge-${escapeHtml(a.severity)}">${escapeHtml(a.severity)}</span></td>
            <td><strong>${escapeHtml(a.alert_type)}</strong></td>
            <td><code>${escapeHtml(a.mitre_attack?.technique_id || "-")}</code></td>
            <td><code>${escapeHtml(src)}</code> &rarr; <code>${escapeHtml(dst)}</code></td>
            <td><span class="badge badge-info">${escapeHtml(a.quarantine_action)}</span></td>
            <td>${escapeHtml(a.summary)}</td>
          </tr>
        `;
      })
      .join("");

    tbody.querySelectorAll("tr[data-alert-id]").forEach((row) => {
      row.addEventListener("click", () => {
        state.selectedAlertId = row.dataset.alertId;
        renderAlertsTable();
        renderInspector();
      });
    });
  }

  function renderInspector() {
    const pane = $("alert-inspector");
    if (!state.currentResult || !state.selectedAlertId) {
      pane.innerHTML = `
        <h3>Forensic Evidence Inspector</h3>
        <p class="muted">No alert selected. Click any row in the Alerts table to view evidence.</p>
      `;
      return;
    }
    const alert = state.currentResult.alerts.find((a) => a.alert_id === state.selectedAlertId);
    if (!alert) return;

    const evRows = Object.entries(alert.evidence || {})
      .map(
        ([k, v]) => `
        <tr>
          <td>${escapeHtml(k)}</td>
          <td><code>${escapeHtml(typeof v === "object" ? JSON.stringify(v) : String(v))}</code></td>
        </tr>
      `
      )
      .join("");

    pane.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;gap:0.5rem;">
        <h3>${escapeHtml(alert.alert_id)} &middot; ${escapeHtml(alert.alert_type)}</h3>
        <span class="badge badge-${escapeHtml(alert.severity)}">${escapeHtml(alert.severity)}</span>
      </div>
      <p style="font-size:0.84rem;margin:0.4rem 0;">${escapeHtml(alert.summary)}</p>
      <table class="kv-table">
        <tr><td>MITRE Tactic</td><td>${escapeHtml(alert.mitre_attack?.tactic)} (${escapeHtml(alert.mitre_attack?.technique_id)})</td></tr>
        <tr><td>Technique</td><td>${escapeHtml(alert.mitre_attack?.technique_name)}</td></tr>
        <tr><td>Timestamp (UTC)</td><td><code>${escapeHtml(alert.timestamp)}</code></td></tr>
        <tr><td>Source</td><td><code>${escapeHtml(alert.src_ip || "-")}</code> (${escapeHtml(alert.src_mac || "n/a")})</td></tr>
        <tr><td>Destination</td><td><code>${escapeHtml(alert.dst_ip || "-")}</code> (${escapeHtml(alert.dst_mac || "n/a")})</td></tr>
        <tr><td>Quarantine</td><td><code>${escapeHtml(alert.quarantine_action)}</code> ${alert.quarantine_detail ? "— " + escapeHtml(alert.quarantine_detail) : ""}</td></tr>
        ${evRows}
      </table>
      <details>
        <summary style="cursor:pointer;font-size:0.8rem;color:var(--accent);margin-top:0.5rem;">Raw Alert JSON</summary>
        <pre class="code-block">${escapeHtml(JSON.stringify(alert, null, 2))}</pre>
      </details>
    `;
  }

  $("sev-filters").querySelectorAll(".filter-pill").forEach((pill) => {
    pill.addEventListener("click", () => {
      $("sev-filters").querySelectorAll(".filter-pill").forEach((p) => p.classList.remove("active"));
      pill.classList.add("active");
      state.severityFilter = pill.dataset.sev;
      renderAlertsTable();
    });
  });

  $("alert-search").addEventListener("input", (e) => {
    state.searchTerm = e.target.value;
    renderAlertsTable();
  });

  // Exports
  function triggerDownload(filename, content, mime) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  $("export-json-btn").addEventListener("click", () => {
    if (!state.currentResult) return;
    triggerDownload(
      `netguard_report_${Date.now()}.json`,
      JSON.stringify(state.currentResult, null, 2),
      "application/json"
    );
  });

  $("export-jsonl-btn").addEventListener("click", () => {
    if (!state.currentResult) return;
    const lines = state.currentResult.alerts.map((a) => JSON.stringify(a)).join("\n") + "\n";
    triggerDownload(`netguard_alerts_${Date.now()}.jsonl`, lines, "application/x-ndjson");
  });

  // ---- Telemetry Charts (Pure Inline SVG) ----
  function renderTelemetry(result) {
    renderProtocolsChart(result.protocol_counts || {});
    renderTimelineChart(result.timeline_buckets || []);
    renderDnsScatter(result.dns_observations || [], result.config?.detector || {});
    renderPortsChart(result.top_targeted_ports || []);
    renderArpTable(result.arp_table || []);
  }

  function renderProtocolsChart(counts) {
    const container = $("chart-protocols");
    const entries = Object.entries(counts).filter(([, v]) => v > 0);
    if (!entries.length) {
      container.innerHTML = '<div class="muted">No packet protocol data yet.</div>';
      return;
    }
    const maxVal = Math.max(...entries.map(([, v]) => v), 1);
    const rowH = 30;
    const h = entries.length * rowH + 20;
    const colors = { TCP: "#38bdf8", DNS: "#a78bfa", ARP: "#f59e0b", UDP: "#2dd4bf", ICMP: "#10b981", IPv6: "#818cf8", Other: "#64748b" };

    const bars = entries
      .map(([name, val], i) => {
        const y = 12 + i * rowH;
        const barW = Math.max(4, (val / maxVal) * 320);
        const col = colors[name] || "#38bdf8";
        return `
          <text x="8" y="${y + 16}" fill="#cbd5e1" font-size="12" font-family="monospace">${escapeHtml(name)}</text>
          <rect x="75" y="${y + 4}" width="${barW}" height="16" rx="4" fill="${col}" />
          <text x="${82 + barW}" y="${y + 16}" fill="#f8fafc" font-size="11" font-family="monospace">${val}</text>
        `;
      })
      .join("");

    container.innerHTML = `<svg viewBox="0 0 460 ${h}">${bars}</svg>`;
  }

  function renderTimelineChart(buckets) {
    const container = $("chart-timeline");
    if (!buckets.length) {
      container.innerHTML = '<div class="muted">No timeline buckets available.</div>';
      return;
    }
    const w = 480;
    const h = 210;
    const padL = 36;
    const padB = 28;
    const plotW = w - padL - 16;
    const plotH = h - padB - 18;
    const maxPkt = Math.max(...buckets.map((b) => b.packets), 1);
    const barW = Math.max(4, plotW / buckets.length - 3);

    const bars = buckets
      .map((b, i) => {
        const x = padL + i * (plotW / buckets.length) + 1;
        const pktH = (b.packets / maxPkt) * plotH;
        const y = 12 + (plotH - pktH);
        const hasAlert = b.alerts > 0;
        const alertMarker = hasAlert
          ? `<circle cx="${x + barW / 2}" cy="${Math.max(10, y - 5)}" r="4" fill="#ef4444"><title>${escapeHtml(b.label)}: ${b.alerts} alert(s)</title></circle>`
          : "";
        const label =
          i === 0 || i === buckets.length - 1 || i % Math.max(1, Math.floor(buckets.length / 5)) === 0
            ? `<text x="${x + barW / 2}" y="${h - 8}" text-anchor="middle" fill="#94a3b8" font-size="10">${escapeHtml(b.label)}</text>`
            : "";
        return `
          <rect x="${x}" y="${y}" width="${barW}" height="${pktH}" rx="2" fill="${hasAlert ? "#f59e0b" : "#06b6d4"}">
            <title>${escapeHtml(b.label)}: ${b.packets} packets, ${b.alerts} alerts</title>
          </rect>
          ${alertMarker}
          ${label}
        `;
      })
      .join("");

    container.innerHTML = `
      <svg viewBox="0 0 ${w} ${h}">
        <line x1="${padL}" y1="${12 + plotH}" x2="${w - 12}" y2="${12 + plotH}" stroke="#334155" />
        <text x="6" y="20" fill="#94a3b8" font-size="10">${maxPkt}</text>
        <text x="6" y="${12 + plotH}" fill="#94a3b8" font-size="10">0</text>
        ${bars}
      </svg>
    `;
  }

  function renderDnsScatter(obs, detCfg) {
    const container = $("chart-dns-scatter");
    if (!obs.length) {
      container.innerHTML = '<div class="muted">No DNS queries observed in this capture.</div>';
      return;
    }
    const w = 480;
    const h = 220;
    const padL = 40;
    const padB = 30;
    const plotW = w - padL - 20;
    const plotH = h - padB - 20;

    const entThresh = Number(detCfg.dns_entropy_threshold || 3.8);
    const lenThresh = Number(detCfg.dns_max_subdomain_len || 50);
    const maxLen = Math.max(lenThresh + 15, ...obs.map((o) => o.subdomain_len));
    const maxEnt = 6.0;

    const xFor = (len) => padL + (Math.min(len, maxLen) / maxLen) * plotW;
    const yFor = (ent) => 12 + plotH - (Math.min(ent, maxEnt) / maxEnt) * plotH;

    const dots = obs
      .map((o) => {
        const cx = xFor(o.subdomain_len);
        const cy = yFor(o.entropy);
        const fill = o.flagged ? "#ef4444" : "#10b981";
        return `
          <circle cx="${cx}" cy="${cy}" r="${o.flagged ? 5.5 : 4}" fill="${fill}" fill-opacity="0.88" stroke="#0f172a" stroke-width="1">
            <title>${escapeHtml(o.qname)} (${escapeHtml(o.qtype)}) | len=${o.subdomain_len}, entropy=${o.entropy}</title>
          </circle>
        `;
      })
      .join("");

    container.innerHTML = `
      <svg viewBox="0 0 ${w} ${h}">
        <line x1="${padL}" y1="${12 + plotH}" x2="${w - 16}" y2="${12 + plotH}" stroke="#334155" />
        <line x1="${padL}" y1="12" x2="${padL}" y2="${12 + plotH}" stroke="#334155" />
        <line x1="${padL}" y1="${yFor(entThresh)}" x2="${w - 16}" y2="${yFor(entThresh)}" stroke="#f59e0b" stroke-dasharray="4 4" />
        <line x1="${xFor(lenThresh)}" y1="12" x2="${xFor(lenThresh)}" y2="${12 + plotH}" stroke="#38bdf8" stroke-dasharray="4 4" />
        <text x="${w - 18}" y="${yFor(entThresh) - 4}" text-anchor="end" fill="#f59e0b" font-size="10">entropy ${entThresh}</text>
        <text x="${xFor(lenThresh) + 4}" y="22" fill="#38bdf8" font-size="10">len ${lenThresh}</text>
        <text x="${padL + plotW / 2}" y="${h - 6}" text-anchor="middle" fill="#94a3b8" font-size="10">Subdomain Length (chars)</text>
        <text x="10" y="20" fill="#94a3b8" font-size="10">6.0</text>
        <text x="10" y="${12 + plotH}" fill="#94a3b8" font-size="10">0.0</text>
        ${dots}
      </svg>
    `;
  }

  function renderPortsChart(ports) {
    const container = $("chart-ports");
    if (!ports.length) {
      container.innerHTML = '<div class="muted">No port scan probes observed in this capture.</div>';
      return;
    }
    const maxHits = Math.max(...ports.map((p) => p.hits), 1);
    const rowH = 26;
    const h = ports.length * rowH + 16;
    const bars = ports
      .map((p, i) => {
        const y = 8 + i * rowH;
        const barW = Math.max(6, (p.hits / maxHits) * 300);
        return `
          <text x="8" y="${y + 15}" fill="#cbd5e1" font-size="11" font-family="monospace">:${p.port}</text>
          <rect x="75" y="${y + 3}" width="${barW}" height="15" rx="3" fill="#f59e0b" />
          <text x="${82 + barW}" y="${y + 15}" fill="#f8fafc" font-size="11" font-family="monospace">${p.hits}</text>
        `;
      })
      .join("");
    container.innerHTML = `<svg viewBox="0 0 460 ${h}">${bars}</svg>`;
  }

  function renderArpTable(bindings) {
    const tbody = $("arp-tbody");
    if (!bindings.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-cell">No ARP bindings observed in active capture.</td></tr>';
      return;
    }
    tbody.innerHTML = bindings
      .map((b) => {
        const hasConflict = b.conflicts > 0;
        return `
          <tr>
            <td><code>${escapeHtml(b.ip)}</code></td>
            <td><code>${escapeHtml(b.mac)}</code></td>
            <td><span class="badge ${b.is_static ? "badge-info" : "badge-LOW"}">${b.is_static ? "Static" : "Learned"}</span></td>
            <td>${b.packet_count}</td>
            <td>${hasConflict ? `<span class="badge badge-CRITICAL">${b.conflicts}</span>` : "0"}</td>
            <td><code>${escapeHtml((b.conflicting_macs || []).join(", ") || "—")}</code></td>
            <td><code>${escapeHtml(b.last_seen)}</code></td>
          </tr>
        `;
      })
      .join("");
  }

  // ---- Quarantine Tab ----
  function renderQuarantineLog(result) {
    const tbody = $("quarantine-tbody");
    const recs = result.quarantine_records || [];
    if (!recs.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-cell">No quarantine actions triggered for this capture.</td></tr>';
      return;
    }
    tbody.innerHTML = recs
      .map((r) => {
        const badgeCls =
          r.status === "skipped_allowlisted" ? "badge-MEDIUM" : r.status === "applied" ? "badge-CRITICAL" : "badge-HIGH";
        const cmdText = r.commands && r.commands.length ? r.commands[r.commands.length - 1] : r.detail;
        return `
          <tr>
            <td><code>${escapeHtml(r.alert_id)}</code></td>
            <td><code>${escapeHtml(r.ip || "-")}</code></td>
            <td>${escapeHtml(r.family)}</td>
            <td><span class="badge ${badgeCls}">${escapeHtml(r.status)}</span></td>
            <td>${escapeHtml(r.reason)}</td>
            <td><code>${escapeHtml(cmdText)}</code></td>
          </tr>
        `;
      })
      .join("");
  }

  async function runQuarantinePreview() {
    const ips = $("sim-ips").value
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const allowlist = $("sim-allowlist").value
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    const payload = {
      ips,
      allowlist_cidrs: allowlist,
      table_name: $("sim-table").value.trim() || "netguard",
      timeout_seconds: Number($("sim-timeout").value || 900),
    };

    try {
      const resp = await fetch("/api/quarantine/preview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "Preview failed");

      $("ruleset-pre").textContent = data.bootstrap_ruleset;
      $("sim-results").innerHTML = (data.evaluations || [])
        .map((e) => {
          const cmd = e.commands && e.commands.length ? e.commands[e.commands.length - 1] : e.detail;
          return `
            <div class="sim-item">
              <div style="display:flex;justify-content:space-between;align-items:center;">
                <strong><code>${escapeHtml(e.ip || "(invalid)")}</code></strong>
                <span class="badge ${e.status === "dry_run" ? "badge-HIGH" : "badge-MEDIUM"}">${escapeHtml(e.status)}</span>
              </div>
              <div class="muted" style="margin-top:0.2rem;">${escapeHtml(e.reason)}</div>
              <pre class="code-block" style="margin-top:0.35rem;">${escapeHtml(cmd)}</pre>
            </div>
          `;
        })
        .join("");
    } catch (err) {
      showBanner(err.message);
    }
  }

  $("sim-run-btn").addEventListener("click", runQuarantinePreview);
  $("copy-ruleset-btn").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("ruleset-pre").textContent);
      $("copy-ruleset-btn").textContent = "Copied!";
      setTimeout(() => ($("copy-ruleset-btn").textContent = "Copy Ruleset"), 1500);
    } catch {
      // Clipboard API unavailable in restricted contexts
    }
  });

  // ---- Architecture Tab ----
  async function loadArchitectureDocs() {
    const resp = await fetch("/api/docs/architecture");
    const data = await resp.json();
    $("arch-pipeline-list").innerHTML = (data.pipeline || [])
      .map(
        (p) => `
        <div class="arch-item">
          <strong>${escapeHtml(p.stage)} — ${escapeHtml(p.component)}</strong>
          <p class="muted">${escapeHtml(p.details)}</p>
        </div>
      `
      )
      .join("");

    $("arch-mitre-tbody").innerHTML = (data.mitre_coverage || [])
      .map(
        (m) => `
        <tr>
          <td><code>${escapeHtml(m.alert_type)}</code></td>
          <td>${escapeHtml(m.tactic)}</td>
          <td>${escapeHtml(m.technique)}</td>
          <td><span class="badge badge-HIGH">${escapeHtml(m.severity)}</span></td>
        </tr>
      `
      )
      .join("");
  }

  // ---- Bootstrap ----
  async function init() {
    try {
      const [cfgRes, smpRes] = await Promise.all([
        fetch("/api/config/defaults"),
        fetch("/api/samples"),
      ]);
      state.defaults = await cfgRes.json();
      const smpJson = await smpRes.json();
      state.samples = smpJson.samples || [];

      populateConfigForm(state.defaults);
      renderSamples();
      await Promise.all([runQuarantinePreview(), loadArchitectureDocs()]);
      setStatus("Ready");
    } catch (err) {
      showBanner(`Initialization failed: ${err.message}`);
      setStatus("Error");
    }
  }

  init();
})();
