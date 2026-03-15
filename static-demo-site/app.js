(function () {
  const data = window.PacketQLDemoData;
  const state = {
    page: "upload",
    sourceId: data.sources[0].id,
    searchTerm: "",
    searchSource: "all",
    sqlSample: Object.keys(data.sources[0].sqlSamples)[0]
  };

  const sourceSelect = document.getElementById("sourceSelect");
  const sourceName = document.getElementById("sourceName");
  const sourceUploaded = document.getElementById("sourceUploaded");
  const sourceProcessed = document.getElementById("sourceProcessed");
  const modalRoot = document.getElementById("modalRoot");

  const pages = {
    upload: document.getElementById("page-upload"),
    dashboard: document.getElementById("page-dashboard"),
    search: document.getElementById("page-search"),
    sql: document.getElementById("page-sql"),
    health: document.getElementById("page-health")
  };

  function currentSource() {
    return data.sources.find((source) => source.id === state.sourceId) || data.sources[0];
  }

  function setPage(nextPage) {
    state.page = nextPage;
    document.querySelectorAll(".nav-item").forEach((button) => {
      button.classList.toggle("active", button.dataset.page === nextPage);
    });
    Object.keys(pages).forEach((key) => {
      pages[key].classList.toggle("active", key === nextPage);
    });
  }

  function renderSourcePicker() {
    sourceSelect.innerHTML = data.sources
      .map((source) => `<option value="${source.id}">${source.name}</option>`)
      .join("");
    sourceSelect.value = state.sourceId;
  }

  function renderSourceBar() {
    const source = currentSource();
    sourceName.textContent = source.name;
    sourceUploaded.textContent = `Uploaded: ${source.uploadedAt}`;
    sourceProcessed.textContent = `Last Processed: ${source.processedAt}`;
  }

  function renderUploadPage() {
    const source = currentSource();
    pages.upload.innerHTML = `
      <div class="grid two">
        <section class="card">
          <div class="kicker">Public Demo</div>
          <h2>PCAP Upload</h2>
          <p class="helper">The live product accepts <code>.pcap</code> and <code>.pcapng</code> files. In this public demo, upload is intentionally disabled and the interface uses preloaded example datasets.</p>
          <div class="dropzone">
            <div class="dropzone-title">Upload disabled for public demo</div>
            <p class="helper">Use the source selector above to switch between curated packet captures and explore the rest of the workflow.</p>
            <div class="cta-row">
              <button class="disabled-button">Upload PCAP</button>
              <button class="secondary-button" data-open-page="dashboard">Open Log Dashboard</button>
              <button class="secondary-button" data-open-page="search">Open Log Search</button>
            </div>
          </div>
        </section>

        <section class="card">
          <div class="demo-badge">Current Demo Dataset</div>
          <h2>${source.name}</h2>
          <div class="summary-list">
            <div class="helper">Size: <strong>${source.size}</strong></div>
            <div class="helper">Total structured rows: <strong>${source.totalEvents.toLocaleString()}</strong></div>
            <div class="helper">Top source IP: <strong>${source.topSourceIp}</strong></div>
            <div class="helper">Top queried domain: <strong>${source.topDomain}</strong></div>
          </div>
          <div class="alert" style="margin-top: 18px;">
            Recommended live workflow: upload PCAP files below <strong>50 MB</strong> for the smoothest analyst experience.
          </div>
        </section>
      </div>
    `;
  }

  function renderDashboardPage() {
    const source = currentSource();
    const maxTable = Math.max.apply(null, source.tables.map((row) => row[1]));
    pages.dashboard.innerHTML = `
      <div class="stats-grid">
        <section class="card"><div class="kicker">Total Events</div><div class="big-number">${source.totalEvents.toLocaleString()}</div></section>
        <section class="card"><div class="kicker">Top Source IP</div><div class="big-number">${source.topSourceIp}</div></section>
        <section class="card"><div class="kicker">Top Queried Domain</div><div class="big-number">${source.topDomain}</div></section>
        <section class="card"><div class="kicker">Ingestion Rate</div><div class="big-number">${source.ingestRate}</div></section>
      </div>

      <div class="grid two" style="margin-top: 18px;">
        <section class="card">
          <h2>Available Log Sources</h2>
          <p class="helper">Protocol tables generated after Zeek parsing and normalization.</p>
          <div class="metric-list">
            ${source.tables.map(([name, value]) => {
              const width = maxTable ? Math.max(3, Math.round((value / maxTable) * 100)) : 0;
              return `
                <div class="metric-row">
                  <div class="metric-label">${name}</div>
                  <div class="metric-bar"><span style="width:${width}%"></span></div>
                  <div>${value}</div>
                </div>
              `;
            }).join("")}
          </div>
        </section>

        <section class="card">
          <h2>Top Queried Domains</h2>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Domain</th><th>Hits</th></tr></thead>
              <tbody>
                ${source.dashboard.queriedDomains.map((row) => `<tr><td>${row[0]}</td><td>${row[1]}</td></tr>`).join("")}
              </tbody>
            </table>
          </div>
        </section>
      </div>

      <div class="grid two" style="margin-top: 18px;">
        <section class="card">
          <h2>Top Source IPs</h2>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Source IP</th><th>Hits</th></tr></thead>
              <tbody>
                ${source.dashboard.topSourceIps.map((row) => `<tr><td>${row[0]}</td><td>${row[1]}</td></tr>`).join("")}
              </tbody>
            </table>
          </div>
        </section>

        <section class="card">
          <h2>Top Destination IPs</h2>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Destination IP</th><th>Hits</th></tr></thead>
              <tbody>
                ${source.dashboard.topDestinationIps.map((row) => `<tr><td>${row[0]}</td><td>${row[1]}</td></tr>`).join("")}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    `;
  }

  function filteredLogs() {
    const source = currentSource();
    return source.logs.filter((entry) => {
      const matchesSource = state.searchSource === "all" || entry.source === state.searchSource;
      const needle = state.searchTerm.trim().toLowerCase();
      const blob = Object.values(entry).join(" ").toLowerCase();
      const matchesSearch = !needle || blob.indexOf(needle) !== -1;
      return matchesSource && matchesSearch;
    });
  }

  function renderSearchPage() {
    const source = currentSource();
    const rows = filteredLogs();
    const distinctSources = Array.from(new Set(source.logs.map((entry) => entry.source)));

    pages.search.innerHTML = `
      <section class="card">
        <div class="toolbar">
          <div>
            <div class="kicker">Log Search</div>
            <h2>Search normalized investigation data</h2>
          </div>
          <div class="status-pill">Results: ${rows.length}</div>
        </div>

        <div class="search-bar" style="margin-top: 16px;">
          <select id="searchSourceSelect">
            <option value="all">All Sources</option>
            ${distinctSources.map((name) => `<option value="${name}" ${state.searchSource === name ? "selected" : ""}>${name}</option>`).join("")}
          </select>
          <input id="searchTermInput" type="text" placeholder="Search IP, domain, host, message..." value="${escapeHtml(state.searchTerm)}">
          <button id="searchAction" class="primary-button">Search</button>
        </div>

        <div class="table-wrap" style="margin-top: 18px;">
          <table class="search-results">
            <thead>
              <tr>
                <th>Time</th>
                <th>Source</th>
                <th>Src IP</th>
                <th>Dst IP</th>
                <th>Protocol</th>
                <th>Summary</th>
              </tr>
            </thead>
            <tbody>
              ${rows.map((entry, index) => `
                <tr class="clickable-row" data-log-index="${index}">
                  <td>${entry.time}</td>
                  <td>${entry.source}</td>
                  <td>${entry.src_ip || "—"}</td>
                  <td>${entry.dst_ip || "—"}</td>
                  <td>${entry.protocol || "—"}</td>
                  <td>${entry.summary || "—"}</td>
                </tr>
              `).join("") || `<tr><td colspan="6">No matching logs found in this demo dataset.</td></tr>`}
            </tbody>
          </table>
        </div>
      </section>
    `;

    document.getElementById("searchSourceSelect").addEventListener("change", (event) => {
      state.searchSource = event.target.value;
      renderSearchPage();
    });

    document.getElementById("searchTermInput").addEventListener("input", (event) => {
      state.searchTerm = event.target.value;
    });

    document.getElementById("searchAction").addEventListener("click", () => {
      renderSearchPage();
    });

    pages.search.querySelectorAll("[data-log-index]").forEach((row) => {
      row.addEventListener("click", () => {
        const entry = rows[Number(row.dataset.logIndex)];
        openLogModal(entry);
      });
    });
  }

  function renderSqlPage() {
    const source = currentSource();
    const sampleNames = Object.keys(source.sqlSamples);
    if (!source.sqlSamples[state.sqlSample]) {
      state.sqlSample = sampleNames[0];
    }
    const sample = source.sqlSamples[state.sqlSample];

    pages.sql.innerHTML = `
      <div class="sql-layout">
        <section class="card sql-editor">
          <div class="sql-toolbar">
            <div>
              <div class="kicker">SQL Query</div>
              <h2>Run read-only investigation queries</h2>
            </div>
            <div class="demo-badge">Demo results are hard-coded</div>
          </div>
          <p class="helper">This static demo simulates SQL execution using prepared result sets. It is intended to show the product workflow, not a live database runtime.</p>
          <textarea id="sqlTextarea">${sample.sql}</textarea>
          <div class="cta-row" style="margin-top: 14px;">
            <button id="runSqlButton" class="primary-button">Run Query</button>
            <button class="disabled-button">Save Query Disabled</button>
          </div>
        </section>

        <section class="card">
          <div class="kicker">Example Queries</div>
          <h2>Analyst Shortcuts</h2>
          <div class="sql-samples">
            ${sampleNames.map((name) => `
              <button class="sample-button" data-sql-sample="${name}">${name}</button>
            `).join("")}
          </div>
        </section>
      </div>

      <section class="card" style="margin-top: 18px;">
        <div class="toolbar">
          <div>
            <div class="kicker">Results</div>
            <h2>${state.sqlSample}</h2>
          </div>
          <div class="status-pill">${sample.rows.length} rows</div>
        </div>
        <div class="table-wrap" style="margin-top: 18px;">
          <table>
            <thead>
              <tr>${sample.columns.map((column) => `<th>${column}</th>`).join("")}</tr>
            </thead>
            <tbody>
              ${sample.rows.map((row) => `<tr>${row.map((cell) => `<td>${cell}</td>`).join("")}</tr>`).join("")}
            </tbody>
          </table>
        </div>
      </section>
    `;

    pages.sql.querySelectorAll("[data-sql-sample]").forEach((button) => {
      button.addEventListener("click", () => {
        state.sqlSample = button.dataset.sqlSample;
        renderSqlPage();
      });
    });

    document.getElementById("runSqlButton").addEventListener("click", () => {
      const textarea = document.getElementById("sqlTextarea");
      textarea.value = source.sqlSamples[state.sqlSample].sql;
      renderSqlPage();
    });
  }

  function renderHealthPage() {
    const source = currentSource();
    const pipeline = source.pipeline;
    pages.health.innerHTML = `
      <div class="stats-grid">
        <section class="card"><div class="kicker">Tracked Sources</div><div class="big-number">${pipeline.trackedSources}</div></section>
        <section class="card"><div class="kicker">Total Parsed Rows</div><div class="big-number">${pipeline.parsedRows.toLocaleString()}</div></section>
        <section class="card"><div class="kicker">Dropped Packets</div><div class="big-number">${pipeline.droppedPackets}</div></section>
        <section class="card"><div class="kicker">Error Sources</div><div class="big-number">${pipeline.errorSources}</div></section>
      </div>

      <div class="grid two" style="margin-top: 18px;">
        <section class="card">
          <div class="kicker">Processing Status</div>
          <h2>Ingestion health snapshot</h2>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Source</th><th>Status</th><th>Rows</th><th>Updated</th><th>Message</th></tr></thead>
              <tbody>
                ${pipeline.processingStatus.map((row) => `
                  <tr>
                    <td>${row[0]}</td>
                    <td>${row[1]}</td>
                    <td>${row[2]}</td>
                    <td>${row[3]}</td>
                    <td>${row[4]}</td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>
        </section>

        <section class="card">
          <div class="kicker">Pipeline Events</div>
          <h2>Dropped events and errors</h2>
          <p class="helper">This demo dataset is healthy. No dropped packets or error log entries are included in the mock state.</p>
          <div class="alert" style="margin-top: 12px;">
            Status: healthy. Public demo uses hard-coded pipeline health data for a stable customer walkthrough.
          </div>
        </section>
      </div>
    `;
  }

  function openHowItWorksModal() {
    modalRoot.innerHTML = `
      <div class="modal-backdrop" id="closeBackdrop">
        <div class="modal">
          <div class="close-row">
            <div>
              <div class="kicker">How It Works</div>
              <h2>PacketQL architecture in one flow</h2>
            </div>
            <button id="closeModalButton" class="secondary-button">Close</button>
          </div>
          <p class="helper">PacketQL uses Zeek as the packet parser, streams logs through Kafka, normalizes and enriches events in Go, and writes structured Parquet outputs that analysts query with DuckDB.</p>
          <div class="modal-grid">
            ${[
              ["PCAP", "Analyst uploads a packet capture."],
              ["Zeek", "Zeek extracts network protocol logs in the background."],
              ["Kafka", "Events are streamed through Kafka in KRaft mode."],
              ["Go Pipeline", "Logs are normalized, enriched, and routed."],
              ["Parquet", "Structured tables are written into Parquet files."],
              ["DuckDB + UI", "DuckDB powers SQL and the UI presents dashboard and search."]
            ].map((step) => `
              <div class="modal-step">
                <strong>${step[0]}</strong>
                <div class="helper">${step[1]}</div>
              </div>
            `).join("")}
          </div>
          <p class="helper" style="margin-top: 16px;">
            Learn more about Zeek:
            <a class="muted-link" href="https://zeek.org/" target="_blank" rel="noreferrer">zeek.org</a>
          </p>
        </div>
      </div>
    `;

    document.getElementById("closeModalButton").addEventListener("click", closeModal);
    document.getElementById("closeBackdrop").addEventListener("click", (event) => {
      if (event.target.id === "closeBackdrop") closeModal();
    });
  }

  function openLogModal(entry) {
    modalRoot.innerHTML = `
      <div class="modal-backdrop" id="closeBackdrop">
        <div class="modal">
          <div class="close-row">
            <div>
              <div class="kicker">Log Details</div>
              <h2>${entry.source} · ${entry.uid}</h2>
            </div>
            <button id="closeModalButton" class="secondary-button">Close</button>
          </div>
          <div class="table-wrap" style="margin-top: 18px;">
            <table>
              <thead><tr><th>Field</th><th>Value</th></tr></thead>
              <tbody>
                ${Object.keys(entry).sort().map((key) => `<tr><td>${key}</td><td>${entry[key]}</td></tr>`).join("")}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;

    document.getElementById("closeModalButton").addEventListener("click", closeModal);
    document.getElementById("closeBackdrop").addEventListener("click", (event) => {
      if (event.target.id === "closeBackdrop") closeModal();
    });
  }

  function closeModal() {
    modalRoot.innerHTML = "";
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function attachSharedActions() {
    document.querySelectorAll("[data-open-page]").forEach((button) => {
      button.addEventListener("click", () => {
        setPage(button.dataset.openPage);
      });
    });
  }

  function renderAll() {
    renderSourceBar();
    renderUploadPage();
    renderDashboardPage();
    renderSearchPage();
    renderSqlPage();
    renderHealthPage();
    attachSharedActions();
  }

  document.querySelectorAll(".nav-item").forEach((button) => {
    button.addEventListener("click", () => setPage(button.dataset.page));
  });

  sourceSelect.addEventListener("change", (event) => {
    state.sourceId = event.target.value;
    state.searchTerm = "";
    state.searchSource = "all";
    state.sqlSample = Object.keys(currentSource().sqlSamples)[0];
    renderAll();
  });

  document.getElementById("howItWorksButton").addEventListener("click", openHowItWorksModal);

  renderSourcePicker();
  renderAll();
})();
