/* APQCrypt dashboard: shared pipeline controls + one loader per page.
   Every value that comes from the network or from CSV files is passed through esc()
   before it is put into the page, so crafted packet text cannot inject HTML. */
(function () {
  'use strict';

  const $ = id => document.getElementById(id);
  const esc = s => String(s ?? '').replace(/[&<>"']/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const isNum = v => typeof v === 'number' && isFinite(v);
  const num = (v, d = 2) => (v === null || v === undefined || (typeof v === 'number' && !isFinite(v)))
    ? '—' : (typeof v === 'number' ? String(+v.toFixed(d)) : esc(v));
  const page = document.body.dataset.page;
  const Page = {};

  async function api(url, opts) {
    try {
      const r = await fetch(url, opts);
      let d = {};
      try { d = await r.json(); } catch (e) { /* not json */ }
      return { ok: r.ok, status: r.status, d };
    } catch (e) {
      return { ok: false, status: 0, d: { message: String(e) } };
    }
  }

  /* ============ PIPELINE STATUS (shared) ============ */
  const STAGE_ORDER = ['capture', 'features', 'sensitivity', 'policy', 'encryption', 'finished'];
  const RUNNING = ['capture', 'features', 'sensitivity', 'policy', 'encryption'];
  let polling = null, lastKey = 'capture', lastTs = null, lastChange = 0;

  function setPill(state, text) {
    $('livePill').className = 'live-pill ' + state;
    $('livePillText').textContent = text;
  }

  function setStages(key, isError) {
    const idx = STAGE_ORDER.indexOf(key);
    STAGE_ORDER.forEach((k, i) => {
      const el = $('stage-' + k);
      el.className = 'stage';
      if (isError && i === idx) el.className = 'stage error';
      else if (i < idx || (i === idx && k === 'finished')) el.className = 'stage done';
      else if (i === idx) el.className = 'stage active';
    });
    $('trackFill').style.width = (idx < 0 ? 0 : (idx / (STAGE_ORDER.length - 1)) * 100) + '%';
    const p = $('particle');
    if (!isError && key !== 'finished' && idx >= 0) p.classList.add('run'); else p.classList.remove('run');
  }

  function mapStageToKey(stage) {
    const s = (stage || '').toLowerCase();
    if (!s) return null;
    if (s.includes('error')) return 'error';
    if (s.includes('start')) return 'capture';
    if (s.includes('capture')) return 'capture';
    if (s.includes('feature')) return 'features';
    if (s.includes('sensitiv')) return 'sensitivity';
    if (s.includes('policy')) return 'policy';
    if (s.includes('encrypt')) return 'encryption';
    if (s.includes('finish')) return 'finished';
    return null;
  }

  function setUiRunning() {
    const b = $('startBtn');
    b.disabled = true; b.textContent = '● Running…';
    setPill('running', 'RUNNING');
  }

  function finishPolling() {
    if (polling) clearInterval(polling);
    polling = null;
    const b = $('startBtn');
    b.disabled = false; b.textContent = '▶ Start pipeline';
  }

  function showStatusError(msg) {
    const el = $('statusLine');
    el.className = 'status-line error';
    el.textContent = msg;
    setPill('error', 'ERROR');
  }

  function startPolling() {
    if (polling) clearInterval(polling);
    lastChange = Date.now();
    polling = setInterval(pollStatus, 1200);
    pollStatus();
  }

  async function launch(extra) {
    extra = extra || {};
    setUiRunning();
    setStages('capture', false);
    $('statusLine').className = 'status-line';
    $('statusLine').textContent = 'Starting pipeline…';

    const q = new URLSearchParams({ mode: $('modeSel').value });
    const load = $('loadSel').value;
    if (load) q.set('force', load);
    if ($('reuseChk').checked && !extra.start_from) q.set('replay', '1');
    for (const [k, v] of Object.entries(extra)) q.set(k, v);

    const r = await api('/start-pipeline?' + q.toString(), { method: 'POST' });
    if (!r.ok) {
      showStatusError(r.d.message || ('Pipeline could not start (HTTP ' + r.status + ')'));
      setStages(lastKey, true);
      finishPolling();
      return;
    }
    startPolling();
  }
  const startPipeline = () => launch({});
  window.APQ = { launch };

  async function pollStatus() {
    const r = await api('/status');
    const d = r.d || {};
    if (d.timestamp !== lastTs) { lastTs = d.timestamp; lastChange = Date.now(); }
    if (Date.now() - lastChange > 5 * 60 * 1000) {
      showStatusError('No update for 5 minutes. Check the server terminal.');
      setStages(lastKey, true);
      finishPolling();
      return;
    }
    const key = mapStageToKey(d.stage);
    const el = $('statusLine');

    if (key === 'error') {
      setStages(lastKey, true);
      showStatusError(d.message || 'Pipeline error');
      finishPolling();
      return;
    }
    if (key) { lastKey = key; setStages(key, false); }
    el.className = 'status-line';
    el.textContent = (d.message || '') + (d.progress != null ? '  ·  ' + d.progress + '%' : '');

    if (key === 'finished') {
      setPill('done', 'COMPLETE');
      el.className = 'status-line done';
      finishPolling();
      if (Page[page] && Page[page].load) Page[page].load();
    }
  }

  async function initStatus() {
    const r = await api('/status');
    const d = r.d || {};
    const key = mapStageToKey(d.stage);
    const age = d.timestamp ? (Date.now() / 1000 - d.timestamp) : null;
    const el = $('statusLine');
    if (key && RUNNING.includes(key) && age !== null && age < 120) {
      lastKey = key; setUiRunning(); setStages(key, false); startPolling();
    } else if (key === 'finished') {
      setStages('finished', false); setPill('done', 'COMPLETE');
      el.className = 'status-line done'; el.textContent = d.message || 'Last run finished';
    } else if (key === 'error') {
      el.className = 'status-line error'; el.textContent = d.message || 'Last run failed';
    }
  }

  function setCheck(id, ok) {
    const el = $(id);
    if (!el) return;
    el.classList.remove('ok', 'bad');
    el.classList.add(ok ? 'ok' : 'bad');
  }

  async function refreshDiagnostics() {
    const r = await api('/diagnostics');
    const d = r.d || {};
    setCheck('diag-sudo', d.sudo_access);
    setCheck('diag-mininet', d.mininet_installed);
    setCheck('diag-tshark', d.tshark_installed);
    setCheck('diag-oqs', d.liboqs_mlkem);
    setCheck('diag-data', d.data_dir_exists);
  }

  /* ============ SHARED RENDER HELPERS ============ */
  const PROTO_CLASS = {
    TCP: 'fill-tcp', UDP: 'fill-udp', HTTP: 'fill-http', HTTPS: 'fill-https', DNS: 'fill-dns',
    ICMP: 'fill-icmp', ARP: 'fill-arp', SSH: 'fill-ssh', NTP: 'fill-ntp', OTHER: 'fill-other'
  };
  const TIER_CLASS = { LOW: 'fill-low', MEDIUM: 'fill-medium', HIGH: 'fill-high' };
  const POLICY_CLASS = {
    'High Security Policy': 'fill-high', 'Standard Security Policy': 'fill-medium', 'Default Security Policy': 'fill-low'
  };

  function renderBars(id, obj, classMap, total) {
    const c = $(id);
    if (!c) return;
    if (!obj || Object.keys(obj).length === 0) { c.innerHTML = '<div class="empty-note">No data available</div>'; return; }
    const t = total || Object.values(obj).reduce((a, b) => a + b, 0) || 1;
    let html = '';
    for (const [key, count] of Object.entries(obj)) {
      const pct = Math.round((count / t) * 100);
      html += `<div class="bar-row"><div class="bar-head"><span>${esc(key)}</span><b>${esc(count)} · ${pct}%</b></div>
        <div class="bar-track"><div class="bar-fill ${(classMap && classMap[key]) || 'fill-other'}" style="width:${pct}%"></div></div></div>`;
    }
    c.innerHTML = html;
  }

  function renderTimings(timings, names, withTotal) {
    const c = $('timingList');
    if (!c) return;
    if (!timings) { c.innerHTML = '<div class="empty-note">No timing data yet</div>'; return; }
    let html = '';
    for (const n of names) if (timings[n] != null) html += `<div class="timing-row"><span class="t-name">${esc(n)}</span><span class="t-val">${esc(timings[n])}s</span></div>`;
    if (withTotal && timings['Total Execution'] != null)
      html += `<div class="timing-row total"><span class="t-name">Total</span><span class="t-val">${esc(timings['Total Execution'])}s</span></div>`;
    c.innerHTML = html || '<div class="empty-note">No timing data yet</div>';
  }

  /* opts: labels{col:label}, badges[cols], max (truncate chars), cell(col,val,row)->html|undefined */
  function renderTable(el, columns, rows, opts) {
    opts = opts || {};
    if (!el) return;
    if (!columns || !columns.length || !rows || !rows.length) {
      el.innerHTML = '<tbody><tr><td class="empty-note" style="padding:16px">No data yet. Run the pipeline first.</td></tr></tbody>';
      return;
    }
    const max = opts.max || 40;
    const head = '<thead><tr>' + columns.map(c => `<th>${esc((opts.labels && opts.labels[c]) || c)}</th>`).join('') + '</tr></thead>';
    const body = '<tbody>' + rows.map(row => '<tr>' + columns.map(col => {
      const v = row[col];
      if (opts.cell) { const custom = opts.cell(col, v, row); if (custom !== undefined) return `<td>${custom}</td>`; }
      if (v === null || v === undefined || v === '') return '<td>—</td>';
      if ((opts.badges || []).includes(col) && ['LOW', 'MEDIUM', 'HIGH'].includes(v))
        return `<td><span class="tier-badge tier-${v}">${v}</span></td>`;
      if (isNum(v)) return `<td>${esc(+v.toFixed(3))}</td>`;
      const s = String(v);
      if (s.length > max) return `<td class="trunc" title="${esc(s)}">${esc(s.slice(0, max))}…</td>`;
      return `<td>${esc(s)}</td>`;
    }).join('') + '</tr>').join('') + '</tbody>';
    el.innerHTML = head + body;
  }

  /* ============ PAGE 1: CAPTURE + FEATURES ============ */
  Page.capture = {
    async load() {
      const { d } = await api('/results');
      if (!d.total_packets) { renderTable($('featTable'), [], []); return; }
      $('totalPackets').innerHTML = esc(d.total_packets) + '<span class="unit">packets</span>';
      $('captureFile').textContent = d.packet_file || '';
      $('flowCount').textContent = d.flows ?? '—';
      $('payloadCount').textContent = d.packets_with_payload ?? '—';
      renderBars('protocolBars', d.protocols, PROTO_CLASS, d.total_packets);
      renderTimings(d.module_timings, ['Packet Capture', 'Feature Extraction'], false);
      const v = await api('/view/features');
      if (v.d.error) { renderTable($('featTable'), [], []); return; }
      renderTable($('featTable'), v.d.columns, v.d.data, { max: 34 });
      $('tableRowCount').textContent = `showing ${(v.d.data || []).length} of ${v.d.total_rows}`;
    }
  };

  /* ============ PAGE 2: SENSITIVITY ============ */
  Page.sensitivity = {
    async load() {
      const { d } = await api('/results');
      renderBars('sensitivityBars', d.sensitivity, TIER_CLASS, d.total_packets);
      renderBars('riskBars', d.risk_tiers, TIER_CLASS, d.total_packets);
      $('dpiFound').textContent = d.dpi_found ?? '—';
      renderTimings(d.module_timings, ['Sensitivity Analysis'], false);
      const v = await api('/view/results');
      if (v.d.error) { renderTable($('scoreTable'), [], []); return; }
      const want = ['Pkt_Index', 'Protocol', 'Dest_Port', 'Confidentiality_Score', 'DPI_Signal', 'Risk_Tier',
        'Risk_Confidence', 'Packet_Score', 'Final_Score', 'Sensitivity', 'Reason'];
      const cols = want.filter(c => (v.d.columns || []).includes(c));
      renderTable($('scoreTable'), cols.length ? cols : v.d.columns, v.d.data,
        { badges: ['Sensitivity', 'Risk_Tier'], max: 70 });
      $('tableRowCount').textContent = `showing ${(v.d.data || []).length} of ${v.d.total_rows}`;
    }
  };

  /* ============ PAGE 3: SYSTEM CONDITION ============ */
  Page.resources = {
    chart: null, timer: null, hist: { cpu: [], mem: [], t: [] }, limits: { cpu: 50, mem: 70 }, state: null,
    async load() {
      const m = await api('/policy-matrix');
      if (m.d.rows) {
        this.limits = { cpu: m.d.cpu_limit, mem: m.d.mem_limit };
        this.renderMatrix(m.d.rows);
      }
      const { d } = await api('/results');
      this.renderLast(d);
      renderBars('policyBars', d.policies, POLICY_CLASS, d.total_packets);
      renderBars('algorithmBars', d.algorithms, {}, d.total_packets);
      if (!this.timer) { this.tick(); this.timer = setInterval(() => this.tick(), 2000); }
    },
    renderMatrix(rows) {
      const get = (s, r) => rows.find(x => x.sensitivity === s && x.resources === r);
      const cell = (s, r) => {
        const x = get(s, r);
        if (!x) return '<td>—</td>';
        const pq = x.pqc_handshake ? '<span class="pq-yes">quantum-safe</span>' : '<span class="pq-no">classical</span>';
        return `<td data-res="${r}">${esc(x.algorithm)}<br>${pq}</td>`;
      };
      let html = '<thead><tr><th>Sensitivity</th><th>Computer free (AVAILABLE)</th><th>Computer busy (CONSTRAINED)</th></tr></thead><tbody>';
      for (const s of ['HIGH', 'MEDIUM', 'LOW'])
        html += `<tr><td><span class="tier-badge tier-${s}">${s}</span></td>${cell(s, 'AVAILABLE')}${cell(s, 'CONSTRAINED')}</tr>`;
      $('matrixTable').innerHTML = html + '</tbody>';
      this.markNow();
    },
    markNow() {
      document.querySelectorAll('#matrixTable td[data-res]').forEach(td =>
        td.classList.toggle('now', td.dataset.res === this.state));
    },
    renderLast(d) {
      const c = $('lastDecision');
      const r = d.resource_status;
      if (!r) { c.innerHTML = '<div class="empty-note">No run yet</div>'; return; }
      const cls = r.status === 'CONSTRAINED' ? 'badc' : 'okc';
      const reading = (r.cpu_percent == null && r.memory_percent == null)
        ? 'Simulated (forced for the demo)' : `CPU ${num(r.cpu_percent, 1)}% · Memory ${num(r.memory_percent, 1)}%`;
      c.innerHTML = `<div class="mono">Condition used: <b class="${cls}">${esc(r.status)}</b><br>
        <span class="mutedtxt">${reading}</span><br>
        <span class="mutedtxt" style="font-size:12px">The decision table below was applied with this condition.</span></div>`;
    },
    async tick() {
      const r = await api('/live-resources');
      const d = r.d;
      if (!r.ok || d.cpu === undefined) return;
      this.limits = { cpu: d.cpu_limit, mem: d.memory_limit };
      $('cpuVal').textContent = d.cpu.toFixed(0) + '%';
      $('memVal').textContent = d.memory.toFixed(0) + '%';
      $('cpuFill').style.width = d.cpu + '%'; $('memFill').style.width = d.memory + '%';
      $('cpuFill').classList.toggle('hot', d.cpu >= d.cpu_limit);
      $('memFill').classList.toggle('hot', d.memory >= d.memory_limit);
      $('cpuLimit').style.left = d.cpu_limit + '%'; $('memLimit').style.left = d.memory_limit + '%';
      $('limitNote').textContent = `Yellow lines are the limits: CPU ${d.cpu_limit}% · Memory ${d.memory_limit}%. Over either one = CONSTRAINED.`;
      this.state = d.status;
      const chip = $('stateChip');
      chip.textContent = d.status;
      chip.className = 'state-chip state-' + d.status;
      this.markNow();

      const h = this.hist;
      h.cpu.push(d.cpu); h.mem.push(d.memory); h.t.push(new Date().toLocaleTimeString());
      if (h.cpu.length > 30) { h.cpu.shift(); h.mem.shift(); h.t.shift(); }
      this.drawChart();
    },
    drawChart() {
      const h = this.hist, n = h.cpu.length;
      const limCpu = Array(n).fill(this.limits.cpu), limMem = Array(n).fill(this.limits.mem);
      if (!this.chart) {
        this.chart = new Chart($('histChart'), {
          type: 'line',
          data: {
            labels: h.t, datasets: [
              { label: 'CPU %', data: h.cpu, borderColor: '#4DD8C4', backgroundColor: '#4DD8C4', tension: .3, pointRadius: 0 },
              { label: 'Memory %', data: h.mem, borderColor: '#818CF8', backgroundColor: '#818CF8', tension: .3, pointRadius: 0 },
              { label: 'CPU limit', data: limCpu, borderColor: '#FBBF24', borderDash: [6, 4], pointRadius: 0 },
              { label: 'Memory limit', data: limMem, borderColor: '#FB7185', borderDash: [6, 4], pointRadius: 0 }]
          },
          options: {
            responsive: true, maintainAspectRatio: false, animation: false,
            plugins: { legend: { labels: { color: '#7E8AA8', font: { size: 11 } } } },
            scales: { y: { min: 0, max: 100, ticks: { color: '#7E8AA8' }, grid: { color: '#283151' } },
              x: { ticks: { color: '#7E8AA8', maxTicksLimit: 6 }, grid: { display: false } } }
          }
        });
      } else {
        this.chart.data.labels = h.t;
        this.chart.data.datasets[0].data = h.cpu; this.chart.data.datasets[1].data = h.mem;
        this.chart.data.datasets[2].data = limCpu; this.chart.data.datasets[3].data = limMem;
        this.chart.update();
      }
    }
  };

  /* ============ PAGE 4: ENCRYPTION ============ */
  function renderEncryptionSummary(s, checks) {
    const c = $('encryptionSummary');
    if (!s || !s.total_packets) { c.innerHTML = '<div class="empty-note">Run the pipeline first</div>'; return; }
    const k = (checks && checks.checks) || {};
    c.innerHTML = `<div class="mono">
      <div>${esc(s.total_packets)} packets in <b>${esc(s.total_flows)}</b> conversations</div>
      <div class="mutedtxt"><b class="badc">${esc(s.pqc_handshakes)}</b> hybrid quantum-safe key exchanges</div>
      <div class="mutedtxt" style="font-size:12px;margin-top:8px">Key exchange time: ${esc(s.total_handshake_ms)} ms<br>
        Encrypt time: ${esc(s.total_encrypt_ms)} ms<br>Ciphertext: ${esc(Number(s.total_ciphertext_bytes).toLocaleString())} bytes</div>
      <div class="okc" style="font-size:12px;margin-top:8px">Decrypt checks passed: ${esc(k.roundtrip_ok ?? '—')} · Tampering caught: ${esc(k.tamper_detected ?? '—')}
        ${k.tamper_missed ? ' · <b class="badc">MISSED: ' + esc(k.tamper_missed) + '</b>' : ''}</div></div>`;
  }

  Page.encryption = {
    async load() {
      const { d } = await api('/results');
      renderEncryptionSummary(d.encryption_summary, d.encryption_checks);
      renderBars('kexBars', d.key_exchanges, {}, null);
      renderBars('algorithmBars', d.algorithms, {}, d.total_packets);
      const f = await api('/flows');
      const rows = f.d.rows || [];
      const high = rows.filter(r => r.sensitivity === 'HIGH');
      const pq = high.filter(r => /ML-KEM|Kyber/.test(r.key_exchange || ''));
      if (high.length) {
        const pct = Math.round(pq.length / high.length * 100);
        $('highCov').innerHTML = pct + '<span class="unit">%</span>';
        $('highCovNote').textContent = `${pq.length} of ${high.length} HIGH conversations use a quantum-safe key exchange` +
          (pct < 100 ? ' (expected in the "normal" mode)' : '');
      } else { $('highCov').textContent = '—'; $('highCovNote').textContent = 'no HIGH conversations in this run'; }
      $('flowCountTxt').textContent = rows.length ? rows.length + ' conversations' : '';
      renderTable($('flowTable'),
        ['flow', 'protocol', 'packets', 'peek', 'sensitivity', 'score', 'key_exchange', 'cipher', 'handshake_ms', 'reason'], rows, {
          badges: ['sensitivity'], max: 46,
          labels: { flow: 'Conversation', peek: 'What we saw (peek)', key_exchange: 'Key exchange', handshake_ms: 'Key exch. ms', reason: 'Why' },
          cell: (col, v) => {
            if (col === 'key_exchange') return `<span class="${/ML-KEM|Kyber/.test(v || '') ? 'pq-yes' : 'pq-no'}">${esc(v)}</span>`;
            return undefined;
          }
        });
    }
  };

  /* ============ PAGE 5: COMPARISON ENGINE ============ */
  const SERIES_COLOR = { static_aes: '#7E8AA8', static_pqc: '#FB7185', 'adaptive:free': '#4DD8C4', 'adaptive:busy': '#2BA897' };
  const SERIES_ORDER = ['static_aes', 'static_pqc', 'adaptive:free', 'adaptive:busy'];
  const MODE_COLOR = { static_aes: '#7E8AA8', static_pqc: '#FB7185', adaptive: '#4DD8C4' };
  const axis = { ticks: { color: '#7E8AA8' }, grid: { color: '#283151' } };
  const SERIES_SHORT = { static_aes: 'A · Normal', static_pqc: 'B · All quantum-safe', 'adaptive:free': 'C · Adaptive (free)', 'adaptive:busy': 'C · Adaptive (busy)' };

  function chartOf(id, config) {
    const old = Chart.getChart(id); if (old) old.destroy();
    const el = $(id); if (!el) return;
    new Chart(el, config);
  }

  Page.compare = {
    data: null, view: { host: null, sha: null }, timer: null, lastDone: -1,
    init() {
      $('measureAll').addEventListener('click', () => this.run(['static_aes', 'static_pqc', 'adaptive']));
      $('cancelBtn').addEventListener('click', async () => { await api('/api/comparison/cancel', { method: 'POST' }); });
      $('microBtn').addEventListener('click', async () => {
        const r = await api('/api/comparison/micro', { method: 'POST' });
        if (!r.ok) { $('microMsg').textContent = r.d.message || 'could not start'; return; }
        this.watch();
      });
      $('clearAll').addEventListener('click', async () => {
        if (!confirm('Delete every stored run (all machines, all captures)? This cannot be undone.')) return;
        await api('/api/comparison/clear', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ all: true }) });
        this.load();
      });
      $('modeCards').addEventListener('click', async e => {
        const run = e.target.closest('button[data-run]'), clr = e.target.closest('button[data-clear]');
        if (run) this.run([run.dataset.run]);
        if (clr) {
          if (!confirm('Delete the stored runs of this mode (on this machine and capture)?')) return;
          await api('/api/comparison/clear', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: clr.dataset.clear }) });
          this.load();
        }
      });
      $('datasetBar').addEventListener('change', e => {
        if (e.target.id === 'hostSel') this.view = { host: e.target.value, sha: null };
        if (e.target.id === 'capSel') this.view.sha = e.target.value;
        this.load();
      });
    },
    async load() {
      const q = new URLSearchParams();
      if (this.view.host) q.set('host', this.view.host);
      if (this.view.sha) q.set('sha', this.view.sha);
      const r = await api('/api/comparison?' + q.toString());
      if (!r.ok) return;
      this.data = r.d;
      this.render();
      if (r.d.state && r.d.state.running) this.watch();
    },
    async run(modes) {
      const body = { modes, runs: +$('runsSel').value, interleave: $('interleave').checked };
      const cond = document.getElementById('condSel');
      if (cond && cond.value) body.force = cond.value;
      $('runProgress').innerHTML = '<div class="empty-note">Starting…</div>';
      const r = await api('/api/comparison/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      if (!r.ok) { $('runProgress').innerHTML = `<div class="errbox">${esc(r.d.message || 'could not start')}</div>`; return; }
      this.view = { host: null, sha: null };
      this.lastDone = -1;
      this.watch();
    },
    watch() {
      if (this.timer) return;
      const tick = async () => {
        const r = await api('/api/comparison/status');
        const s = r.d || {};
        if (this.data) this.data.state = s;
        this.progress();
        this.cards();
        if (s.done !== this.lastDone) { this.lastDone = s.done; await this.load(); }
        if (!s.running) { clearInterval(this.timer); this.timer = null; await this.load(); }
      };
      this.timer = setInterval(tick, 1500); tick();
    },
    render() { this.setup(); this.cards(); this.progress(); this.findings(); this.charts(); this.numbers(); this.micro(); this.evidence(); },

    setup() {
      const d = this.data, h = d.host, c = d.capture, v = d.viewing;
      const anySeries = Object.values(d.series)[0];
      const card = (t, rows) => `<div class="setup-card"><div class="t">${esc(t)}</div><div class="v">${rows.map(x => esc(x)).join('<br>')}</div></div>`;
      $('setupGrid').innerHTML =
        card('Machine', [h.board || h.cpu, `${h.machine} · ${h.cores} cores · ${h.ram_gb ?? '?'} GB RAM`, h.os || '', 'Python ' + h.python, h.isa ? 'ISA: ' + h.isa : '']) +
        card('Capture used', c ? [`${c.path}`, `fingerprint ${c.sha8} · ${(c.size / 1024).toFixed(1)} KB`,
          anySeries ? `${anySeries.packets} packets · ${anySeries.conversations} conversations` : 'packets/conversations: shown after the first run'] : ['No capture yet', 'Run the pipeline first']) +
        card('Crypto', [`ML-KEM provider: ${d.provider}`, `liboqs: ${h.liboqs || 'not installed'}`, `cryptography: ${h.cryptography || '?'}`]) +
        card('What is compared', ['Same capture for every mode', 'Fresh process per run', 'First run per mode = warm-up (not counted)', 'Adaptive uses the current Settings']);
      let notes = '';
      if (d.provider !== 'liboqs') notes += '<div class="errbox">The ML-KEM provider is <b>simulated</b>. Quantum-safe modes cannot be measured until you switch to real liboqs on the Interfaces page.</div>';
      else if (!h.liboqs) notes += '<div class="warnbox">liboqs is not installed. Modes B and C will refuse to run.</div>';
      if (!v.is_this_machine) notes += '<div class="warnbox">You are viewing results measured on <b>another machine</b>. Measuring here would create a separate set.</div>';
      else if (!v.is_current_capture) notes += '<div class="warnbox">You are viewing results for an <b>older capture</b>, not the current one.</div>';
      if (d.ignored_runs) notes += `<div class="sub">${esc(d.ignored_runs)} stored run(s) from another machine or capture are kept but not mixed into these results.</div>`;
      $('setupNotes').innerHTML = notes;
      const hosts = d.datasets.hosts, caps = d.datasets.captures;
      $('datasetBar').innerHTML = (hosts.length > 1 ? `<span class="mono mutedtxt">machine</span><select class="ctl" id="hostSel">${hosts.map(x => `<option value="${esc(x.id)}" ${x.id === v.host ? 'selected' : ''}>${esc(x.label)}</option>`).join('')}</select>` : '') +
        (caps.length > 1 ? `<span class="mono mutedtxt">capture</span><select class="ctl" id="capSel">${caps.map(x => `<option value="${esc(x.sha8)}" ${x.sha8 === v.sha ? 'selected' : ''}>${esc(x.sha8)} (${(x.size / 1024).toFixed(0)} KB)</option>`).join('')}</select>` : '');
    },

    cards() {
      const d = this.data; if (!d) return;
      const st = d.state || {}, running = !!st.running;
      const cur = st.current && st.current.mode;
      $('measureAll').disabled = running;
      $('cancelBtn').style.display = running && st.task === 'measure' ? '' : 'none';
      const prevCond = document.getElementById('condSel') ? document.getElementById('condSel').value : '';
      $('modeCards').innerHTML = Object.entries(d.modes).sort((a, b) => a[1].letter.localeCompare(b[1].letter)).map(([key, m]) => {
        let status, cls;
        if (running && cur === key) { status = `Measuring… run ${st.current.index}/${st.total}${st.current.warmup ? ' (warm-up)' : ''}`; cls = 'busy'; }
        else if (m.runs_counted) { status = `✓ ${m.runs_counted} run${m.runs_counted > 1 ? 's' : ''} measured · last ${new Date(m.last_run * 1000).toLocaleTimeString()}`; cls = 'ok'; }
        else { status = 'Not measured yet'; cls = 'none'; }
        const problem = m.last_problem ? `<div class="mc-status bad">Last problem: ${esc(String(m.last_problem).slice(0, 160))}</div>` : '';
        const cond = key === 'adaptive' ? `<div class="row-actions" style="margin:0"><span class="mono mutedtxt" style="font-size:11px">computer condition</span>
            <select class="ctl" id="condSel"><option value="">real (measured when the run starts)</option><option value="AVAILABLE">simulate: free</option><option value="CONSTRAINED">simulate: busy</option></select></div>` : '';
        return `<div class="mode-card ${running && cur === key ? 'running' : ''}">
          <div class="mc-title"><span class="mc-letter" style="background:${MODE_COLOR[key]}">${esc(m.letter)}</span>${esc(m.title)}</div>
          <div class="mc-about">${esc(m.about)}</div>${cond}
          <div class="mc-status ${cls}">${esc(status)}</div>${problem}
          <div class="row-actions" style="margin:0"><button class="ghost-btn" data-run="${esc(key)}" ${running ? 'disabled' : ''}>▶ Measure ${esc(m.title)}</button>
            ${m.runs_counted ? `<button class="ghost-btn" data-clear="${esc(key)}" ${running ? 'disabled' : ''}>Clear</button>` : ''}</div></div>`;
      }).join('');
      const cs = document.getElementById('condSel'); if (cs && prevCond) cs.value = prevCond;
    },

    progress() {
      const st = (this.data && this.data.state) || {};
      if (!st.total || (!st.running && !st.error && !st.last_error && st.message !== 'Finished' && st.message !== 'Cancelled')) { $('runProgress').innerHTML = ''; return; }
      const pct = st.total ? Math.round(st.done / st.total * 100) : 0;
      let h = `<div class="progress"><div style="width:${pct}%"></div></div><div class="mono mutedtxt" style="font-size:12px">${esc(st.message || '')} · ${esc(st.done)}/${esc(st.total)}</div>`;
      if (st.error) h += `<div class="errbox">${esc(st.error)}</div>`;
      else if (st.last_error) h += `<div class="warnbox">${esc(st.last_error)} (this run was stored but is not counted)</div>`;
      $('runProgress').innerHTML = h;
    },

    findings() {
      const m = (this.data && this.data.messages) || [];
      $('findings').innerHTML = m.map(x => `<li>${esc(x)}</li>`).join('');
    },

    series() {
      const s = this.data.series;
      return SERIES_ORDER.filter(k => s[k]).map(k => s[k]);
    },

    charts() {
      const ser = this.series();
      $('chartsEmpty').style.display = ser.length ? 'none' : '';
      $('chartsWrap').style.display = ser.length ? '' : 'none';
      if (!ser.length) return;
      const labels = ser.map(s => SERIES_SHORT[s.key] || s.label), colors = ser.map(s => SERIES_COLOR[s.key]);
      const val = (s, k, f) => (s[k] ? +(s[k].mean * (f || 1)).toFixed(4) : null);
      const bar = (id, key, f) => chartOf(id, {
        type: 'bar', data: { labels, datasets: [{ data: ser.map(s => val(s, key, f)), backgroundColor: colors, borderRadius: 6 }] },
        options: { responsive: true, maintainAspectRatio: false, animation: { duration: 300 }, plugins: { legend: { display: false } },
          scales: { x: { ticks: { color: '#7E8AA8', font: { size: 10 } }, grid: { display: false } }, y: { beginAtZero: true, ...axis } } }
      });
      bar('chTime', 'total_s'); bar('chCpu', 'cpu_s'); bar('chMem', 'peak_mem_mb'); bar('chHs', 'handshake_ms_total');
      const part = (s, k, f) => (s[k] ? s[k].mean * (f || 1) : 0);
      const other = s => Math.max(part(s, 'total_s') - part(s, 'parse_s') - part(s, 'decision_s') - part(s, 'handshake_ms_total', .001) - part(s, 'encrypt_ms_total', .001), 0);
      const stack = (label, color, fn) => ({ label, backgroundColor: color, data: ser.map(s => +fn(s).toFixed(4)), borderRadius: 2 });
      chartOf('chStack', {
        type: 'bar', data: { labels, datasets: [
          stack('Read capture', '#818CF8', s => part(s, 'parse_s')), stack('Decision (AI model, scoring, policy)', '#FBBF24', s => part(s, 'decision_s')),
          stack('Key exchange', '#FB7185', s => part(s, 'handshake_ms_total', .001)), stack('Encrypt packets', '#4DD8C4', s => part(s, 'encrypt_ms_total', .001)),
          stack('Other (file reading/writing)', '#4B5572', other)] },
        options: { responsive: true, maintainAspectRatio: false, animation: { duration: 300 }, plugins: { legend: { labels: { color: '#7E8AA8', font: { size: 10 } } } },
          scales: { x: { stacked: true, ticks: { color: '#7E8AA8', font: { size: 10 } }, grid: { display: false } }, y: { stacked: true, beginAtZero: true, ...axis } } }
      });
      chartOf('chPq', {
        type: 'bar', data: { labels, datasets: [
          { label: 'All conversations', backgroundColor: '#818CF8', borderRadius: 6, data: ser.map(s => (s.pq_flow_share ? +(s.pq_flow_share.mean * 100).toFixed(1) : null)) },
          { label: 'HIGH conversations', backgroundColor: '#FB7185', borderRadius: 6, data: ser.map(s => (s.high_coverage ? +(s.high_coverage.mean * 100).toFixed(1) : null)) }] },
        options: { responsive: true, maintainAspectRatio: false, animation: { duration: 300 }, plugins: { legend: { labels: { color: '#7E8AA8', font: { size: 10 } } } },
          scales: { x: { ticks: { color: '#7E8AA8', font: { size: 10 } }, grid: { display: false } }, y: { beginAtZero: true, max: 100, ...axis } } }
      });
    },

    numbers() {
      const ser = this.series();
      if (!ser.length) { $('numTable').innerHTML = '<tbody><tr><td class="empty-note" style="padding:16px">Nothing measured yet.</td></tr></tbody>'; return; }
      const pm = (st, d, f) => (st ? ((st.mean * (f || 1)).toFixed(d) + (st.std != null ? ' ± ' + (st.std * (f || 1)).toFixed(d) : '')) : '—');
      const pct = st => (st ? Math.round(st.mean * 100) + '%' : '—');
      let h = '<thead><tr><th>Mode</th><th>Runs</th><th>Total time (s)</th><th>Decision (s)</th><th>Key exchange (ms)</th><th>Encrypt (ms)</th><th>CPU (s)</th><th>Peak memory (MB)</th><th>Extra bytes</th><th>Quantum-safe conversations</th><th>HIGH protected</th></tr></thead><tbody>';
      ser.forEach(s => {
        h += `<tr><td>${esc(s.label)}</td><td>${esc(s.n)}</td><td>${pm(s.total_s, 4)}</td><td>${pm(s.decision_s, 4)}</td><td>${pm(s.handshake_ms_total, 2)}</td><td>${pm(s.encrypt_ms_total, 2)}</td>
          <td>${pm(s.cpu_s, 4)}</td><td>${pm(s.peak_mem_mb, 0)}</td><td>${s.overhead_bytes ? Math.round(s.overhead_bytes.mean) : '—'}</td><td>${pct(s.pq_flow_share)}</td><td>${pct(s.high_coverage)}</td></tr>`;
      });
      $('numTable').innerHTML = h + '</tbody>';
    },

    micro() {
      const m = this.data.micro;
      if (!m) { $('microTable').innerHTML = '<tbody><tr><td class="empty-note" style="padding:16px">Not measured yet. Press the button to measure X25519, ML-KEM, AES-GCM, ChaCha20-Poly1305 and HKDF on this machine.</td></tr></tbody>'; return; }
      $('microMsg').textContent = 'measured ' + new Date(m.started_at * 1000).toLocaleString();
      const t = us => (us >= 1000 ? (us / 1000).toFixed(3) + ' ms' : us.toFixed(1) + ' µs');
      let h = '<thead><tr><th>Group</th><th>Operation</th><th>Median</th><th>95% under</th><th>Note</th></tr></thead><tbody>';
      (m.rows || []).forEach(r => { h += `<tr><td>${esc(r.group)}</td><td>${esc(r.operation)}</td><td><b>${esc(t(r.median_us))}</b></td><td>${esc(t(r.p95_us))}</td><td>${esc(r.detail || '')}</td></tr>`; });
      (m.notes || []).forEach(n => { h += `<tr><td colspan="5" class="badc">${esc(n)}</td></tr>`; });
      $('microTable').innerHTML = h + '</tbody>';
    },

    evidence() {
      const ev = this.data.evidence || [];
      const rows = ev.map(r => ({ when: new Date(r.started_at * 1000).toLocaleTimeString(), mode: r.mode + (r.condition ? ' (' + r.condition + (r.forced ? ', simulated' : '') + ')' : ''),
        type: r.warmup ? 'warm-up' : 'measured', counted: r.ok && r.valid && !r.warmup ? 'yes' : 'no', total: r.total_s, cpu: r.cpu_s, mem: r.peak_mem_mb,
        kex: r.handshake_ms_total, pq: r.pq_flow_share != null ? Math.round(r.pq_flow_share * 100) + '%' : null,
        note: r.error || r.invalid_reason || '' }));
      renderTable($('evTable'), ['when', 'mode', 'type', 'counted', 'total', 'cpu', 'mem', 'kex', 'pq', 'note'], rows, {
        max: 80, labels: { total: 'total (s)', cpu: 'cpu (s)', mem: 'peak MB', kex: 'key exch. (ms)', pq: 'quantum-safe' } });
    }
  };

  /* ============ shared helpers for the new pages ============ */
  const kv = obj => Object.entries(obj || {}).filter(([, v]) => v !== undefined).map(([k, v]) =>
    `<div class="kv"><span>${esc(k.replace(/_/g, ' '))}</span><b>${esc(v !== null && typeof v === 'object' ? JSON.stringify(v) : (v === null ? '—' : v))}</b></div>`).join('')
    || '<div class="empty-note">nothing recorded</div>';
  const fmtTime = ts => new Date(ts * 1000).toLocaleTimeString();
  const chip = s => `<span class="chip ${s === 'done' ? 'done' : s === 'error' ? 'error' : s === 'running' ? 'running' : 'idle'}">${esc(s)}</span>`;
  const VIEW_NAME = { features: 'features', sensitivity: 'results', policy: 'policy', encryption: 'encrypted' };

  /* ============ PAGE 6: DEBUG ============ */
  Page.debug = {
    lastSeq: 0, events: [], timer: null, busy: false,
    init() {
      $('runStopBtn').addEventListener('click', () => window.APQ.launch({ stop_after: $('stopSel').value }));
      $('runFromBtn').addEventListener('click', () => window.APQ.launch({ start_from: $('fromSel').value }));
      $('traceBtn').addEventListener('click', () => this.trace());
      $('logClear').addEventListener('click', () => { this.events = []; this.renderLog(); });
      ['logStage', 'logLevel'].forEach(id => $(id).addEventListener('change', () => this.renderLog()));
      $('stepTable').addEventListener('click', e => {
        const b = e.target.closest('button[data-stage]');
        if (b) this.inspect(b.dataset.stage);
      });
      this.timer = setInterval(() => this.tick(), 1200);
    },
    async load() { await this.loadStages(); await this.loadFlows(); await this.loadRunCfg(); },
    async loadStages() {
      const r = await api('/api/debug/stages');
      this.stages = r.d.stages || [];
      const rows = this.stages.map(s => ({ step: s.title, status: s.status, seconds: s.seconds, rows: s.rows, output: s.output, stage: s.stage, exists: s.exists }));
      renderTable($('stepTable'), ['step', 'status', 'seconds', 'rows', 'output', 'inspect'], rows, {
        labels: { seconds: 'time (s)', rows: 'rows', inspect: '' },
        cell: (col, v, row) => {
          if (col === 'status') return chip(v);
          if (col === 'inspect') return `<button class="ghost-btn" data-stage="${esc(row.stage)}">Inspect</button>`;
          return undefined;
        }
      });
    },
    async inspect(stage) {
      const s = (this.stages || []).find(x => x.stage === stage);
      if (!s) return;
      const box = $('stepDetail');
      box.style.display = 'block';
      box.innerHTML = '<div class="empty-note">Loading…</div>';
      const ev = await api('/api/debug/events?stage=' + encodeURIComponent(stage) + '&limit=40');
      let html = `<div class="mono"><b>${esc(s.title)}</b> ${chip(s.status)} <span class="mutedtxt">output: ${esc(s.output)}${s.size != null ? ' · ' + esc(s.size) + ' bytes' : ''}</span></div>`;
      html += '<div class="grid-2" style="margin-top:12px"><div><div class="label">Settings used by this step</div>' + kv(s.params) +
        '</div><div><div class="label">Result of this step</div>' + kv(s.result ? Object.fromEntries(Object.entries(s.result).filter(([k]) => !['params', 'input', 'output'].includes(k))) : null) + '</div></div>';
      if (s.error_msg) html += `<div class="errbox">${esc(s.error_msg)}<br>${esc(JSON.stringify(s.error || {}))}</div>`;
      (s.warnings || []).forEach(w => { html += `<div class="warnbox">${esc(w)}</div>`; });
      const logs = (ev.d.events || []).map(e => `<span class="t">${esc(fmtTime(e.ts))}</span> <span class="l-${esc(e.level)}">${esc(e.msg)}</span> <span class="d">${esc(JSON.stringify(e.data))}</span>`).join('\n');
      html += `<div class="label" style="margin-top:14px">Log lines for this step</div><div class="console" style="height:130px">${logs || 'no log lines yet'}</div>`;
      if (VIEW_NAME[stage] && s.exists) {
        const v = await api('/view/' + VIEW_NAME[stage]);
        if (!v.d.error) {
          html += `<div class="label" style="margin-top:14px">Output sample (first 8 of ${esc(v.d.total_rows)} rows)</div><div class="table-scroll sample-table"><table id="sampleTbl"></table></div>`;
          box.innerHTML = html;
          renderTable($('sampleTbl'), v.d.columns, (v.d.data || []).slice(0, 8), { max: 28, badges: ['Sensitivity', 'Risk_Tier'] });
          return;
        }
      }
      box.innerHTML = html;
    },
    async loadFlows() {
      const r = await api('/flows');
      const sel = $('traceSel');
      const rows = r.d.rows || [];
      const keep = sel.value;
      sel.innerHTML = rows.length ? rows.map(f =>
        `<option value="${esc(f.flow)}">${esc(f.sensitivity)} · ${esc(f.protocol)} · ${esc(f.peek || 'no peek clue')} · ${esc(f.flow)}</option>`).join('')
        : '<option value="">Run the pipeline first</option>';
      if (keep) sel.value = keep;
    },
    async trace() {
      const flow = $('traceSel').value;
      const out = $('traceOut');
      if (!flow) { out.innerHTML = '<div class="empty-note">Pick a conversation first.</div>'; return; }
      out.innerHTML = '<div class="empty-note">Loading…</div>';
      const r = await api('/api/debug/trace?flow=' + encodeURIComponent(flow));
      if (!r.ok) { out.innerHTML = `<div class="errbox">${esc(r.d.error || 'trace failed')}</div>`; return; }
      out.innerHTML = '<div class="trace">' + r.d.steps.map(s =>
        `<div class="trace-card"><h4><span>${esc(s.step)}</span>${esc(s.title)}</h4><div class="sum">${esc(s.summary)}</div>${kv(s.details)}</div>`).join('') + '</div>';
    },
    async loadRunCfg() {
      const r = await api('/api/debug/run-config');
      if (!r.ok) return;
      const c = r.d.config || {}, run = r.d.run || {};
      $('runCfg').innerHTML = '<div class="label">Run</div>' + kv({ saved_at: new Date(r.d.saved_at * 1000).toLocaleString(), ...run }) +
        '<div class="label" style="margin-top:12px">Resources and scoring</div>' +
        kv({ cpu_limit: c.resources && c.resources.cpu_limit, memory_limit: c.resources && c.resources.memory_limit,
          high_threshold: c.scoring && c.scoring.high_threshold, medium_threshold: c.scoring && c.scoring.medium_threshold,
          flow_first_n: c.scoring && c.scoring.flow_first_n, use_peek: c.scoring && c.scoring.use_peek, allow_unsafe: c.policy && c.policy.allow_unsafe });
    },
    async tick() {
      const r = await api('/api/debug/events?since=' + this.lastSeq + '&limit=300');
      if (!r.ok) return;
      if (r.d.max_seq !== undefined && r.d.max_seq < this.lastSeq) { this.lastSeq = 0; this.events = []; }   // a new full run cleared the log
      const ev = r.d.events || [];
      if (ev.length) {
        this.lastSeq = ev[ev.length - 1].seq;
        this.events = this.events.concat(ev).slice(-2000);
        if (!$('logPause').checked) this.renderLog();
        if (!this.busy) { this.busy = true; await this.loadStages(); this.busy = false; }
      }
    },
    renderLog() {
      const st = $('logStage').value, lv = $('logLevel').value, box = $('logBox');
      const atEnd = box.scrollTop + box.clientHeight >= box.scrollHeight - 20;
      box.innerHTML = this.events.filter(e => (!st || e.stage === st) && (!lv || e.level === lv)).map(e =>
        `<div class="l-${esc(e.level)}"><span class="t">${esc(fmtTime(e.ts))}</span> <span class="s">[${esc(e.stage)}]</span> ${esc(e.msg)} <span class="d">${esc(JSON.stringify(e.data))}</span></div>`).join('');
      if (atEnd) box.scrollTop = box.scrollHeight;
    }
  };

  /* ============ PAGE 7: INTERFACES (wrapper) ============ */
  Page.interfaces = {
    key: null, spec: null, endpoints: [],
    init() {
      $('connRefresh').addEventListener('click', () => this.loadConn());
      $('connTable').addEventListener('click', e => {
        const b = e.target.closest('button[data-act]');
        if (b) this.connAction(b.dataset.act, b.dataset.kind, b.dataset.name);
      });
      $('keyShow').addEventListener('click', () => {
        const box = $('keyBox'), hidden = box.dataset.shown !== '1';
        box.textContent = hidden ? (this.key || 'not available') : '••••••••••••';
        box.dataset.shown = hidden ? '1' : '0'; $('keyShow').textContent = hidden ? 'Hide' : 'Show';
      });
      $('keyCopy').addEventListener('click', async () => {
        try { await navigator.clipboard.writeText(this.key || ''); $('keyCopy').textContent = 'Copied'; }
        catch (e) { $('keyCopy').textContent = 'Select and copy it with Show'; }
        setTimeout(() => $('keyCopy').textContent = 'Copy', 1500);
      });
      $('apiSel').addEventListener('change', () => this.pick());
      $('apiSend').addEventListener('click', () => this.send());
      $('apiBody').addEventListener('input', () => this.curl());
      $('apiParam').addEventListener('input', () => this.curl());
    },
    async load() { await Promise.all([this.loadConn(), this.loadApi()]); },
    async loadConn() {
      $('connMsg').textContent = 'checking…';
      const r = await api('/api/interfaces');
      const rows = (r.d.rows || []).map(x => ({ ...x, kind_label: x.kind.replace(/_/g, ' ') }));
      renderTable($('connTable'), ['kind_label', 'title', 'status', 'quantum', 'detail', 'active', 'test'], rows, {
        max: 90, labels: { kind_label: 'connection', title: 'implementation', quantum: 'quantum-safe', test: '' },
        cell: (col, v, row) => {
          if (col === 'status') return row.available ? '<span class="okc">● available</span>' : '<span class="badc">● unavailable</span>';
          if (col === 'quantum') return row.quantum_safe === true ? '<span class="okc">yes</span>' : row.quantum_safe === false ? '<span class="badc">NO (dev only)</span>' : '—';
          if (col === 'detail') return `<span title="${esc(row.detail)}">${esc(String(row.detail || '').slice(0, 90))}${row.ms != null ? ' · ' + esc(row.ms) + ' ms' : ''}</span>`;
          if (col === 'active') {
            if (row.active) return '<b class="okc">ACTIVE</b>';
            return ['packet_source', 'crypto_provider'].includes(row.kind)
              ? `<button class="ghost-btn" data-act="use" data-kind="${esc(row.kind)}" data-name="${esc(row.name)}">Use this</button>` : '—';
          }
          if (col === 'test') return `<button class="ghost-btn" data-act="test" data-kind="${esc(row.kind)}" data-name="${esc(row.name)}">Test</button>`;
          return undefined;
        }
      });
      $('connMsg').textContent = '';
      $('apiBase').textContent = r.d.base_url || location.origin + '/api/v1';
    },
    async connAction(act, kind, name) {
      if (act === 'test') {
        $('connMsg').textContent = 'testing ' + name + '…';
        const r = await api('/api/interfaces/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ kind, name }) });
        await this.loadConn();
        $('connMsg').textContent = (r.d.available ? '✓ ' : '✗ ') + name + ': ' + (r.d.detail || '');
      } else if (act === 'use') {
        const body = { kind, name };
        if (name === 'simulated') {
          if (!confirm('The simulated ML-KEM is NOT quantum-safe. Use it for development only. Continue?')) return;
          body.confirm_unsafe = true;
        }
        const r = await api('/api/interfaces/select', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        await this.loadConn();
        $('connMsg').textContent = r.ok ? 'Active connection changed. It applies to the next run.' : (r.d.error || (r.d.errors || []).join('; '));
      }
    },
    async loadApi() {
      const [k, s] = await Promise.all([api('/api/v1/key'), api('/api/v1/openapi.json')]);
      this.key = k.d.key || null;
      this.spec = s.d;
      this.endpoints = [];
      for (const [path, ops] of Object.entries((s.d && s.d.paths) || {}))
        for (const [method, op] of Object.entries(ops)) this.endpoints.push({ method: method.toUpperCase(), path, op });
      const order = ['/health', '/decide', '/analyze', '/jobs/{id}', '/jobs/{id}/decisions', '/config'];
      this.endpoints.sort((a, b) => order.indexOf(a.path) - order.indexOf(b.path));
      renderTable($('apiTable'), ['method', 'path', 'key', 'summary'], this.endpoints.map(e => ({ method: e.method, path: '/api/v1' + e.path, key: e.op.auth ? 'required' : 'no', summary: e.op.summary })), { max: 100 });
      $('apiSel').innerHTML = this.endpoints.map((e, i) => `<option value="${i}">${esc(e.method)} /api/v1${esc(e.path)}</option>`).join('');
      this.pick();
    },
    cur() { return this.endpoints[+$('apiSel').value]; },
    pick() {
      const e = this.cur(); if (!e) return;
      const analyze = e.path === '/analyze', needsId = e.path.includes('{id}'), isPost = e.method === 'POST';
      $('apiFile').style.display = analyze ? '' : 'none';
      $('apiParam').style.display = needsId ? '' : 'none';
      if (needsId && !$('apiParam').value && this.lastJob) $('apiParam').value = this.lastJob;
      $('apiBody').disabled = !isPost || analyze;
      $('apiBody').value = e.path === '/decide' ? JSON.stringify(e.op.example, null, 2)
        : analyze ? 'multipart form: choose a capture file above.\nmode=adaptive  encrypt=false' : '';
      this.curl();
    },
    url(e) { return location.origin + '/api/v1' + e.path.replace('{id}', encodeURIComponent($('apiParam').value || '<job_id>')); },
    curl() {
      const e = this.cur(); if (!e) return;
      let c = `export APQ_KEY=<your key>\ncurl ${e.method === 'POST' ? '-X POST ' : ''}${e.op.auth ? '-H "X-API-Key: $APQ_KEY" ' : ''}`;
      if (e.path === '/analyze') c += `-F pcap=@capture.pcapng -F mode=adaptive `;
      else if (e.method === 'POST') c += `-H "Content-Type: application/json" -d '${($('apiBody').value || '').replace(/\s+/g, ' ')}' `;
      $('curlBox').textContent = c + `"${this.url(e)}"`;
    },
    async send() {
      const e = this.cur(); if (!e) return;
      const headers = {};
      if (e.op.auth && this.key) headers['X-API-Key'] = this.key;
      let body;
      if (e.path === '/analyze') {
        const f = $('apiFile').files[0];
        if (!f) { $('apiOut').textContent = 'Choose a .pcap or .pcapng file first.'; return; }
        body = new FormData(); body.append('pcap', f); body.append('mode', 'adaptive'); body.append('encrypt', 'false');
      } else if (e.method === 'POST') { headers['Content-Type'] = 'application/json'; body = $('apiBody').value; }
      $('apiOut').textContent = 'Sending…';
      const t0 = performance.now();
      let res, text;
      try { res = await fetch(this.url(e), { method: e.method, headers, body }); text = await res.text(); }
      catch (err) { $('apiOut').textContent = 'Could not reach the server: ' + err; return; }
      let pretty = text; try { const j = JSON.parse(text); pretty = JSON.stringify(j, null, 2); if (j.job_id) { this.lastJob = j.job_id; } } catch (x) { /* csv or text */ }
      $('apiStatus').textContent = `HTTP ${res.status} · ${Math.round(performance.now() - t0)} ms`;
      $('apiStatus').className = 'mono ' + (res.ok ? 'okc' : 'badc');
      $('apiOut').textContent = pretty;
    }
  };

  /* ============ PAGE 8: SETTINGS (configuration) ============ */
  Page.settings = {
    state: null, dirty: false,
    init() {
      $('cfgSave').addEventListener('click', () => this.save());
      $('cfgDiscard').addEventListener('click', () => this.load());
      $('cfgReset').addEventListener('click', async () => {
        if (!confirm('Reset every setting to the defaults?')) return;
        const r = await api('/api/config/reset', { method: 'POST' }); this.applied(r.d.config, 'Reset to defaults.');
      });
      $('cfgImport').addEventListener('change', async e => {
        const f = e.target.files[0]; if (!f) return;
        try { await this.put(JSON.parse(await f.text()), 'Imported and saved.'); } catch (x) { this.errors(['That file is not valid JSON.']); }
        e.target.value = '';
      });
      $('presetBar').addEventListener('click', async e => {
        const b = e.target.closest('button[data-preset]'); if (!b) return;
        const r = await api('/api/config/preset/' + encodeURIComponent(b.dataset.preset), { method: 'POST' });
        if (r.ok) this.applied(r.d.config, 'Preset "' + b.dataset.preset + '" applied and saved.'); else this.errors(r.d.errors || ['could not apply preset']);
      });
      $('settingsForm').addEventListener('input', () => this.markDirty());
      $('settingsForm').addEventListener('change', e => { if (e.target.closest('.matrix')) this.refreshLabels(); this.markDirty(); });
      $('settingsForm').addEventListener('click', e => {
        const del = e.target.closest('button[data-del]'); if (del) { del.closest('.rowedit').remove(); this.markDirty(); }
        if (e.target.id === 'addPort') { this.addPortRow('', ''); this.markDirty(); }
      });
    },
    markDirty() { this.dirty = true; $('cfgState').textContent = '● unsaved changes'; $('cfgState').className = 'mono badc'; },
    async load() {
      const r = await api('/api/config');
      this.choices = r.d.choices; this.defaults = r.d.defaults;
      $('presetBar').innerHTML = '<span class="mono mutedtxt">Presets:</span>' + (r.d.presets || []).map(p =>
        `<button class="ghost-btn" data-preset="${esc(p.name)}" title="${esc(p.about)}">${esc(p.title)}</button>`).join('');
      this.applied(r.d.config, r.d.saved ? 'Showing saved settings.' : 'Showing the default settings.');
    },
    applied(cfg, msg) {
      this.state = cfg; this.build(cfg); this.dirty = false;
      $('cfgErrors').innerHTML = msg ? `<div class="okbox">${esc(msg)}</div>` : '';
      $('cfgState').textContent = ''; 
    },
    errors(list) { $('cfgErrors').innerHTML = '<div class="errbox"><b>Not saved. Please fix:</b><br>' + list.map(e => '• ' + esc(e)).join('<br>') + '</div>'; },
    field(path, label, val, o) {
      o = o || {};
      if (o.type === 'bool') return `<div class="field chk"><input type="checkbox" data-path="${path}" data-type="bool" ${val ? 'checked' : ''}><label>${esc(label)}</label></div>`;
      if (o.type === 'select') return `<div class="field"><label>${esc(label)}</label><select class="inp" data-path="${path}" data-type="text">${o.options.map(x => `<option ${x === val ? 'selected' : ''}>${esc(x)}</option>`).join('')}</select></div>`;
      if (o.type === 'area') return `<div class="field" style="grid-column:1/-1"><label>${esc(label)}</label><textarea class="inp" rows="3" data-path="${path}" data-type="text">${esc(val)}</textarea><span class="hint">${esc(o.hint || '')}</span></div>`;
      return `<div class="field"><label>${esc(label)}</label><input class="inp" data-path="${path}" data-type="num" value="${esc(val)}" inputmode="decimal"><span class="hint">${esc(o.hint || '')}</span></div>`;
    },
    panel(title, hint, inner) { return `<div class="panel"><div class="label">${esc(title)}</div>${hint ? `<div class="sub" style="margin:-6px 0 12px">${hint}</div>` : ''}${inner}</div>`; },
    build(c) {
      const f = (p, l, v, o) => this.field(p, l, v, o);
      let h = '';
      h += this.panel('Computer condition (resources)', 'When CPU or memory is at or above these limits, the computer counts as <b>CONSTRAINED</b> (busy).',
        `<div class="fgrid">${f('resources.cpu_limit', 'CPU limit (%)', c.resources.cpu_limit, { hint: '5 to 100' })}${f('resources.memory_limit', 'Memory limit (%)', c.resources.memory_limit, { hint: '5 to 100' })}${f('resources.samples', 'Readings to average', c.resources.samples, { hint: '1 to 20, about 0.2 s each' })}</div>`);
      const s = c.scoring;
      h += this.panel('Sensitivity scoring', 'Final score = MAX(rule score, AI score). At or above the HIGH limit → HIGH; at or above the MEDIUM limit → MEDIUM.',
        `<div class="fgrid">${f('scoring.high_threshold', 'HIGH limit', s.high_threshold, { hint: '0 to 1' })}${f('scoring.medium_threshold', 'MEDIUM limit', s.medium_threshold, { hint: 'must be lower than HIGH' })}${f('scoring.flow_first_n', 'Packets used per conversation', s.flow_first_n, { hint: 'highest score in the first N packets decides' })}
        ${f('scoring.use_peek', 'Peek at plain-text clues (website name, DNS type, login, SSH)', s.use_peek, { type: 'bool' })}${f('scoring.raise_when_uncertain', 'If the AI is unsure, raise protection', s.raise_when_uncertain, { type: 'bool' })}
        ${f('scoring.uncertain_confidence', 'AI "unsure" below confidence', s.uncertain_confidence, { hint: '0 to 1' })}${f('scoring.uncertain_floor', 'Score used when unsure', s.uncertain_floor, { hint: '0 to 1' })}
        ${f('scoring.risk_tier_scores.HIGH', 'AI says HIGH → score', s.risk_tier_scores.HIGH)}${f('scoring.risk_tier_scores.MEDIUM', 'AI says MEDIUM → score', s.risk_tier_scores.MEDIUM)}${f('scoring.risk_tier_scores.LOW', 'AI says LOW → score', s.risk_tier_scores.LOW)}
        ${f('scoring.sensitive_words', 'Sensitive website-name words', (s.sensitive_words || []).join(', '), { type: 'area', hint: 'comma separated; a website name containing one of these scores 1.0' })}</div>`);
      h += this.panel('Port scores', 'Our design values (informed by NIST FIPS 199 and SP 800-60, not defined by them). Higher = more sensitive.',
        `<div id="portRows"></div><button class="ghost-btn" id="addPort" type="button">+ Add port</button>`);
      h += this.panel('Protocol scores', 'Used when the port has no score.',
        `<div class="fgrid">${Object.keys(s.protocol_scores).map(p => f('scoring.protocol_scores.' + p, p, s.protocol_scores[p])).join('')}</div>`);
      const m = c.policy.matrix, ch = this.choices;
      let mt = '<table class="matrix"><thead><tr><th>Sensitivity</th><th>Computer free (AVAILABLE)</th><th>Computer busy (CONSTRAINED)</th></tr></thead><tbody>';
      for (const sens of ['HIGH', 'MEDIUM', 'LOW']) {
        mt += `<tr><td><span class="tier-badge tier-${sens}">${sens}</span></td>`;
        for (const res of ['AVAILABLE', 'CONSTRAINED']) {
          const cell = m[sens][res], base = `policy.matrix.${sens}.${res}`;
          mt += `<td><select class="inp" data-path="${base}.kex" data-type="text">${ch.kex.map(x => `<option ${x === cell.kex ? 'selected' : ''}>${x}</option>`).join('')}</select>
            <select class="inp" data-path="${base}.cipher" data-type="text">${ch.cipher.map(x => `<option ${x === cell.cipher ? 'selected' : ''}>${x}</option>`).join('')}</select><div class="lab" data-lab="${sens}.${res}"></div></td>`;
        }
        mt += '</tr>';
      }
      h += this.panel('Decision table: what protection each level gets', 'Key exchange: X25519 = normal, HYBRID_768 / HYBRID_1024 = X25519 + ML-KEM (quantum-safe). Locks: only AES-GCM and ChaCha20-Poly1305 (they detect tampering).',
        mt + '</tbody></table>' + this.field('policy.allow_unsafe', 'Allow unsafe settings (lets HIGH use a non-quantum-safe key exchange, for experiments only)', c.policy.allow_unsafe, { type: 'bool' }) +
        '<div class="warnbox">By default HIGH must stay quantum-safe. Tick "Allow unsafe" only to show the panel what happens without it.</div>');
      const cp = c.capture;
      h += this.panel('Capture (traffic generator)', 'Applied by the Mininet capture when packet_capture.py reads these settings (see the guide). A capture file ignores them.',
        `<div class="fgrid">${Object.keys(cp).map(k => f('capture.' + k, k.replace(/_/g, ' '), cp[k])).join('')}</div>`);
      h += this.panel('Comparison', '', `<div class="fgrid">${f('benchmark.runs', 'Runs per mode (default for the Compare page)', c.benchmark.runs, { hint: '1 to 20' })}</div>`);
      $('settingsForm').innerHTML = h;
      Object.entries(s.port_scores).sort((a, b) => +a[0] - +b[0]).forEach(([p, sc]) => this.addPortRow(p, sc));
      this.refreshLabels();
    },
    addPortRow(p, sc) {
      const d = document.createElement('div'); d.className = 'rowedit';
      d.innerHTML = `<input class="inp" data-port="1" placeholder="port" value="${esc(p)}"><input class="inp" data-portscore="1" placeholder="score 0-1" value="${esc(sc)}"><button class="ghost-btn" type="button" data-del="1">✕</button>`;
      $('portRows').appendChild(d);
    },
    refreshLabels() {
      document.querySelectorAll('[data-lab]').forEach(el => {
        const [s, r] = el.dataset.lab.split('.');
        const kex = document.querySelector(`[data-path="policy.matrix.${s}.${r}.kex"]`).value, ci = document.querySelector(`[data-path="policy.matrix.${s}.${r}.cipher"]`).value;
        el.textContent = (kex === 'HYBRID_1024' ? 'X25519+ML-KEM-1024' : kex === 'HYBRID_768' ? 'X25519+ML-KEM-768' : 'X25519') + ' / ' + ci;
      });
    },
    collect() {
      const cfg = JSON.parse(JSON.stringify(this.state));
      document.querySelectorAll('#settingsForm [data-path]').forEach(el => {
        const parts = el.dataset.path.split('.'); let o = cfg;
        for (let i = 0; i < parts.length - 1; i++) { o[parts[i]] = o[parts[i]] || {}; o = o[parts[i]]; }
        const last = parts[parts.length - 1];
        o[last] = el.dataset.type === 'bool' ? el.checked : el.value;
      });
      const ports = {};
      document.querySelectorAll('#portRows .rowedit').forEach(r => {
        const p = r.querySelector('[data-port]').value.trim(), sc = r.querySelector('[data-portscore]').value.trim();
        if (p !== '' || sc !== '') ports[p] = sc;
      });
      cfg.scoring.port_scores = ports;
      return cfg;
    },
    async put(cfg, okMsg) {
      const r = await api('/api/config', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ config: cfg }) });
      if (r.ok) this.applied(r.d.config, okMsg || 'Saved. The next run uses these settings.');
      else this.errors(r.d.errors || ['could not save']);
      return r.ok;
    },
    async save() { await this.put(this.collect()); }
  };

  /* The policy-mode select only matters on the Debug page. Everywhere else the pipeline runs the adaptive policy,
     and the Comparison page has its own buttons, so the pipeline options are hidden there. */
  function tidyControls() {
    const mode = $('modeSel');
    if (page !== 'debug') { mode.value = 'adaptive'; mode.style.display = 'none'; try { localStorage.removeItem('apq_modeSel'); } catch (e) { /* ignore */ } }
    if (page === 'compare') { const o = document.querySelector('.opts'); if (o) o.style.display = 'none'; }
  }

  /* remember the Start options (mode, simulated load, reuse capture) across pages */
  function persistControls() {
    const ids = ['modeSel', 'loadSel', 'reuseChk'];
    try {
      ids.forEach(id => {
        const el = $(id), saved = localStorage.getItem('apq_' + id);
        if (saved !== null) { if (el.type === 'checkbox') el.checked = saved === '1'; else el.value = saved; }
        el.addEventListener('change', () => localStorage.setItem('apq_' + id, el.type === 'checkbox' ? (el.checked ? '1' : '0') : el.value));
      });
    } catch (e) { /* storage not available */ }
  }

  /* ============ START ============ */
  persistControls();
  tidyControls();
  $('startBtn').addEventListener('click', startPipeline);
  refreshDiagnostics();
  initStatus();
  if (Page[page]) {
    if (Page[page].init) Page[page].init();
    if (Page[page].load) Page[page].load();
  }
})();
