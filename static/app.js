/* APQCrypt dashboard: stage bar and run controls, one loader per page, saved results, admin pages.
   Every value that comes from the network, from CSV files or from user input is passed through esc()
   before it is put into the page, so crafted text cannot inject HTML. */
(function () {
  'use strict';

  const $ = id => document.getElementById(id);
  const esc = s => String(s ?? '').replace(/[&<>"']/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const isNum = v => typeof v === 'number' && isFinite(v);
  const num = (v, d = 2) => (v === null || v === undefined || (typeof v === 'number' && !isFinite(v)))
    ? '–' : (typeof v === 'number' ? String(+v.toFixed(d)) : esc(v));
  const page = document.body.dataset.page;
  const csrf = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
  const Page = {};

  const MODE_LABEL = { adaptive: 'Adaptive (APQCrypt)', static_aes: 'Static AES-256', static_pqc: 'All quantum-safe' };
  const fmtTime = t => t ? new Date(t * 1000).toLocaleString() : '–';
  const fmtBytes = b => b == null ? '–' : b < 1024 ? b + ' B' : b < 1048576 ? (b / 1024).toFixed(1) + ' KB' : (b / 1048576).toFixed(1) + ' MB';

  async function api(url, opts) {
    opts = opts || {};
    const method = (opts.method || 'GET').toUpperCase();
    const headers = Object.assign({ 'X-Requested-With': 'fetch' }, opts.headers || {});
    if (method !== 'GET') headers['X-CSRF-Token'] = csrf;
    if (opts.json !== undefined) { headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(opts.json); }
    try {
      const r = await fetch(url, { method, headers, body: opts.body, credentials: 'same-origin' });
      if (r.status === 401) { window.location = '/login'; return { ok: false, status: 401, d: {} }; }
      let d = {};
      try { d = await r.json(); } catch (e) { /* not json */ }
      return { ok: r.ok, status: r.status, d };
    } catch (e) {
      return { ok: false, status: 0, d: { message: 'The server could not be reached.' } };
    }
  }

  function toast(msg, isError) {
    const host = $('toastHost');
    if (!host) return;
    const t = document.createElement('div');
    t.className = 'toast' + (isError ? ' error' : '');
    t.setAttribute('role', isError ? 'alert' : 'status');
    t.textContent = msg;
    host.appendChild(t);
    setTimeout(() => t.remove(), 4200);
  }

  /* Small dialogs that replace the browser's prompt() and confirm() */
  function askDialog({ title, label, value, confirm, password, danger, text }) {
    return new Promise(resolve => {
      const d = document.createElement('dialog');
      d.innerHTML = `<form method="dialog"><h3>${esc(title)}</h3>
        ${text ? `<p class="page-sub" style="margin:-6px 0 14px">${esc(text)}</p>` : ''}
        ${label ? `<div class="field"><label for="dlgInput">${esc(label)}</label>
        <input class="ctl" id="dlgInput" ${password ? 'type="password" minlength="8"' : ''} maxlength="80" autocomplete="off" required></div>` : ''}
        <div class="dlg-actions"><button class="btn ghost" type="button" data-x="cancel">Cancel</button>
        <button class="btn ${danger ? 'danger' : 'navy'}" type="submit">${esc(confirm || 'OK')}</button></div></form>`;
      document.body.appendChild(d);
      const input = d.querySelector('input');
      if (input && value) input.value = value;
      const done = v => { d.close(); d.remove(); resolve(v); };
      d.querySelector('[data-x]').addEventListener('click', () => done(null));
      d.addEventListener('cancel', e => { e.preventDefault(); done(null); });
      d.querySelector('form').addEventListener('submit', e => { e.preventDefault(); done(input ? input.value : true); });
      d.showModal();
      if (input) input.focus();
    });
  }

  /* ============ STAGE BAR + RUN CONTROLS (pipeline pages) ============ */
  const STAGES = ['capture', 'sensitivity', 'resources', 'encryption', 'compare'];
  // backend stage name -> stage bar position
  const BACKEND_TO_STAGE = { capture: 'capture', features: 'capture', sensitivity: 'sensitivity', policy: 'resources', encryption: 'encryption' };
  let pollTimer = null, wasRunning = false, lastStageKey = 'capture';

  function backendKey(stage) {
    const s = (stage || '').toLowerCase();
    if (!s) return null;
    if (s.includes('error')) return 'error';
    if (s.includes('start') || s.includes('capture')) return 'capture';
    if (s.includes('feature')) return 'features';
    if (s.includes('sensitiv')) return 'sensitivity';
    if (s.includes('policy')) return 'policy';
    if (s.includes('encrypt')) return 'encryption';
    if (s.includes('finish')) return 'finished';
    return null;
  }

  function setStep(key, cls, text) {
    const el = $('step-' + key), st = $('state-' + key), node = $('node-' + key);
    if (!el) return;
    el.classList.remove('done', 'active', 'error');
    if (cls) el.classList.add(cls);
    if (st) st.textContent = text;
    if (node) node.textContent = cls === 'done' ? '✓' : cls === 'error' ? '!' : String(STAGES.indexOf(key) + 1);
  }

  function cleanMsg(m) {
    // keep only the first sentence of backend messages: no file paths, no dictionaries
    return String(m || '').split(' | ')[0].replace(/^[✓⚠\s]+/, '').trim();
  }

  function paintStages(s) {
    const st = s.status || {};
    const bk = backendKey(st.stage);
    const running = s.pipeline_running;
    const benchRunning = s.bench && s.bench.running;
    let pos = -1, failed = false;

    if (running && bk && bk !== 'finished' && bk !== 'error') { pos = STAGES.indexOf(BACKEND_TO_STAGE[bk]); lastStageKey = BACKEND_TO_STAGE[bk]; }
    else if (bk === 'error') { failed = true; pos = STAGES.indexOf(lastStageKey); }
    else if (bk === 'finished' || s.has_results) pos = 4;   // all four pipeline stages complete

    STAGES.slice(0, 4).forEach((k, i) => {
      if (failed && i === pos) setStep(k, 'error', 'Failed');
      else if (running && i === pos) setStep(k, 'active', 'Running');
      else if (i < pos || (!running && !failed && pos === 4)) setStep(k, 'done', 'Done');
      else setStep(k, null, 'Waiting');
    });
    if (benchRunning) setStep('compare', 'active', 'Running');
    else if (s.has_benchmark) setStep('compare', 'done', 'Done');
    else setStep('compare', null, 'Waiting');
  }

  function paintRun(s) {
    const st = s.status || {};
    const bk = backendKey(st.stage);
    const line = $('statusLine'), fill = $('progressFill');
    const busy = s.pipeline_running || (s.bench && s.bench.running);
    $('startBtn').disabled = busy;
    $('startBtn').textContent = s.pipeline_running ? 'Running…' : 'Start pipeline';
    if ($('benchBtn')) $('benchBtn').disabled = busy;
    $('saveBtn').disabled = busy || !s.has_results;
    if (!line) return;

    if (s.pipeline_running && bk && bk !== 'finished' && bk !== 'error') {
      line.className = 'run-msg';
      line.textContent = cleanMsg(st.message) || 'Running…';
      fill.style.width = (st.progress || 0) + '%'; fill.style.background = '';
    } else if (bk === 'error') {
      line.className = 'run-msg error';
      line.textContent = cleanMsg(st.message) || 'The last run failed.';
      fill.style.width = '0%';
    } else if (bk === 'finished') {
      line.className = 'run-msg done';
      line.textContent = cleanMsg(st.message) || 'The last run finished.';
      fill.style.width = '100%'; fill.style.background = 'var(--low)';
    } else if (s.bench && s.bench.running) {
      line.className = 'run-msg'; line.textContent = s.bench.message || 'Comparison running…'; fill.style.width = '0%';
    }
  }

  async function pollState() {
    const r = await api('/api/state');
    if (!r.ok) return schedule(false);
    const s = r.d;
    paintStages(s);
    paintRun(s);
    const running = s.pipeline_running || (s.bench && s.bench.running);
    if (wasRunning && !running && Page[page] && Page[page].load) Page[page].load();   // a run just ended: refresh numbers
    wasRunning = running;
    schedule(running);
  }

  function schedule(running) {
    clearTimeout(pollTimer);
    pollTimer = setTimeout(pollState, running ? 1200 : 4000);
  }

  async function startPipeline() {
    const b = $('startBtn');
    b.disabled = true; b.textContent = 'Starting…';
    const q = new URLSearchParams({ mode: $('modeSel').value });
    if ($('reuseChk').checked) q.set('replay', '1');
    const r = await api('/start-pipeline?' + q.toString(), { method: 'POST' });
    if (!r.ok) {
      const line = $('statusLine');
      line.className = 'run-msg error';
      line.textContent = r.d.message || r.d.error || 'The pipeline could not start.';
      b.disabled = false; b.textContent = 'Start pipeline';
      return;
    }
    wasRunning = true;
    pollState();
  }

  function initRunBar() {
    $('startBtn').addEventListener('click', startPipeline);
    const dlg = $('saveDlg');
    $('saveBtn').addEventListener('click', () => {
      $('saveName').value = '';
      dlg.showModal(); $('saveName').focus();
    });
    $('saveCancel').addEventListener('click', () => dlg.close());
    $('saveForm').addEventListener('submit', async e => {
      e.preventDefault();
      $('saveConfirm').disabled = true;
      const r = await api('/api/runs', { method: 'POST', json: { name: $('saveName').value } });
      $('saveConfirm').disabled = false;
      dlg.close();
      toast(r.ok ? 'Result saved. Find it under Saved results.' : (r.d.message || 'Could not save the result.'), !r.ok);
    });
    pollState();
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
  const MONO_COLS = ['First_Bytes_Hex', 'Flow_ID', 'Flow_Key', 'flow'];

  function renderBars(id, obj, classMap, total) {
    const c = $(id);
    if (!c) return;
    if (!obj || Object.keys(obj).length === 0) { c.innerHTML = '<div class="empty-note">No data available.</div>'; return; }
    const t = total || Object.values(obj).reduce((a, b) => a + b, 0) || 1;
    let html = '';
    for (const [key, count] of Object.entries(obj)) {
      const pct = Math.round((count / t) * 100);
      html += `<div class="bar-row"><div class="bar-head"><span>${esc(key)}</span><b>${esc(count)} (${pct}%)</b></div>
        <div class="bar-track"><div class="bar-fill ${(classMap && classMap[key]) || 'fill-other'}" style="width:${pct}%"></div></div></div>`;
    }
    c.innerHTML = html;
  }

  function renderTimings(timings, names, withTotal) {
    const c = $('timingList');
    if (!c) return;
    if (!timings) { c.innerHTML = '<div class="empty-note">No timing data yet.</div>'; return; }
    let html = '';
    for (const n of names) if (timings[n] != null) html += `<div class="timing-row"><span class="t-name">${esc(n)}</span><span class="t-val">${esc(timings[n])} s</span></div>`;
    if (withTotal && timings['Total Execution'] != null)
      html += `<div class="timing-row total"><span class="t-name">Total</span><span class="t-val">${esc(timings['Total Execution'])} s</span></div>`;
    c.innerHTML = html || '<div class="empty-note">No timing data yet.</div>';
  }

  /* opts: labels{col:label}, badges[cols], max (truncate chars), cell(col,val,row)->html|undefined, empty (text) */
  function renderTable(el, columns, rows, opts) {
    opts = opts || {};
    if (!el) return;
    if (!columns || !columns.length || !rows || !rows.length) {
      el.innerHTML = `<tbody><tr><td class="empty-note" style="padding:16px">${esc(opts.empty || 'No data yet. Run the pipeline first.')}</td></tr></tbody>`;
      return;
    }
    const max = opts.max || 40;
    const head = '<thead><tr>' + columns.map(c => `<th>${esc(opts.labels && c in opts.labels ? opts.labels[c] : c)}</th>`).join('') + '</tr></thead>';
    const body = '<tbody>' + rows.map(row => '<tr>' + columns.map(col => {
      const v = row[col];
      const mono = MONO_COLS.includes(col) ? ' class="data"' : '';
      if (opts.cell) { const custom = opts.cell(col, v, row); if (custom !== undefined) return `<td>${custom}</td>`; }
      if (v === null || v === undefined || v === '') return '<td>–</td>';
      if ((opts.badges || []).includes(col) && ['LOW', 'MEDIUM', 'HIGH'].includes(v))
        return `<td><span class="tier-badge tier-${v}">${v}</span></td>`;
      if (isNum(v)) return `<td>${esc(+v.toFixed(3))}</td>`;
      const s = String(v);
      if (s.length > max) return `<td class="trunc${mono ? ' data' : ''}" title="${esc(s)}">${esc(s.slice(0, max))}…</td>`;
      return `<td${mono}>${esc(s)}</td>`;
    }).join('') + '</tr>').join('') + '</tbody>';
    el.innerHTML = head + body;
  }

  const tierBadges = obj => ['HIGH', 'MEDIUM', 'LOW'].filter(k => obj && obj[k] != null)
    .map(k => `<span class="tier-badge tier-${k}">${k} ${esc(obj[k])}</span>`).join(' ') || '–';

  /* ============ STAGE 1: CAPTURE ============ */
  Page.capture = {
    async load() {
      const { d } = await api('/results');
      if (!d.total_packets) { renderTable($('featTable'), [], []); return; }
      $('totalPackets').innerHTML = esc(d.total_packets) + '<span class="unit">packets</span>';
      const sz = /\((\d+) bytes\)/.exec(d.packet_file || '');
      $('captureFile').textContent = 'traffic.pcapng' + (sz ? ', ' + fmtBytes(+sz[1]) : '');
      $('flowCount').textContent = d.flows ?? '–';
      $('payloadCount').textContent = d.packets_with_payload ?? '–';
      renderBars('protocolBars', d.protocols, PROTO_CLASS, d.total_packets);
      renderTimings(d.module_timings, ['Packet Capture', 'Feature Extraction'], false);
      const v = await api('/view/features');
      if (v.d.error) { renderTable($('featTable'), [], []); return; }
      renderTable($('featTable'), v.d.columns, v.d.data, { max: 34 });
      $('tableRowCount').textContent = `Showing ${(v.d.data || []).length} of ${v.d.total_rows} rows`;
    }
  };

  /* ============ STAGE 2: SENSITIVITY ============ */
  Page.sensitivity = {
    async load() {
      const { d } = await api('/results');
      renderBars('sensitivityBars', d.sensitivity, TIER_CLASS, d.total_packets);
      renderBars('riskBars', d.risk_tiers, TIER_CLASS, d.total_packets);
      $('dpiFound').textContent = d.dpi_found ?? '–';
      renderTimings(d.module_timings, ['Sensitivity Analysis'], false);
      const v = await api('/view/results');
      if (v.d.error) { renderTable($('scoreTable'), [], []); return; }
      const want = ['Pkt_Index', 'Protocol', 'Dest_Port', 'Confidentiality_Score', 'DPI_Signal', 'Risk_Tier',
        'Risk_Confidence', 'Packet_Score', 'Final_Score', 'Sensitivity', 'Reason'];
      const cols = want.filter(c => (v.d.columns || []).includes(c));
      renderTable($('scoreTable'), cols.length ? cols : v.d.columns, v.d.data, {
        badges: ['Sensitivity', 'Risk_Tier'], max: 70,
        labels: { Pkt_Index: 'Packet', Dest_Port: 'Port', Confidentiality_Score: 'Confidentiality', DPI_Signal: 'Payload signal',
          Risk_Tier: 'Risk', Risk_Confidence: 'Risk confidence', Packet_Score: 'Packet score', Final_Score: 'Final score' }
      });
      $('tableRowCount').textContent = `Showing ${(v.d.data || []).length} of ${v.d.total_rows} rows`;
    }
  };

  /* ============ STAGE 3: SYSTEM CONDITION ============ */
  Page.resources = {
    chart: null, timer: null, hist: { cpu: [], mem: [], t: [] }, limits: { cpu: 50, mem: 70 }, state: null,
    async load() {
      const m = await api('/policy-matrix');
      if (m.d.rows) { this.limits = { cpu: m.d.cpu_limit, mem: m.d.mem_limit }; this.renderMatrix(m.d.rows); }
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
        if (!x) return '<td>–</td>';
        const pq = x.pqc_handshake ? '<span class="pq-yes">Quantum-safe</span>' : '<span class="pq-no">Classical</span>';
        return `<td data-res="${r}">${esc(x.algorithm)}<br>${pq}</td>`;
      };
      let html = '<thead><tr><th>Sensitivity</th><th>Available</th><th>Constrained</th></tr></thead><tbody>';
      for (const s of ['HIGH', 'MEDIUM', 'LOW'])
        html += `<tr><td><span class="tier-badge tier-${s}">${s}</span></td>${cell(s, 'AVAILABLE')}${cell(s, 'CONSTRAINED')}</tr>`;
      $('matrixTable').innerHTML = html + '</tbody>';
      this.markNow();
    },
    markNow() {
      document.querySelectorAll('#matrixTable td[data-res]').forEach(td => td.classList.toggle('now', td.dataset.res === this.state));
    },
    renderLast(d) {
      const c = $('lastDecision');
      const r = d.resource_status;
      if (!r) { c.innerHTML = '<div class="empty-note">No run yet.</div>'; return; }
      const label = r.status === 'CONSTRAINED' ? 'Constrained' : 'Available';
      const cls = r.status === 'CONSTRAINED' ? 'badc' : 'okc';
      const reading = (r.cpu_percent == null && r.memory_percent == null)
        ? 'Simulated by the super admin' : `CPU ${num(r.cpu_percent, 1)}%, memory ${num(r.memory_percent, 1)}%`;
      c.innerHTML = `<div style="font-size:22px;font-weight:700" class="${cls}">${label}</div>
        <div class="mutedtxt" style="margin-top:4px">${reading}</div>
        <div class="sub">The decision table was applied with this condition.</div>`;
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
      $('limitNote').textContent = `Limits: CPU ${d.cpu_limit}%, memory ${d.memory_limit}%. At or above either limit the system is Constrained.`;
      this.state = d.status;
      const chip = $('stateChip');
      chip.textContent = d.status === 'CONSTRAINED' ? 'Constrained' : 'Available';
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
              { label: 'CPU %', data: h.cpu, borderColor: '#292F6E', backgroundColor: '#292F6E', tension: .3, pointRadius: 0, borderWidth: 2.5 },
              { label: 'Memory %', data: h.mem, borderColor: '#EEAC19', backgroundColor: '#EEAC19', tension: .3, pointRadius: 0, borderWidth: 2.5 },
              { label: 'CPU limit', data: limCpu, borderColor: '#8E93C9', borderDash: [6, 4], pointRadius: 0, borderWidth: 1.5 },
              { label: 'Memory limit', data: limMem, borderColor: '#C99A2E', borderDash: [6, 4], pointRadius: 0, borderWidth: 1.5 }]
          },
          options: {
            responsive: true, maintainAspectRatio: false, animation: false,
            plugins: { legend: { labels: { color: '#565C7A', font: { size: 12 }, boxWidth: 18 } } },
            scales: { y: { min: 0, max: 100, ticks: { color: '#565C7A' }, grid: { color: '#E6E8F2' } },
              x: { ticks: { color: '#565C7A', maxTicksLimit: 6 }, grid: { display: false } } }
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

  /* ============ STAGE 4: ENCRYPTION ============ */
  function renderEncryptionSummary(s, checks) {
    const c = $('encryptionSummary');
    if (!s || !s.total_packets) { c.innerHTML = '<div class="empty-note">Run the pipeline first.</div>'; return; }
    const k = (checks && checks.checks) || {};
    c.innerHTML = `<div class="timing-list">
      <div class="timing-row"><span class="t-name">Packets</span><span class="t-val">${esc(s.total_packets)}</span></div>
      <div class="timing-row"><span class="t-name">Flows</span><span class="t-val">${esc(s.total_flows)}</span></div>
      <div class="timing-row"><span class="t-name">Hybrid quantum-safe key exchanges</span><span class="t-val">${esc(s.pqc_handshakes)}</span></div>
      <div class="timing-row"><span class="t-name">Key exchange time</span><span class="t-val">${esc(s.total_handshake_ms)} ms</span></div>
      <div class="timing-row"><span class="t-name">Encryption time</span><span class="t-val">${esc(s.total_encrypt_ms)} ms</span></div>
      <div class="timing-row"><span class="t-name">Ciphertext</span><span class="t-val">${esc(Number(s.total_ciphertext_bytes).toLocaleString())} bytes</span></div>
      <div class="timing-row total"><span class="t-name">Self-checks</span>
        <span class="t-val okc">${esc(k.roundtrip_ok ?? '–')} decrypted, ${esc(k.tamper_detected ?? '–')} tampering caught${k.tamper_missed ? ', <span class="badc">' + esc(k.tamper_missed) + ' missed</span>' : ''}</span></div></div>`;
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
        $('highCovNote').textContent = `${pq.length} of ${high.length} HIGH flows` + (pct < 100 ? ' (expected in the static AES-256 mode)' : '');
      } else { $('highCov').textContent = '–'; $('highCovNote').textContent = 'No HIGH flows in this run'; }
      $('flowCountTxt').textContent = rows.length ? rows.length + ' flows' : '';
      renderTable($('flowTable'),
        ['flow', 'protocol', 'packets', 'peek', 'sensitivity', 'score', 'key_exchange', 'cipher', 'handshake_ms', 'reason'], rows, {
          badges: ['sensitivity'], max: 46,
          labels: { flow: 'Flow', protocol: 'Protocol', packets: 'Packets', peek: 'Payload signal', sensitivity: 'Sensitivity', score: 'Score',
            key_exchange: 'Key exchange', cipher: 'Cipher', handshake_ms: 'Key exchange (ms)', reason: 'Reason' },
          cell: (col, v) => {
            if (col === 'key_exchange') return `<span class="${/ML-KEM|Kyber/.test(v || '') ? 'pq-yes' : 'pq-no'}">${esc(v)}</span>`;
            return undefined;
          }
        });
    }
  };

  /* ============ STAGE 5: COMPARISON ENGINE ============ */
  const IS_ADMIN = document.body.dataset.role === 'super_admin';
  const SERIES_COLOR = { static_aes: '#8E93AE', static_pqc: '#292F6E', 'adaptive:free': '#EEAC19', 'adaptive:busy': '#B97F00' };
  const SERIES_ORDER = ['static_aes', 'static_pqc', 'adaptive:free', 'adaptive:busy'];
  const MODE_COLOR = { static_aes: '#8E93AE', static_pqc: '#292F6E', adaptive: '#EEAC19' };
  const MODE_INK = { static_aes: '#fff', static_pqc: '#fff', adaptive: '#1B2050' };
  const AX = { ticks: { color: '#565C7A' }, grid: { color: '#E6E8F2' } };
  const SERIES_SHORT = { static_aes: 'A. Normal', static_pqc: 'B. All quantum-safe', 'adaptive:free': 'C. Adaptive (free)', 'adaptive:busy': 'C. Adaptive (busy)' };
  const LEG = { labels: { color: '#565C7A', font: { size: 11 } } };

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
      if ($('clearAll')) $('clearAll').addEventListener('click', async () => {
        const ok = await askDialog({ title: 'Delete all stored runs?', text: 'Every stored run, for every machine and capture, is removed. This cannot be undone.', confirm: 'Delete all', danger: true });
        if (!ok) return;
        await api('/api/comparison/clear', { method: 'POST', json: { all: true } });
        this.load();
      });
      $('modeCards').addEventListener('click', async e => {
        const run = e.target.closest('button[data-run]'), clr = e.target.closest('button[data-clear]');
        if (run) this.run([run.dataset.run]);
        if (clr) {
          const ok = await askDialog({ title: 'Clear this mode?', text: 'The stored runs of this mode (on this machine and capture) are removed.', confirm: 'Clear', danger: true });
          if (!ok) return;
          await api('/api/comparison/clear', { method: 'POST', json: { mode: clr.dataset.clear } });
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
      if (!r.ok) { $('runProgress').innerHTML = `<div class="errbox">${esc((r.d && (r.d.message || r.d.error)) || 'The comparison data could not be loaded.')}</div>`; return; }
      this.data = r.d;
      this.render();
      if (r.d.state && r.d.state.running) this.watch();
    },
    async run(modes) {
      const body = { modes, runs: +$('runsSel').value, interleave: $('interleave').checked };
      const cond = document.getElementById('condSel');
      if (cond && cond.value) body.force = cond.value;
      $('runProgress').innerHTML = '<div class="empty-note">Starting…</div>';
      const r = await api('/api/comparison/run', { method: 'POST', json: body });
      if (!r.ok) { $('runProgress').innerHTML = `<div class="errbox">${esc(r.d.message || 'could not start')}</div>`; return; }
      this.view = { host: null, sha: null };
      this.lastDone = -1;
      wasRunning = true;
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
    render() { this.setup(); this.cards(); this.progress(); this.findings(); this.charts(); this.applied(); this.numbers(); this.micro(); this.evidence(); },

    setup() {
      const d = this.data, h = d.host, c = d.capture, v = d.viewing;
      const anySeries = Object.values(d.series)[0];
      const card = (t, rows) => `<div class="setup-card"><div class="t">${esc(t)}</div><div class="v">${rows.filter(Boolean).map(x => esc(x)).join('<br>')}</div></div>`;
      $('setupGrid').innerHTML =
        card('Machine', [h.board || h.cpu, `${h.machine} · ${h.cores} cores · ${h.ram_gb ?? '?'} GB RAM`, h.os || '', 'Python ' + h.python, h.isa ? 'ISA: ' + h.isa : '']) +
        card('Capture used', c ? [`${c.path}`, `fingerprint ${c.sha8} · ${(c.size / 1024).toFixed(1)} KB`,
          anySeries ? `${anySeries.packets} packets · ${anySeries.conversations} conversations` : 'Packet counts appear after the first run'] : ['No capture yet', 'Run the pipeline first']) +
        card('Cryptography', [`ML-KEM provider: ${d.provider}`, `liboqs: ${h.liboqs || 'not installed'}`, `cryptography: ${h.cryptography || '?'}`]) +
        card('What is compared', ['Same capture for every mode', 'Fresh process per run', 'First run per mode is a warm-up (not counted)', 'Adaptive uses the current policy settings']);
      let notes = '';
      if (d.provider !== 'liboqs') notes += '<div class="errbox">The ML-KEM provider is <b>simulated</b>. Quantum-safe modes cannot be measured until real liboqs is selected on the Interface page.</div>';
      else if (!h.liboqs) notes += '<div class="warnbox">liboqs is not installed. Modes B and C will refuse to run.</div>';
      if (!v.is_this_machine) notes += '<div class="warnbox">You are viewing results measured on <b>another machine</b>. Measuring here creates a separate set.</div>';
      else if (!v.is_current_capture) notes += '<div class="warnbox">You are viewing results for an <b>older capture</b>, not the current one.</div>';
      if (d.ignored_runs) notes += `<div class="sub">${esc(d.ignored_runs)} stored run(s) from another machine or capture are kept but not mixed into these results.</div>`;
      $('setupNotes').innerHTML = notes;
      const hosts = d.datasets.hosts, caps = d.datasets.captures;
      $('datasetBar').innerHTML = (hosts.length > 1 ? `<span class="hint">Machine</span><select class="ctl" id="hostSel">${hosts.map(x => `<option value="${esc(x.id)}" ${x.id === v.host ? 'selected' : ''}>${esc(x.label)}</option>`).join('')}</select>` : '') +
        (caps.length > 1 ? `<span class="hint">Capture</span><select class="ctl" id="capSel">${caps.map(x => `<option value="${esc(x.sha8)}" ${x.sha8 === v.sha ? 'selected' : ''}>${esc(x.sha8)} (${(x.size / 1024).toFixed(0)} KB)</option>`).join('')}</select>` : '');
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
        else if (m.runs_counted) { status = `${m.runs_counted} run${m.runs_counted > 1 ? 's' : ''} measured, last ${new Date(m.last_run * 1000).toLocaleTimeString()}`; cls = 'ok'; }
        else { status = 'Not measured yet'; cls = 'none'; }
        const problem = m.last_problem ? `<div class="mc-status bad">Last problem: ${esc(String(m.last_problem).slice(0, 160))}</div>` : '';
        const cond = (key === 'adaptive' && IS_ADMIN) ? `<div class="row-actions" style="margin:0"><span class="hint">System condition</span>
            <select class="ctl" id="condSel"><option value="">Real (measured when the run starts)</option><option value="AVAILABLE">Simulate: available</option><option value="CONSTRAINED">Simulate: constrained</option></select></div>` : '';
        return `<div class="mode-card ${running && cur === key ? 'running' : ''}">
          <div class="mc-title"><span class="mc-letter" style="background:${MODE_COLOR[key]};color:${MODE_INK[key]}">${esc(m.letter)}</span>${esc(m.title)}</div>
          <div class="mc-about">${esc(m.about)}</div>${cond}
          <div class="mc-status ${cls}">${esc(status)}</div>${problem}
          <div class="row-actions" style="margin:0"><button class="ghost-btn" data-run="${esc(key)}" ${running ? 'disabled' : ''}>Measure ${esc(m.title)}</button>
            ${(m.runs_counted && IS_ADMIN) ? `<button class="ghost-btn" data-clear="${esc(key)}" ${running ? 'disabled' : ''}>Clear</button>` : ''}</div></div>`;
      }).join('');
      const cs = document.getElementById('condSel'); if (cs && prevCond) cs.value = prevCond;
    },

    progress() {
      const st = (this.data && this.data.state) || {};
      if (!st.total || (!st.running && !st.error && !st.last_error && st.message !== 'Finished' && st.message !== 'Cancelled')) { $('runProgress').innerHTML = ''; return; }
      const pct = st.total ? Math.round(st.done / st.total * 100) : 0;
      let h = `<div class="progress"><i style="width:${pct}%"></i></div><div class="hint" style="margin-top:6px">${esc(st.message || '')} · ${esc(st.done)}/${esc(st.total)}</div>`;
      if (st.error) h += `<div class="errbox">${esc(st.error)}</div>`;
      else if (st.last_error) h += `<div class="warnbox">${esc(st.last_error)} (this run was stored but is not counted)</div>`;
      $('runProgress').innerHTML = h;
    },

    findings() {
      const m = (this.data && this.data.messages) || [];
      $('findings').innerHTML = m.length ? m.map(x => `<li>${esc(x)}</li>`).join('') : '<li class="mutedtxt">Findings appear after at least one mode has been measured.</li>';
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
      const labels = ser.map(s => SERIES_SHORT[s.key] || s.label), colors = ser.map(s => SERIES_COLOR[s.key] || '#A9ADC4');
      const val = (s, k, f) => (s[k] ? +(s[k].mean * (f || 1)).toFixed(4) : null);
      const xs = { ticks: { color: '#565C7A', font: { size: 11 } }, grid: { display: false } };
      const base = { responsive: true, maintainAspectRatio: false, animation: { duration: 300 } };
      const bar = (id, key, f) => chartOf(id, {
        type: 'bar', data: { labels, datasets: [{ data: ser.map(s => val(s, key, f)), backgroundColor: colors, borderRadius: 6 }] },
        options: { ...base, plugins: { legend: { display: false } }, scales: { x: xs, y: { beginAtZero: true, ...AX } } }
      });
      bar('chTime', 'total_s'); bar('chCpu', 'cpu_s'); bar('chMem', 'peak_mem_mb'); bar('chHs', 'handshake_ms_total');
      const part = (s, k, f) => (s[k] ? s[k].mean * (f || 1) : 0);
      const other = s => Math.max(part(s, 'total_s') - part(s, 'parse_s') - part(s, 'decision_s') - part(s, 'handshake_ms_total', .001) - part(s, 'encrypt_ms_total', .001), 0);
      const stack = (label, color, fn) => ({ label, backgroundColor: color, data: ser.map(s => +fn(s).toFixed(4)), borderRadius: 2 });
      chartOf('chStack', {
        type: 'bar', data: {
          labels, datasets: [
            stack('Read capture', '#6B73B8', s => part(s, 'parse_s')), stack('Decision (AI model, scoring, policy)', '#EEAC19', s => part(s, 'decision_s')),
            stack('Key exchange', '#B3302A', s => part(s, 'handshake_ms_total', .001)), stack('Encrypt packets', '#1E7F4B', s => part(s, 'encrypt_ms_total', .001)),
            stack('Other (file reading and writing)', '#A9ADC4', other)]
        },
        options: { ...base, plugins: { legend: LEG }, scales: { x: { ...xs, stacked: true }, y: { stacked: true, beginAtZero: true, ...AX } } }
      });
      bar('chKb', 'handshake_bytes', 1 / 1024);
      chartOf('chSteady', {
        type: 'bar', data: {
          labels, datasets: [
            { label: 'First start (includes loading the AI model)', backgroundColor: '#EEAC19', borderRadius: 4, data: ser.map(s => val(s, 'total_s')) },
            { label: 'Service already running', backgroundColor: '#292F6E', borderRadius: 4, data: ser.map(s => val(s, 'steady_total_s')) }]
        },
        options: { ...base, plugins: { legend: LEG }, scales: { x: xs, y: { beginAtZero: true, ...AX } } }
      });
      chartOf('chPq', {
        type: 'bar', data: {
          labels, datasets: [
            { label: 'All conversations', backgroundColor: '#292F6E', borderRadius: 6, data: ser.map(s => (s.pq_flow_share ? +(s.pq_flow_share.mean * 100).toFixed(1) : null)) },
            { label: 'HIGH conversations', backgroundColor: '#EEAC19', borderRadius: 6, data: ser.map(s => (s.high_coverage ? +(s.high_coverage.mean * 100).toFixed(1) : null)) }]
        },
        options: { ...base, plugins: { legend: LEG }, scales: { x: xs, y: { beginAtZero: true, max: 100, ...AX } } }
      });
    },

    applied() {
      const ser = this.series(), box = $('appliedBox');
      if (!ser.length) { box.innerHTML = '<div class="empty-note">Nothing measured yet.</div>'; return; }
      box.innerHTML = ser.map(s => {
        const a = s.applied; if (!a) return '';
        const choices = Object.entries(a.by_choice || {}).map(([k, v]) => `<b>${esc(v)}</b> of ${esc(a.conversations)} conversations: ${esc(k)}`).join('<br>');
        return `<div class="setup-card" style="margin-bottom:10px"><div class="t">${esc(s.label)}</div><div class="v">${choices}<br>
          <b>${esc(a.packets_encrypted)}</b> of ${esc(a.packets_total)} packets carried data and were encrypted (${esc(a.payload_bytes)} bytes in, ${esc(a.ciphertext_bytes)} bytes out);
          ${esc(a.packets_without_data)} had no data to encrypt.${s.model_loader ? '<br>AI model loaded with: ' + esc(s.model_loader) : ''}</div></div>`;
      }).join('');
    },

    numbers() {
      const ser = this.series();
      if (!ser.length) { $('numTable').innerHTML = '<tbody><tr><td class="empty-note" style="padding:16px">Nothing measured yet.</td></tr></tbody>'; return; }
      const pm = (st, d, f) => (st ? ((st.mean * (f || 1)).toFixed(d) + (st.std != null ? ' ± ' + (st.std * (f || 1)).toFixed(d) : '')) : '–');
      const pct = st => (st ? Math.round(st.mean * 100) + '%' : '–');
      let h = '<thead><tr><th>Mode</th><th>Runs</th><th>Total, first start (s)</th><th>Total, service running (s)</th><th>Decision (s)</th><th>Key exchange (ms)</th><th>Key-exchange data (KB)</th><th>Encrypt (ms)</th><th>CPU (s)</th><th>Peak memory (MB)</th><th>Extra bytes</th><th>Quantum-safe conversations</th><th>HIGH protected</th></tr></thead><tbody>';
      ser.forEach(s => {
        h += `<tr><td>${esc(s.label)}</td><td>${esc(s.n)}</td><td>${pm(s.total_s, 4)}</td><td>${pm(s.steady_total_s, 4)}</td><td>${pm(s.decision_s, 4)}</td><td>${pm(s.handshake_ms_total, 2)}</td><td>${s.handshake_bytes ? (s.handshake_bytes.mean / 1024).toFixed(1) : '–'}</td><td>${pm(s.encrypt_ms_total, 2)}</td>
          <td>${pm(s.cpu_s, 4)}</td><td>${pm(s.peak_mem_mb, 0)}</td><td>${s.overhead_bytes ? Math.round(s.overhead_bytes.mean) : '–'}</td><td>${pct(s.pq_flow_share)}</td><td>${pct(s.high_coverage)}</td></tr>`;
      });
      $('numTable').innerHTML = h + '</tbody>';
    },

    micro() {
      const m = this.data.micro;
      if (!m) { $('microTable').innerHTML = '<tbody><tr><td class="empty-note" style="padding:16px">Not measured yet. Press the button to measure X25519, ML-KEM, AES-GCM, ChaCha20-Poly1305 and HKDF on this machine.</td></tr></tbody>'; return; }
      $('microMsg').textContent = 'Measured ' + new Date(m.started_at * 1000).toLocaleString();
      const t = us => (us >= 1000 ? (us / 1000).toFixed(3) + ' ms' : us.toFixed(1) + ' µs');
      let h = '<thead><tr><th>Group</th><th>Operation</th><th>Median</th><th>95% under</th><th>Note</th></tr></thead><tbody>';
      (m.rows || []).forEach(r => { h += `<tr><td>${esc(r.group)}</td><td>${esc(r.operation)}</td><td><b>${esc(t(r.median_us))}</b></td><td>${esc(t(r.p95_us))}</td><td>${esc(r.detail || '')}</td></tr>`; });
      (m.notes || []).forEach(n => { h += `<tr><td colspan="5" class="badc">${esc(n)}</td></tr>`; });
      $('microTable').innerHTML = h + '</tbody>';
    },

    evidence() {
      const ev = this.data.evidence || [];
      const rows = ev.map(r => ({
        when: new Date(r.started_at * 1000).toLocaleTimeString(), mode: r.mode + (r.condition ? ' (' + r.condition + (r.forced ? ', simulated' : '') + ')' : ''),
        type: r.warmup ? 'warm-up' : 'measured', counted: r.ok && r.valid && !r.warmup ? 'yes' : 'no', total: r.total_s, cpu: r.cpu_s, mem: r.peak_mem_mb,
        kex: r.handshake_ms_total, pq: r.pq_flow_share != null ? Math.round(r.pq_flow_share * 100) + '%' : null,
        note: r.error || r.invalid_reason || ''
      }));
      renderTable($('evTable'), ['when', 'mode', 'type', 'counted', 'total', 'cpu', 'mem', 'kex', 'pq', 'note'], rows, {
        max: 80, empty: 'No runs stored yet.',
        labels: { when: 'Time', mode: 'Mode', type: 'Type', counted: 'Counted', total: 'Total (s)', cpu: 'CPU (s)', mem: 'Peak MB', kex: 'Key exchange (ms)', pq: 'Quantum-safe', note: 'Note' }
      });
    }
  };

  /* ============ SAVED RESULTS ============ */
  Page.saved = {
    all: false,
    async load() {
      const r = await api('/api/runs');
      const rows = r.d.rows || [];
      this.all = !!r.d.all_users;
      if (this.all) $('savedSub').textContent = 'Results saved by all users. Open one to review or download its files.';
      const cols = ['name'].concat(this.all ? ['owner'] : [], ['created', 'mode', 'packets', 'sens', 'time', 'actions']);
      const flat = rows.map(m => ({
        id: m.id, name: m.name, owner: m.owner, created: fmtTime(m.created),
        mode: MODE_LABEL[(m.summary || {}).mode] || (m.summary || {}).mode || '–',
        packets: (m.summary || {}).packets, sens: (m.summary || {}).sensitivity,
        time: (m.summary || {}).total_time != null ? (m.summary.total_time + ' s') : '–'
      }));
      renderTable($('savedTable'), cols, flat, {
        empty: 'Nothing saved yet. Run the pipeline, then choose Save result.',
        labels: { name: 'Name', owner: 'Saved by', created: 'Saved on', mode: 'Policy', packets: 'Packets', sens: 'Sensitivity', time: 'Run time', actions: '' },
        cell: (col, v, row) => {
          if (col === 'name') return `<a href="/saved/${esc(row.id)}"><b>${esc(v)}</b></a>`;
          if (col === 'sens') return tierBadges(v);
          if (col === 'actions') return `<span class="row-actions" style="margin:0;flex-wrap:nowrap">
            <a class="ghost-btn" href="/saved/${esc(row.id)}">Open</a>
            <button class="ghost-btn" data-act="rename" data-id="${esc(row.id)}" data-name="${esc(row.name)}" type="button">Rename</button>
            <button class="ghost-btn" data-act="delete" data-id="${esc(row.id)}" data-name="${esc(row.name)}" type="button" style="color:var(--high)">Delete</button></span>`;
          return undefined;
        }
      });
    },
    init() {
      $('savedTable').addEventListener('click', async e => {
        const b = e.target.closest('button[data-act]');
        if (!b) return;
        if (b.dataset.act === 'rename') {
          const name = await askDialog({ title: 'Rename result', label: 'Name', value: b.dataset.name, confirm: 'Save' });
          if (!name) return;
          const r = await api('/api/runs/' + b.dataset.id, { method: 'PATCH', json: { name } });
          toast(r.ok ? 'Renamed' : (r.d.message || 'Could not rename'), !r.ok);
        } else {
          const ok = await askDialog({ title: 'Delete this result?', text: `"${b.dataset.name}" and its files will be removed. This cannot be undone.`, confirm: 'Delete', danger: true });
          if (!ok) return;
          const r = await api('/api/runs/' + b.dataset.id, { method: 'DELETE' });
          toast(r.ok ? 'Deleted' : (r.d.message || 'Could not delete'), !r.ok);
        }
        this.load();
      });
    }
  };

  const FILE_KEYS = { 'traffic.pcapng': ['packets', 'Capture (pcapng)'], 'features.csv': ['features', 'Features'], 'results.csv': ['results', 'Sensitivity results'],
    'policy.csv': ['policy', 'Policy decisions'], 'encrypted_results.csv': ['encrypted', 'Encrypted results'], 'benchmark_summary.csv': ['benchmark', 'Benchmark summary'] };

  Page.saved_run = {
    async load() {
      const id = $('runSummary').dataset.id;
      const r = await api('/api/runs');
      const m = (r.d.rows || []).find(x => x.id === id);
      if (!m) return;
      const s = m.summary || {};
      const sens = s.sensitivity || {};
      $('runSummary').innerHTML = `
        <div class="card"><div class="label">Packets</div><div class="big-number">${esc(s.packets ?? '–')}</div><div class="sub">Saved ${esc(fmtTime(m.created))}</div></div>
        <div class="card"><div class="label">Policy</div><div style="font-size:20px;font-weight:700;color:var(--navy-deep)">${esc(MODE_LABEL[s.mode] || s.mode || '–')}</div>
          <div class="sub">System condition: ${esc(s.resource_status === 'CONSTRAINED' ? 'Constrained' : s.resource_status === 'AVAILABLE' ? 'Available' : '–')}</div></div>
        <div class="card"><div class="label">Run time</div><div class="big-number">${s.total_time != null ? esc(s.total_time) : '–'}<span class="unit">s</span></div></div>
        <div class="card"><div class="label">Sensitivity (packets)</div><div id="runSens"></div></div>`;
      renderBars('runSens', sens, TIER_CLASS, null);
      const files = (m.files || []).filter(f => FILE_KEYS[f]);
      $('runFiles').innerHTML = files.map(f => `<a class="ghost-btn" href="/saved/${esc(id)}/download/${FILE_KEYS[f][0]}" download>${esc(FILE_KEYS[f][1])}</a>`).join('') || '<span class="empty-note">No files.</span>';
      const csv = files.filter(f => f.endsWith('.csv'));
      const sel = $('previewSel');
      sel.innerHTML = csv.map(f => `<option value="${FILE_KEYS[f][0]}">${esc(FILE_KEYS[f][1])}</option>`).join('');
      sel.addEventListener('change', () => this.preview(id, sel.value));
      if (csv.length) this.preview(id, sel.value);
    },
    async preview(id, key) {
      const v = await api(`/api/runs/${id}/view/${key}`);
      if (v.d.error) { renderTable($('previewTable'), [], [], { empty: 'This file cannot be previewed.' }); return; }
      renderTable($('previewTable'), v.d.columns, v.d.data, { max: 40, badges: ['Sensitivity', 'Risk_Tier'] });
      $('previewCount').textContent = `Showing ${(v.d.data || []).length} of ${v.d.total_rows} rows`;
    }
  };

  /* ============ ADMIN: DEBUG ============ */
  const checkCard = (name, ok, note) => `<div class="chk ${ok ? 'ok' : 'bad'}"><i></i><div><b>${esc(name)}</b><span>${esc(ok ? 'Available' : 'Missing')}${note ? ': ' + esc(note) : ''}</span></div></div>`;
  const kv = pairs => pairs.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join('');

  Page.debug = {
    timer: null,
    init() { $('refreshBtn').addEventListener('click', () => this.load()); },
    async load() {
      const r = await api('/api/admin/debug');
      const d = r.d;
      if (!r.ok) return;
      const c = d.checks;
      $('envChecks').innerHTML = checkCard('Passwordless sudo', c.sudo_access, 'required to run Mininet and tshark') +
        checkCard('Mininet', c.mininet_installed, 'builds the test network') + checkCard('tshark', c.tshark_installed, 'records packets') +
        checkCard('ML-KEM (liboqs)', c.liboqs_mlkem, 'post-quantum key exchange') + checkCard('Data directory', c.data_dir_exists, 'output location');
      const p = d.pipeline, st = p.status || {};
      $('pipeKv').innerHTML = kv([
        ['State', p.running ? '<span class="pill ok">Running</span>' : '<span class="pill">Idle</span>'],
        ['Started by', esc(p.run_by || '–')], ['Policy', esc(MODE_LABEL[p.mode] || p.mode || '–')],
        ['Started at', esc(fmtTime(p.started))], ['Last stage', esc(st.stage || '–')],
        ['Last message', esc(cleanMsg(st.message) || '–')], ['Progress', esc((st.progress ?? 0) + '%')]]);
      $('rawStatus').textContent = JSON.stringify(st, null, 2);
      renderTimings(p.timings, Object.keys(p.timings || {}).filter(k => k !== 'Total Execution'), true);
      const b = d.comparison;
      $('benchKv').innerHTML = kv([['State', b.running ? '<span class="pill ok">Running</span>' : '<span class="pill">Idle</span>'],
        ['Message', esc(b.message || '–')], ['Error', esc(b.error || 'None')]]);
      renderTable($('fileTable'), ['name', 'path', 'bytes', 'modified'], d.files, {
        labels: { name: 'File', path: 'Path', bytes: 'Size', modified: 'Last modified' },
        cell: (col, v) => col === 'bytes' ? esc(v == null ? 'Not created' : fmtBytes(v)) : col === 'modified' ? esc(fmtTime(v)) : col === 'path' ? `<span class="mono">${esc(v)}</span>` : undefined
      });
      renderTable($('logTable'), ['time', 'user', 'event', 'detail', 'ip'], d.log, {
        empty: 'No events yet.', max: 90, labels: { time: 'Time', user: 'User', event: 'Event', detail: 'Detail', ip: 'Address' }
      });
      this.loadStages();
      if (!this.timer) this.timer = setInterval(() => { if (!document.hidden) this.load(); }, 5000);
    },
    async loadStages() {
      const s = await api('/api/debug/stages');
      if (s.ok && $('stageTable')) {
        renderTable($('stageTable'), ['title', 'status', 'seconds', 'rows', 'size', 'output', 'detail'], (s.d.stages || []).map(x => ({
          title: x.title, status: x.status, seconds: x.seconds, rows: x.rows, size: x.size, output: x.output,
          detail: x.error_msg ? x.error_msg : (x.warnings && x.warnings.length ? x.warnings.join('; ') : '') })), {
          max: 80, labels: { title: 'Stage', status: 'State', seconds: 'Seconds', rows: 'Rows', size: 'Size', output: 'Output file', detail: 'Problems' },
          cell: (col, v) => col === 'status' ? `<span class="pill ${v === 'done' ? 'ok' : v === 'error' ? 'bad' : v === 'running' ? 'admin' : 'off'}">${esc(v)}</span>`
            : col === 'size' ? esc(v == null ? '–' : fmtBytes(v)) : col === 'output' ? `<span class="mono">${esc(v)}</span>` : undefined
        });
      }
      const e = await api('/api/debug/events?limit=60');
      if (e.ok && $('eventTable')) {
        const rows = (e.d.events || []).slice().reverse().map(x => ({ time: x.ts ? new Date(x.ts * 1000).toLocaleTimeString() : '', level: x.level, stage: x.stage, msg: x.msg,
          data: x.data ? JSON.stringify(x.data) : '' }));
        renderTable($('eventTable'), ['time', 'level', 'stage', 'msg', 'data'], rows, {
          empty: 'No engine events yet. Run the pipeline.', max: 90, labels: { time: 'Time', level: 'Level', stage: 'Stage', msg: 'Event', data: 'Data' },
          cell: (col, v) => col === 'level' ? `<span class="pill ${v === 'error' ? 'bad' : v === 'warn' ? 'admin' : 'off'}">${esc(v)}</span>` : undefined
        });
      }
    }
  };

  /* ============ ADMIN: INTERFACE ============ */
  Page.interface = {
    init() {
      $('prepBtn').addEventListener('click', () => this.act('/api/admin/network/prepare', $('prepBtn')));
      $('stopBtn').addEventListener('click', () => this.act('/api/admin/network/stop', $('stopBtn')));
      $('connTable').addEventListener('click', async e => {
        const b = e.target.closest('button[data-act]');
        if (!b) return;
        const kind = b.dataset.kind, name = b.dataset.name;
        if (b.dataset.act === 'test') {
          b.disabled = true;
          const r = await api('/api/interfaces/test', { method: 'POST', json: { kind, name } });
          b.disabled = false;
          toast(r.ok ? ((r.d.title || name) + ': ' + (r.d.available ? 'working. ' : 'not working. ') + (r.d.detail || '')) : (r.d.error || 'Test failed'), !r.ok || r.d.available === false);
        } else {
          const body = { kind, name };
          if (kind === 'crypto_provider' && name === 'simulated') {
            const ok = await askDialog({ title: 'Use the simulated provider?', text: 'The simulated provider is NOT quantum-safe. Use it for development only.', confirm: 'Use simulated', danger: true });
            if (!ok) return;
            body.confirm_unsafe = true;
          }
          const r = await api('/api/interfaces/select', { method: 'POST', json: body });
          toast(r.ok ? 'Connection changed' : (r.d.error || (r.d.errors || []).join(' ') || 'Could not change it'), !r.ok);
        }
        this.load();
      });
    },
    async act(url, btn) {
      btn.disabled = true;
      const r = await api(url, { method: 'POST' });
      btn.disabled = false;
      toast(r.d.message || (r.ok ? 'Done' : 'Failed'), !r.ok);
      this.load();
    },
    async load() {
      const r = await api('/api/admin/interface');
      const d = r.d;
      if (!r.ok) return;
      $('capKv').innerHTML = kv([['Capture interface', `<span class="mono">${esc(d.capture_interface)}</span>`],
        ['Topology', 'h1 – s1 – h2 (Open vSwitch)'], ['Target packets', esc(d.target_packets)],
        ['Minimum accepted', esc(d.min_packets)], ['Output file', `<span class="mono">${esc(d.output_file)}</span>`]]);
      const n = d.network;
      $('netMsg').className = 'run-msg ' + (n.ready ? 'done' : '');
      $('netMsg').textContent = n.message + (n.updated ? ' (' + fmtTime(n.updated) + ')' : '');
      $('prepBtn').disabled = d.pipeline_running;
      const t = d.tools;
      $('toolChecks').innerHTML = checkCard('Passwordless sudo', t.sudo_access) + checkCard('Mininet', t.mininet_installed) +
        checkCard('tshark', t.tshark_installed) + checkCard('ML-KEM (liboqs)', t.liboqs_mlkem);
      const c = await api('/api/interfaces');
      if (c.ok && $('connTable')) {
        renderTable($('connTable'), ['kind', 'title', 'active', 'available', 'detail', 'actions'], (c.d.rows || []).map(x => Object.assign({ actions: '' }, x)), {
          empty: 'No connections registered.', max: 90,
          labels: { kind: 'Type', title: 'Connection', active: 'In use', available: 'Health', detail: 'Detail', actions: '' },
          cell: (col, v, row) => col === 'active' ? (v ? '<span class="pill admin">In use</span>' : '–')
            : col === 'available' ? `<span class="pill ${v ? 'ok' : 'bad'}">${v ? 'Working' : 'Not working'}</span>`
            : col === 'kind' ? esc(String(v).replace('_', ' '))
            : col === 'title' ? `<b>${esc(v || row.name)}</b>${row.quantum_safe === false ? ' <span class="pill bad">not quantum-safe</span>' : ''}`
            : col === 'actions' ? `<span class="row-actions" style="margin:0;flex-wrap:nowrap"><button class="ghost-btn" data-act="test" data-kind="${esc(row.kind)}" data-name="${esc(row.name)}" type="button">Test</button>${row.active ? '' : `<button class="ghost-btn" data-act="use" data-kind="${esc(row.kind)}" data-name="${esc(row.name)}" type="button">Use</button>`}</span>` : undefined
        });
        if ($('apiBase')) $('apiBase').textContent = c.d.base_url || '';
      }
      renderTable($('nicTable'), ['name', 'up', 'ipv4', 'speed', 'mtu', 'capture'], d.interfaces, {
        empty: 'No interfaces could be read.', labels: { name: 'Name', up: 'Status', ipv4: 'IPv4 address', speed: 'Speed (Mbps)', mtu: 'MTU', capture: 'Role' },
        cell: (col, v, row) => col === 'up' ? `<span class="pill ${v ? 'ok' : 'off'}">${v ? 'Up' : 'Down'}</span>`
          : col === 'capture' ? (v ? '<span class="pill admin">Capture interface</span>' : '–')
          : col === 'name' || col === 'ipv4' ? `<span class="mono">${esc(v ?? '–')}</span>` : undefined
      });
    }
  };

  /* ============ ADMIN: SETTINGS ============ */
  Page.settings = {
    init() { $('saveSettings').addEventListener('click', () => this.save()); },
    async load() {
      const r = await api('/api/admin/settings');
      if (!r.ok) return;
      const s = r.d.settings;
      $('setMode').value = s.default_mode; $('setLoad').value = s.load_source; $('setTimeout').value = s.session_timeout_min;
      $('limitsKv').innerHTML = kv([['CPU limit', esc(r.d.cpu_limit) + '%'], ['Memory limit', esc(r.d.mem_limit) + '%']]);
    },
    async save() {
      const r = await api('/api/admin/settings', { method: 'POST', json: {
        default_mode: $('setMode').value, load_source: $('setLoad').value, session_timeout_min: $('setTimeout').value } });
      $('settingsMsg').textContent = r.ok ? 'Saved.' : (r.d.message || 'Could not save.');
      toast(r.ok ? 'Settings saved' : (r.d.message || 'Could not save'), !r.ok);
    }
  };

  /* ============ ADMIN: USERS ============ */
  Page.users = {
    me: null, pwTarget: null,
    init() {
      $('newUserForm').addEventListener('submit', async e => {
        e.preventDefault();
        const r = await api('/api/admin/users', { method: 'POST', json: {
          display_name: $('nuName').value, username: $('nuUser').value.trim(), password: $('nuPass').value, role: $('nuRole').value } });
        toast(r.ok ? 'User created' : (r.d.message || 'Could not create the user'), !r.ok);
        if (r.ok) { $('newUserForm').reset(); this.load(); }
      });
      $('userTable').addEventListener('click', e => this.onAction(e));
      $('pwCancel').addEventListener('click', () => $('pwDlg').close());
      $('pwForm').addEventListener('submit', async e => {
        e.preventDefault();
        const r = await api('/api/admin/users/' + encodeURIComponent(this.pwTarget), { method: 'PATCH', json: { password: $('pwNew').value } });
        $('pwDlg').close(); $('pwNew').value = '';
        toast(r.ok ? 'Password updated' : (r.d.message || 'Could not update the password'), !r.ok);
      });
    },
    async load() {
      const r = await api('/api/admin/users');
      if (!r.ok) return;
      this.me = r.d.me;
      renderTable($('userTable'), ['display_name', 'username', 'role', 'active', 'last_login', 'actions'], r.d.rows.map(u => Object.assign({ actions: '' }, u)), {
        labels: { display_name: 'Name', username: 'Username', role: 'Role', active: 'Status', last_login: 'Last sign-in', actions: '' },
        cell: (col, v, u) => {
          if (col === 'display_name') return esc(v) + (u.username === this.me ? ' <span class="pill">You</span>' : '');
          if (col === 'username') return `<span class="mono">${esc(v)}</span>`;
          if (col === 'role') return `<span class="pill ${v === 'super_admin' ? 'admin' : ''}">${esc(u.role_label)}</span>`;
          if (col === 'active') return `<span class="pill ${v ? 'ok' : 'off'}">${v ? 'Active' : 'Disabled'}</span>`;
          if (col === 'last_login') return esc(v ? fmtTime(v) : 'Never');
          if (col === 'actions') {
            const self = u.username === this.me, n = esc(u.username);
            return `<span class="row-actions" style="margin:0;flex-wrap:nowrap">
              <button class="ghost-btn" data-act="role" data-u="${n}" data-role="${u.role === 'super_admin' ? 'user' : 'super_admin'}" type="button">${u.role === 'super_admin' ? 'Make user' : 'Make super admin'}</button>
              <button class="ghost-btn" data-act="pw" data-u="${n}" type="button">Reset password</button>
              ${self ? '' : `<button class="ghost-btn" data-act="active" data-u="${n}" data-on="${u.active ? '0' : '1'}" type="button">${u.active ? 'Disable' : 'Enable'}</button>
              <button class="ghost-btn" data-act="del" data-u="${n}" type="button" style="color:var(--high)">Delete</button>`}</span>`;
          }
          return undefined;
        }
      });
    },
    async onAction(e) {
      const b = e.target.closest('button[data-act]');
      if (!b) return;
      const u = b.dataset.u, url = '/api/admin/users/' + encodeURIComponent(u);
      let r;
      if (b.dataset.act === 'pw') { this.pwTarget = u; $('pwTitle').textContent = 'Reset password for ' + u; $('pwDlg').showModal(); $('pwNew').focus(); return; }
      if (b.dataset.act === 'role') r = await api(url, { method: 'PATCH', json: { role: b.dataset.role } });
      else if (b.dataset.act === 'active') r = await api(url, { method: 'PATCH', json: { active: b.dataset.on === '1' } });
      else if (b.dataset.act === 'del') {
        const ok = await askDialog({ title: 'Delete ' + u + '?', text: 'The account is removed. Results this user saved stay available to super admins.', confirm: 'Delete user', danger: true });
        if (!ok) return;
        r = await api(url, { method: 'DELETE' });
      }
      if (r) { toast(r.ok ? r.d.message : (r.d.message || 'That change could not be made'), !r.ok); this.load(); }
    }
  };

  /* ============ START ============ */
  const isPipelinePage = STAGES.includes(page);
  if (isPipelinePage) initRunBar();
  if (Page[page]) {
    if (Page[page].init) Page[page].init();
    if (Page[page].load) Page[page].load();
  }
})();
