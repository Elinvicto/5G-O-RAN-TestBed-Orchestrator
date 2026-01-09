#!/usr/bin/env python3
"""
dashboard_app.py — Components + Attacks with PCAP preview + 100 ms packets & bytes timeseries + Top Talkers.

Highlights:
 - Replaced all system metrics with network metrics derived from PCAPs:
    * packets / 0.1s (existing endpoint)
    * bytes   / 0.1s (new endpoint: /attacks/<name>/bytes_timeseries)
    * top talkers by bytes (new endpoint: /attacks/<name>/top_talkers?n=10)
 - All PCAP parsing uses scapy RawPcapReader (streaming). Install scapy into the Python used to run this:
     /home/testbed/orchestrator/5gorc/bin/python3 -m pip install scapy
 - Dashboard is read-only (parses local PCAPs in workdir/attacks).
"""

from flask import Flask, render_template_string, jsonify, request, send_file
import os, json, argparse, time, math, collections

app = Flask(__name__)

ATTACK_METADATA = {
    "ue_sniff": {
        "title": "UE — Network Sniffing (Passive Collection)",
        "mitre_link": "https://fight.mitre.org/techniques/FGT1040/",
        "description": "Emulates passive network sniffing patterns (UE user-plane flows, DNS/TCP sessions). Useful to validate passive detection and data exposure."
    },
    "ran_locate_ue": {
        "title": "RAN — Locate UE (Signalling / Reconnaissance)",
        "mitre_link": "https://fight.mitre.org/techniques/FGT5012/",
        "description": "Emulates RAN/control-plane small-message sequences that resemble UE location/reconnaissance signaling (many small control messages towards a single control function)."
    },
    "core_flood": {
        "title": "Core — Signalling Flood (Denial of Service)",
        "mitre_link": "https://fight.mitre.org/techniques/FGT1498.501/",
        "description": "Emulates high-volume signaling-like traffic towards core NF IP/port to represent flooding patterns and allow visualization of volume/spike impacts."
    }
}

# ---------------------------
# HTML template
# ---------------------------
TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>O-RAN Dashboard — PCAP bytes/sec & top talkers</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    body { padding: 18px; font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial; }
    .card-summary { min-width: 150px; }
    .small-muted { font-size: 0.9rem; color: #666; }
    .badge-port { margin-right:6px; margin-bottom:6px; }
    .nav-tabs .nav-link { cursor: pointer; }
    table.pcap-preview { font-size: 0.9rem; }
    pre.preview-json { background: #f8f9fa; padding: 10px; max-height: 320px; overflow: auto; }
    .chart-box { height: 220px; }
    .mini-chart { height: 140px; }
    table.top-talkers td, table.top-talkers th { vertical-align: middle; }
  </style>
</head>
<body>
  <div class="container-fluid">
    <div class="d-flex justify-content-between align-items-center mb-3">
      <div>
        <h3>O-RAN Component Map & Attacks — Network Metrics</h3>
        <div class="small-muted">PCAP-derived metrics: packets/0.1s, bytes/0.1s and top-talkers by bytes.</div>
      </div>
      <div>
        <button id="refreshBtn" class="btn btn-outline-primary btn-sm">Refresh</button>
        <a href="/download" class="btn btn-outline-secondary btn-sm">Download Map JSON</a>
      </div>
    </div>

    <ul class="nav nav-tabs mb-3" id="mainTabs">
      <li class="nav-item"><a class="nav-link active" data-tab="components">Components</a></li>
      <li class="nav-item"><a class="nav-link" data-tab="attacks">Attacks</a></li>
    </ul>

    <!-- Components -->
    <div id="tab-components">
      <div class="d-flex gap-3 mb-3 flex-wrap">
        <div class="card card-summary p-2">
          <div class="text-muted">Components</div>
          <div class="fs-4">{{ summary.components_count }}</div>
        </div>
        <div class="card card-summary p-2">
          <div class="text-muted">Total ports</div>
          <div class="fs-4">{{ summary.total_service_ports }}</div>
        </div>
        <div class="card card-summary p-2">
          <div class="text-muted">Sniffed flows</div>
          <div class="fs-4">{{ sniffed }}</div>
        </div>
        <div class="card card-summary p-2">
          <div class="text-muted">Probed responsive</div>
          <div class="fs-4">{{ probe_responsive }}</div>
        </div>
        <div class="card card-summary p-2">
          <div class="text-muted">Reachable</div>
          <div class="fs-4">{{ reachable_total }}</div>
        </div>
      </div>

      <div class="mb-2 d-flex justify-content-between">
        <div class="input-group w-50">
          <span class="input-group-text">Search</span>
          <input id="searchInput" class="form-control" placeholder="filter by host, port, process...">
        </div>
        <div>
          <div class="btn-group" role="group">
            <button class="btn btn-sm btn-outline-secondary filter-btn active" data-filter="all">All</button>
            <button class="btn btn-sm btn-outline-success filter-btn" data-filter="reachable">Reachable</button>
            <button class="btn btn-sm btn-outline-danger filter-btn" data-filter="unreachable">Unreachable</button>
          </div>
        </div>
      </div>

      <div class="table-responsive mb-4">
        <table id="hostsTable" class="table table-hover table-sm">
          <thead class="table-light">
            <tr>
              <th>Host / Component</th>
              <th class="text-center">#Ports</th>
              <th class="text-center">Observed</th>
              <th class="text-center">Probed</th>
              <th class="text-center">Reachable</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
          {% for row in rows %}
            <tr class="host-row" data-host="{{ row.host|e }}" data-total="{{ row.total }}" data-sniff="{{ row.sniff }}" data-probe="{{ row.probe }}" data-reachable="{{ row.reachable }}">
              <td><strong>{{ row.host }}</strong><div class="small-muted">{{ row.component_info }}</div></td>
              <td class="text-center">{{ row.total }}</td>
              <td class="text-center">{{ row.sniff }}</td>
              <td class="text-center">{{ row.probe }}</td>
              <td class="text-center"><strong>{{ row.reachable }}</strong></td>
              <td>
                {% for p in row.ports_list %}
                  <span class="badge {% if p.reachable %}bg-success{% elif p.probe %}bg-warning text-dark{% else %}bg-secondary{% endif %}">{{ p.ip }}:{{ p.port }}:{{ p.proto }}</span>
                {% endfor %}
              </td>
            </tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Attacks -->
    <div id="tab-attacks" style="display:none;">
      <div class="row mb-3">
        <div class="col-md-8">
          <h5>Attack Emulations</h5>
          <p class="small-muted">Offline PCAP emulations produced by <code>attack_runner.py</code>. Packets and bytes timeseries use 100 ms buckets.</p>
        </div>
        <div class="col-md-4 text-end">
          <button class="btn btn-sm btn-outline-secondary" onclick="loadAttacks()">Reload Attacks</button>
        </div>
      </div>

      <div id="attacksContainer">Loading attacks...</div>
      <hr>

      <div id="attackDetail" style="display:none;">
        <div class="d-flex justify-content-between">
          <div>
            <h5 id="attackTitle"></h5>
            <div id="attackDescription" class="small-muted"></div>
            <div class="mt-1"><a id="attackMITRE" target="_blank">MITRE FiGHT technique</a></div>
          </div>
          <div class="text-end">
            <a id="attackDownload" class="btn btn-outline-secondary btn-sm" target="_blank">Download PCAP</a>
            <button class="btn btn-sm btn-outline-primary" id="closeAttackBtn">Close</button>
          </div>
        </div>

        <div class="row mt-3">
          <div class="col-md-5">
            <div class="card p-2 mb-2">
              <div class="text-muted">Total packets</div>
              <div id="attackPackets" class="fs-4"></div>
            </div>
            <div class="card p-2 mb-3">
              <div class="text-muted">Unique flows</div>
              <div id="attackFlows" class="fs-4"></div>
            </div>

            <h6>PCAP Preview (first packets)</h6>
            <div class="table-responsive">
              <table id="pcapPreviewTable" class="table table-sm table-bordered pcap-preview">
                <thead class="table-light"><tr><th>#</th><th>Src</th><th>Dst</th><th>Sport</th><th>Dport</th><th>Proto</th><th>Len</th></tr></thead>
                <tbody id="pcapPreviewBody"></tbody>
              </table>
            </div>

            <pre id="pcapPreviewRaw" class="preview-json" style="display:none;"></pre>
            <div class="mt-2">
              <button id="toggleRawBtn" class="btn btn-sm btn-outline-secondary">Show raw preview JSON</button>
            </div>
          </div>

          <div class="col-md-7">
            <h6>Packets / 0.1s (from PCAP)</h6>
            <div class="card p-2 mb-2">
              <canvas id="chartPackets" class="chart-box"></canvas>
            </div>

            <h6>Bytes / 0.1s (from PCAP)</h6>
            <div class="card p-2 mb-2">
              <canvas id="chartBytes" class="chart-box"></canvas>
            </div>

            <h6 class="mt-3">Top Talkers (by bytes)</h6>
            <div class="card p-2">
              <div class="table-responsive">
                <table id="topTalkersTable" class="table table-sm table-striped top-talkers">
                  <thead class="table-light"><tr><th>#</th><th>Src</th><th>Dst</th><th>Proto</th><th class="text-end">Bytes</th><th class="text-end">Pkts</th></tr></thead>
                  <tbody id="topTalkersBody"></tbody>
                </table>
              </div>
            </div>

          </div>
        </div>

      </div>

    </div>

    <div class="mt-4 small-muted">Data file: <strong>{{ data_file }}</strong> — last updated: {{ last_updated }}</div>
  </div>

<script>
  // Tab switching
  document.querySelectorAll('#mainTabs .nav-link').forEach(function(a){
    a.addEventListener('click', function(){
      document.querySelectorAll('#mainTabs .nav-link').forEach(x=>x.classList.remove('active'));
      a.classList.add('active');
      const tab = a.getAttribute('data-tab');
      document.getElementById('tab-components').style.display = (tab==='components') ? '' : 'none';
      document.getElementById('tab-attacks').style.display = (tab==='attacks') ? '' : 'none';
    });
  });

  // Refresh
  document.getElementById('refreshBtn').addEventListener('click', function(){ fetch('/_reload').then(r=>r.json()).then(()=>location.reload()).catch(()=>alert('Refresh failed')) });

  // Components filters/search
  document.querySelectorAll('.filter-btn').forEach(function(b){ b.addEventListener('click', function(){ document.querySelectorAll('.filter-btn').forEach(x=>x.classList.remove('active')); b.classList.add('active'); applyFilters(); }); });
  document.getElementById('searchInput').addEventListener('input', applyFilters);
  function applyFilters(){
    const q = document.getElementById('searchInput').value.toLowerCase().trim();
    const mode = document.querySelector('.filter-btn.active').getAttribute('data-filter');
    document.querySelectorAll('#hostsTable tbody tr').forEach(function(r){
      const host = r.getAttribute('data-host') ? r.getAttribute('data-host').toLowerCase() : '';
      const total = Number(r.getAttribute('data-total') || 0);
      const sniff = Number(r.getAttribute('data-sniff') || 0);
      const probe = Number(r.getAttribute('data-probe') || 0);
      const reachable = Number(r.getAttribute('data-reachable') || 0);
      let portsText = r.querySelector('td:nth-child(6)').innerText.toLowerCase();
      const matchesQ = (host.indexOf(q) !== -1) || (portsText.indexOf(q) !== -1) || (q==='');
      let modeOk = true;
      if(mode === 'reachable') modeOk = reachable > 0;
      if(mode === 'unreachable') modeOk = reachable === 0;
      r.style.display = (matchesQ && modeOk) ? '' : 'none';
    });
  }

  // Attacks list
  async function loadAttacks(){
    const el = document.getElementById('attacksContainer');
    el.innerHTML = 'Loading...';
    try {
      const res = await fetch('/attacks/list');
      if(!res.ok){
        el.innerHTML = '<div class="alert alert-secondary">No attacks found — run attack_runner.py to generate PCAPs and summaries.</div>';
        return;
      }
      const j = await res.json();
      const attacks = j.attacks || {};
      let html = '<div class="row">';
      for(const [name, info] of Object.entries(attacks)){
        const meta = ({{ attack_meta|tojson }})[name] || {title: name};
        html += `<div class="col-md-4 mb-3">
          <div class="card p-2 h-100">
            <div class="fw-bold">${meta.title}</div>
            <div class="small-muted">packets: ${info.total_packets} &nbsp; flows: ${info.unique_flows}</div>
            <div class="mt-2">
              <button class="btn btn-sm btn-outline-primary" onclick="showAttackDetail('${name}')">View</button>
              <a class="btn btn-sm btn-outline-secondary" href="/attacks/${name}/download">Download PCAP</a>
            </div>
          </div>
        </div>`;
      }
      html += '</div>';
      el.innerHTML = html;
    } catch(e){
      console.error(e);
      el.innerHTML = '<div class="alert alert-danger">Error loading attacks</div>';
    }
  }

  // Charts refs
  let packetsChart = null, bytesChart = null;

  // Show attack detail: preview + charts + top talkers
  async function showAttackDetail(name){
    document.getElementById('attackDetail').style.display = '';
    // summary
    const sres = await fetch(`/attacks/${name}/summary`);
    if(!sres.ok){ alert('Summary not found'); return; }
    const summary = await sres.json();
    const meta = ({{ attack_meta|tojson }})[name] || { title: name, mitre_link: '#', description: '' };
    document.getElementById('attackTitle').innerText = meta.title;
    document.getElementById('attackDescription').innerText = meta.description;
    document.getElementById('attackMITRE').href = meta.mitre_link;
    document.getElementById('attackMITRE').innerText = 'MITRE FiGHT technique';
    document.getElementById('attackDownload').href = `/attacks/${name}/download`;
    document.getElementById('attackPackets').innerText = summary.total_packets || 0;
    document.getElementById('attackFlows').innerText = summary.unique_flows || 0;

    // PCAP preview
    const prevRes = await fetch(`/attacks/${name}/pcap_preview`);
    let prev = [];
    if(prevRes.ok){
      prev = await prevRes.json();
    } else {
      document.getElementById('pcapPreviewBody').innerHTML = `<tr><td colspan="7">No preview available</td></tr>`;
      document.getElementById('pcapPreviewRaw').style.display = 'none';
      return;
    }
    const tbody = document.getElementById('pcapPreviewBody');
    tbody.innerHTML = '';
    for(let i=0;i<prev.length;i++){
      const p = prev[i] || {};
      const sport = p.sport===null || p.sport===undefined ? '' : p.sport;
      const dport = p.dport===null || p.dport===undefined ? '' : p.dport;
      const plen = p.len===null || p.len===undefined ? '' : p.len;
      const proto = p.proto || '';
      const row = `<tr>
        <td>${i+1}</td>
        <td>${p.src||''}</td>
        <td>${p.dst||''}</td>
        <td>${sport}</td>
        <td>${dport}</td>
        <td>${proto}</td>
        <td>${plen}</td>
      </tr>`;
      tbody.insertAdjacentHTML('beforeend', row);
    }
    document.getElementById('pcapPreviewRaw').innerText = JSON.stringify(prev, null, 2);
    document.getElementById('pcapPreviewRaw').style.display = 'none';
    document.getElementById('toggleRawBtn').onclick = function(){
      const el = document.getElementById('pcapPreviewRaw');
      if(el.style.display==='none'){ el.style.display=''; this.innerText='Hide raw preview JSON'; }
      else { el.style.display='none'; this.innerText='Show raw preview JSON'; }
    };

    // Packets timeseries (existing)
    const tsRes = await fetch(`/attacks/${name}/timeseries`);
    if(tsRes.ok){
      const ts = await tsRes.json();
      const labels = ts.buckets.map(b => {
        const d = new Date(b.ts*1000);
        const s = d.toLocaleTimeString();
        const frac = (b.ts % 1).toFixed(1).slice(1);
        return s + frac;
      });
      const values = ts.buckets.map(b => b.count);
      if(packetsChart){ packetsChart.destroy(); packetsChart = null; }
      const ctx = document.getElementById('chartPackets').getContext('2d');
      packetsChart = new Chart(ctx, {
        type: 'line',
        data: { labels: labels, datasets: [{ label: 'packets / 0.1s', data: values, borderColor: 'rgb(75,192,192)', fill:false, pointRadius:0 }] },
        options: { responsive:true, maintainAspectRatio:false, scales: { y: { beginAtZero:true } } }
      });
    } else {
      if(packetsChart){ packetsChart.destroy(); packetsChart = null; }
    }

    // Bytes timeseries
    const bRes = await fetch(`/attacks/${name}/bytes_timeseries`);
    if(bRes.ok){
      const bt = await bRes.json();
      const labels = bt.buckets.map(b => {
        const d = new Date(b.ts*1000);
        const s = d.toLocaleTimeString();
        const frac = (b.ts % 1).toFixed(1).slice(1);
        return s + frac;
      });
      const values = bt.buckets.map(b => b.bytes);
      if(bytesChart){ bytesChart.destroy(); bytesChart = null; }
      const ctxB = document.getElementById('chartBytes').getContext('2d');
      bytesChart = new Chart(ctxB, {
        type: 'line',
        data: { labels: labels, datasets: [{ label: 'bytes / 0.1s', data: values, borderColor: 'rgb(255,159,64)', fill:false, pointRadius:0 }] },
        options: { responsive:true, maintainAspectRatio:false, scales: { y: { beginAtZero:true } } }
      });
    } else {
      if(bytesChart){ bytesChart.destroy(); bytesChart = null; }
    }

    // Top talkers
    const topN = 10;
    const ttRes = await fetch(`/attacks/${name}/top_talkers?n=${topN}`);
    const tbodyTT = document.getElementById('topTalkersBody');
    tbodyTT.innerHTML = '<tr><td colspan="6">Loading...</td></tr>';
    if(ttRes.ok){
      const data = await ttRes.json();
      tbodyTT.innerHTML = '';
      let i = 0;
      for(const row of data.top_talkers){
        i++;
        const tr = `<tr>
          <td>${i}</td>
          <td>${row.src}</td>
          <td>${row.dst}</td>
          <td>${row.proto}</td>
          <td class="text-end">${row.bytes}</td>
          <td class="text-end">${row.pkts}</td>
        </tr>`;
        tbodyTT.insertAdjacentHTML('beforeend', tr);
      }
      if(i===0){
        tbodyTT.innerHTML = '<tr><td colspan="6">No flows found in PCAP</td></tr>';
      }
    } else {
      tbodyTT.innerHTML = '<tr><td colspan="6">Top talkers not available</td></tr>';
    }

    // scroll into view
    window.scrollTo({ top: document.getElementById('attackDetail').offsetTop - 20, behavior: 'smooth' });
  }

  // Close
  document.getElementById('closeAttackBtn').addEventListener('click', function(){
    document.getElementById('attackDetail').style.display = 'none';
    if(packetsChart){ packetsChart.destroy(); packetsChart=null; }
    if(bytesChart){ bytesChart.destroy(); bytesChart=null; }
    document.getElementById('topTalkersBody').innerHTML = '';
  });

  // initial load
  loadAttacks();
</script>
</body>
</html>
"""

# -------------------------
# Helpers & data loading
# -------------------------
def find_map_file(workdir):
    candidates = [
        os.path.join(workdir, 'component_map_reachable.json'),
        os.path.join(workdir, 'component_map_probed.json'),
        os.path.join(workdir, 'component_map.json')
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    return None

def load_map_file(path):
    try:
        with open(path, 'r') as fh:
            return json.load(fh)
    except Exception:
        return {}

def summarize_map(comp_map):
    rows = []
    sp = comp_map.get('service_ports', {})
    components = {c.get('name') or c.get('id'): c for c in comp_map.get('components', [])}
    total_reachable = 0
    total_probe_ok = 0
    total_sniff = 0
    for host, entries in sp.items():
        total = len(entries)
        sniff = sum(1 for e in entries if e.get('observed_in_sniff'))
        probe = sum(1 for e in entries if e.get('observed_by_probe'))
        reachable = sum(1 for e in entries if (e.get('reachable') or e.get('observed_by_probe') or e.get('observed_in_sniff')))
        total_reachable += reachable
        total_probe_ok += probe
        total_sniff += sniff
        ports_list = []
        for e in entries:
            flags = []
            if e.get('observed_in_sniff'): flags.append('SNIFF')
            if e.get('observed_by_probe'): flags.append('PROBE')
            if e.get('reachable'): flags.append('REACH')
            ports_list.append({
                'ip': e.get('ip') or '', 'port': e.get('port') or '', 'proto': e.get('proto') or '',
                'process': e.get('process') or '', 'flags': ','.join(flags), 'probe': bool(e.get('observed_by_probe')), 'reachable': bool(e.get('reachable') or e.get('observed_by_probe') or e.get('observed_in_sniff'))
            })
        comp_obj = components.get(host)
        comp_info = ''
        if comp_obj:
            comp_info = f"pid={comp_obj.get('pid')} cmd={comp_obj.get('cmdline') or comp_obj.get('exe') or ''}"
        rows.append({
            'host': host,
            'total': total,
            'sniff': sniff,
            'probe': probe,
            'reachable': reachable,
            'ports_list': ports_list,
            'component_info': comp_info
        })
    rows.sort(key=lambda r: (-r['reachable'], r['host']))
    summary = {'components_count': len(rows), 'total_service_ports': sum(r['total'] for r in rows)}
    return rows, summary, total_sniff, total_probe_ok, total_reachable

# Globals
WORKDIR = os.environ.get('ORAN_WORKDIR', '.')
DATA_FILE = find_map_file(WORKDIR) or os.path.join(WORKDIR, 'component_map.json')

# -------------------------
# Routes: index & map
# -------------------------
@app.route('/')
def index():
    global DATA_FILE
    DATA_FILE = find_map_file(WORKDIR) or DATA_FILE
    comp_map = load_map_file(DATA_FILE)
    rows, summary, total_sniff, total_probe_ok, total_reachable = summarize_map(comp_map)
    last_updated = 'n/a'
    try:
        last_updated = time.ctime(os.path.getmtime(DATA_FILE))
    except Exception:
        pass
    return render_template_string(TEMPLATE,
                                  rows=rows,
                                  summary=summary,
                                  sniffed=total_sniff,
                                  probe_responsive=total_probe_ok,
                                  reachable_total=total_reachable,
                                  data_file=os.path.basename(DATA_FILE),
                                  last_updated=last_updated,
                                  attack_meta=ATTACK_METADATA)

@app.route('/_reload')
def _reload():
    return jsonify({'status':'ok'})

@app.route('/download')
def download():
    p = find_map_file(WORKDIR) or DATA_FILE
    try:
        return jsonify(load_map_file(p))
    except Exception:
        return jsonify({'error':'cannot read file'}), 500

@app.route('/api/status')
def api_status():
    p = find_map_file(WORKDIR) or DATA_FILE
    comp_map = load_map_file(p)
    rows, summary, total_sniff, total_probe_ok, total_reachable = summarize_map(comp_map)
    return jsonify({'data_file': os.path.basename(p), 'last_updated': time.ctime(os.path.getmtime(p)) if os.path.exists(p) else None, 'rows': rows, 'summary': summary})

# -------------------------
# Attacks endpoints
# -------------------------
def _attacks_dir(workdir):
    return os.path.join(workdir, 'attacks')

@app.route('/attacks/list')
def attacks_list():
    d = _attacks_dir(WORKDIR)
    p = os.path.join(d, 'summary.json')
    if not os.path.exists(p):
        return jsonify({'error':'no attacks found', 'path': p}), 404
    try:
        return jsonify(json.load(open(p)))
    except Exception:
        return jsonify({'error':'cant read summary'}), 500

@app.route('/attacks/<name>/summary')
def attack_summary(name):
    d = _attacks_dir(WORKDIR)
    s = os.path.join(d, f"{name}.summary.json")
    if not os.path.exists(s):
        return jsonify({'error':'not found'}), 404
    try:
        return jsonify(json.load(open(s)))
    except Exception:
        return jsonify({'error':'cannot read file'}), 500

@app.route('/attacks/<name>/pcap_preview')
def pcap_preview(name):
    d = _attacks_dir(WORKDIR)
    pcap_path = os.path.join(d, f"{name}.pcap")
    if not os.path.exists(pcap_path):
        return jsonify({'error':'pcap not found'}), 404
    sfile = os.path.join(d, f"{name}.summary.json")
    if os.path.exists(sfile):
        try:
            j = json.load(open(sfile))
            return jsonify(j.get('preview', []))
        except Exception:
            pass
    try:
        from scapy.all import rdpcap
        pkts = rdpcap(pcap_path, count=20)
        out=[]
        for p in pkts:
            ip = p.getlayer('IP')
            if ip:
                sport = p['TCP'].sport if p.haslayer('TCP') else (p['UDP'].sport if p.haslayer('UDP') else None)
                dport = p['TCP'].dport if p.haslayer('TCP') else (p['UDP'].dport if p.haslayer('UDP') else None)
                proto = 'tcp' if p.haslayer('TCP') else ('udp' if p.haslayer('UDP') else 'ip')
                out.append({'src': ip.src, 'dst': ip.dst, 'sport': sport, 'dport': dport, 'proto': proto, 'len': len(p)})
        return jsonify(out)
    except Exception:
        return jsonify({'error':'cannot parse pcap'}), 500

@app.route('/attacks/<name>/timeseries')
def attack_timeseries(name):
    """
    Existing packets/0.1s endpoint — kept for packets visualization.
    Returns: { start, end, bucket_ms=100, buckets: [{ts, count}] }
    """
    d = _attacks_dir(WORKDIR)
    pcap_path = os.path.join(d, f"{name}.pcap")
    if not os.path.exists(pcap_path):
        return jsonify({'error':'pcap not found'}), 404
    try:
        from scapy.all import RawPcapReader
        times = []
        for pkt_data, pkt_meta in RawPcapReader(pcap_path):
            ts = None
            if hasattr(pkt_meta, 'sec') and hasattr(pkt_meta, 'usec'):
                ts = pkt_meta.sec + float(pkt_meta.usec)/1_000_000
            elif isinstance(pkt_meta, tuple) and len(pkt_meta) >= 2:
                sec = pkt_meta[0]; usec = pkt_meta[1]
                ts = sec + float(usec)/1_000_000
            else:
                # try Ether fallback
                try:
                    from scapy.all import Ether
                    pkt = Ether(pkt_data)
                    if hasattr(pkt, 'time'):
                        ts = float(pkt.time)
                except Exception:
                    ts = None
            if ts is not None:
                times.append(ts)
        if not times:
            return jsonify({'error':'no timestamps found in pcap'}), 500
        times.sort()
        start = times[0]
        end = times[-1]
        bucket_ms = 100
        bucket_s = bucket_ms / 1000.0
        nbuckets = int(math.ceil((end - start) / bucket_s)) + 1
        buckets = [0] * nbuckets
        base = start
        for t in times:
            idx = int(math.floor((t - base) / bucket_s))
            if idx < 0:
                idx = 0
            if idx >= nbuckets:
                idx = nbuckets - 1
            buckets[idx] += 1
        out_buckets = []
        for i, cnt in enumerate(buckets):
            ts_bucket = base + (i * bucket_s)
            out_buckets.append({'ts': round(ts_bucket, 3), 'count': cnt})
        return jsonify({'start': round(start,3), 'end': round(end,3), 'bucket_ms': bucket_ms, 'buckets': out_buckets})
    except Exception as e:
        return jsonify({'error': 'scapy parsing failed', 'detail': str(e)}), 500

@app.route('/attacks/<name>/bytes_timeseries')
def attack_bytes_timeseries(name):
    """
    Compute bytes-per-0.1s (100 ms) buckets from the PCAP file.
    Returns: { start, end, bucket_ms, buckets: [{ts, bytes}] } where ts is float epoch seconds.
    Uses streaming RawPcapReader and computes len(pkt_data) as bytes on-wire.
    """
    d = _attacks_dir(WORKDIR)
    pcap_path = os.path.join(d, f"{name}.pcap")
    if not os.path.exists(pcap_path):
        return jsonify({'error':'pcap not found'}), 404
    try:
        from scapy.all import RawPcapReader
        # First pass: find min & max timestamps without storing all timestamps
        times_min = None
        times_max = None
        # We'll accumulate events into buckets on the fly:
        bucket_ms = 100
        bucket_s = bucket_ms / 1000.0
        # To avoid two-pass over extremely large files, we do streaming and build a dict keyed by bucket index.
        bytes_by_bucket = {}
        for pkt_data, pkt_meta in RawPcapReader(pcap_path):
            ts = None
            if hasattr(pkt_meta, 'sec') and hasattr(pkt_meta, 'usec'):
                ts = pkt_meta.sec + float(pkt_meta.usec)/1_000_000
            elif isinstance(pkt_meta, tuple) and len(pkt_meta) >= 2:
                sec = pkt_meta[0]; usec = pkt_meta[1]
                ts = sec + float(usec)/1_000_000
            else:
                # try Ether fallback to get timestamp
                try:
                    from scapy.all import Ether
                    pkt = Ether(pkt_data)
                    if hasattr(pkt, 'time'):
                        ts = float(pkt.time)
                except Exception:
                    ts = None
            if ts is None:
                continue
            if times_min is None or ts < times_min: times_min = ts
            if times_max is None or ts > times_max: times_max = ts
            # bytes on the wire: use length of pkt_data
            b = len(pkt_data) if pkt_data is not None else 0
            # compute bucket index relative to times_min later; store keyed by raw bucket index using floor(ts/bucket_s)
            idx = int(math.floor(ts / bucket_s))
            bytes_by_bucket[idx] = bytes_by_bucket.get(idx, 0) + b
        if times_min is None:
            return jsonify({'error':'no timestamps found in pcap'}), 500
        # We want contiguous buckets between start_idx and end_idx
        start_idx = int(math.floor(times_min / bucket_s))
        end_idx = int(math.floor(times_max / bucket_s))
        out_buckets = []
        for idx in range(start_idx, end_idx + 1):
            ts_bucket = (idx * bucket_s)
            cnt_bytes = bytes_by_bucket.get(idx, 0)
            out_buckets.append({'ts': round(ts_bucket, 3), 'bytes': cnt_bytes})
        return jsonify({'start': round(times_min,3), 'end': round(times_max,3), 'bucket_ms': bucket_ms, 'buckets': out_buckets})
    except Exception as e:
        return jsonify({'error': 'scapy parsing failed', 'detail': str(e)}), 500

@app.route('/attacks/<name>/top_talkers')
def attack_top_talkers(name):
    """
    Compute top talkers by bytes from the PCAP.
    Query param: n (default 10)
    Returns: { top_talkers: [ {src,dst,proto,bytes,pkts}, ... ] }
    Flow key is (src, dst, proto).
    """
    d = _attacks_dir(WORKDIR)
    pcap_path = os.path.join(d, f"{name}.pcap")
    if not os.path.exists(pcap_path):
        return jsonify({'error':'pcap not found'}), 404
    try:
        n = int(request.args.get('n', 10))
        from scapy.all import RawPcapReader, Ether
        agg = {}  # key -> [bytes, pkts]
        for pkt_data, pkt_meta in RawPcapReader(pcap_path):
            try:
                # decode just enough to find IP/TCP/UDP layers
                # using raw bytes and scapy's Ether when possible
                pkt = None
                try:
                    pkt = Ether(pkt_data)
                except Exception:
                    pkt = None
                ip = None
                proto = 'other'
                src = None
                dst = None
                if pkt is not None and pkt.haslayer('IP'):
                    ip = pkt.getlayer('IP')
                    src = getattr(ip, 'src', None)
                    dst = getattr(ip, 'dst', None)
                    if pkt.haslayer('TCP'):
                        proto = 'tcp'
                    elif pkt.haslayer('UDP'):
                        proto = 'udp'
                    else:
                        proto = str(ip.proto) if hasattr(ip, 'proto') else 'ip'
                else:
                    # skip non-IP frames
                    continue
                key = (src or '', dst or '', proto)
                b = len(pkt_data) if pkt_data is not None else 0
                entry = agg.get(key)
                if entry is None:
                    agg[key] = [b, 1]
                else:
                    entry[0] += b
                    entry[1] += 1
            except Exception:
                # ignore malformed packet decode for aggregation
                continue
        # produce sorted list
        rows = []
        for (src, dst, proto), (byt, pkts) in agg.items():
            rows.append({'src': src, 'dst': dst, 'proto': proto, 'bytes': int(byt), 'pkts': int(pkts)})
        rows.sort(key=lambda r: r['bytes'], reverse=True)
        return jsonify({'top_talkers': rows[:n]})
    except Exception as e:
        return jsonify({'error':'top_talkers failed', 'detail': str(e)}), 500

@app.route('/attacks/<name>/download')
def attack_download(name):
    d = _attacks_dir(WORKDIR)
    p = os.path.join(d, f"{name}.pcap")
    if not os.path.exists(p):
        return jsonify({'error':'pcap not found'}), 404
    try:
        return send_file(p, as_attachment=True, download_name=os.path.basename(p))
    except Exception:
        return jsonify({'error':'cannot send file'}), 500

# -------------------------
# CLI runner
# -------------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--workdir', default='./oran_orchestrator_work')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=5000)
    args = parser.parse_args()
    WORKDIR = args.workdir
    DATA_FILE = find_map_file(WORKDIR) or os.path.join(WORKDIR, 'component_map.json')
    print(f"Starting Flask dashboard, reading from workdir={WORKDIR}, data_file={DATA_FILE}")
    app.run(host=args.host, port=args.port)

