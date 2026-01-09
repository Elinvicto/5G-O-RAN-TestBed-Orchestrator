#!/usr/bin/env python3
"""
Visualization and HTML report generator (includes service_ports table if present).
"""
from common import ensure_work_dir, now_ts, CONFIG, load_json_if_exists
import os, json, logging

# optional matplotlib
try:
    import matplotlib.pyplot as plt
except Exception:
    plt = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def _render_service_ports_table(service_ports):
    """Return an HTML table string for the service_ports dict."""
    rows = []
    for svc, entries in service_ports.items():
        for e in entries:
            ip = e.get("ip") or ""
            port = e.get("port") or ""
            proto = e.get("protocol") or ""
            host = e.get("host") or ""
            notes = ", ".join(e.get("notes") or [])
            raw = (e.get("raw") or "")[:200]
            rows.append((svc, ip, port, proto, host, notes, raw))
    if not rows:
        return "<p><em>No service ports detected.</em></p>"
    html = ["<table border='1' cellpadding='4' cellspacing='0'>",
            "<thead><tr><th>Service</th><th>IP</th><th>Port</th><th>Proto</th><th>Host</th><th>Notes</th><th>Raw</th></tr></thead><tbody>"]
    for r in rows:
        svc, ip, port, proto, host, notes, raw = (str(x) for x in r)
        html.append(f"<tr><td>{svc}</td><td>{ip}</td><td>{port}</td><td>{proto}</td><td>{host}</td><td>{notes}</td><td>{raw}</td></tr>")
    html.append("</tbody></table>")
    return "\n".join(html)

def visualize_and_report(baseline, post, attack_result):
    wd = ensure_work_dir()
    if plt is None:
        logging.warning("matplotlib not available — skipping graphics")
    figs = []
    # create CPU/MEM visuals if matplotlib available
    if plt:
        for hname,hdata in baseline["hosts"].items():
            pre=hdata.get("resources",{}); post_h=post["hosts"].get(hname,{})
            post_res=post_h.get("resources",{})
            cpu_pre=pre.get("cpu"); cpu_post=post_res.get("cpu")
            mem_pre=pre.get("mem"); mem_post=post_res.get("mem")
            if (cpu_pre is not None or cpu_post is not None):
                fig, ax = plt.subplots()
                labels=[]; vals=[]
                if cpu_pre is not None:
                    labels.append("cpu_pre"); vals.append(cpu_pre)
                if cpu_post is not None:
                    labels.append("cpu_post"); vals.append(cpu_post)
                ax.bar(labels, vals); ax.set_title(f"CPU % - {hname}")
                fn=os.path.join(wd, f"{hname}_cpu.png"); fig.savefig(fn); plt.close(fig); figs.append(fn)
            if (mem_pre is not None or mem_post is not None):
                fig, ax = plt.subplots()
                labels=[]; vals=[]
                if mem_pre is not None:
                    labels.append("mem_pre"); vals.append(mem_pre)
                if mem_post is not None:
                    labels.append("mem_post"); vals.append(mem_post)
                ax.bar(labels, vals); ax.set_title(f"Mem % - {hname}")
                fn=os.path.join(wd, f"{hname}_mem.png"); fig.savefig(fn); plt.close(fig); figs.append(fn)
    # Load component_map (if present)
    comp_map = load_json_if_exists(os.path.join(wd, "component_map.json")) or {}
    service_ports = comp_map.get("service_ports", {})
    comp_map_link = "component_map.json" if os.path.exists(os.path.join(wd,"component_map.json")) else None

    repfile = os.path.join(wd, CONFIG["report_file"])
    with open(repfile, "w") as f:
        f.write("<html><head><meta charset='utf-8'><title>O-RAN Attack Report</title></head><body>\n")
        f.write(f"<h1>O-RAN Attack Report</h1>\n<p>Generated: {now_ts()}</p>\n")
        f.write("<h2>Attack Summary</h2>\n<pre>{}</pre>\n".format(json.dumps(attack_result, indent=2)))
        f.write("<h2>Baseline vs Post Visuals</h2>\n")
        for img in figs:
            f.write(f"<div><h3>{os.path.basename(img)}</h3><img src='{os.path.basename(img)}' style='max-width:800px'></div>\n")
        if comp_map_link:
            f.write(f"<h2>Component Map</h2>\n<p><a href='{comp_map_link}'>{comp_map_link}</a></p>\n")
        f.write("<h2>Detected Service Ports</h2>\n")
        f.write(_render_service_ports_table(service_ports))
        f.write("<h2>Notes</h2>\n<ul>\n")
        f.write("<li>All simulations are rate-limited by default. Review the script and inventory before enabling non-safe modes.</li>\n")
        f.write("</ul>\n</body></html>\n")
    logging.info("HTML report written to %s", repfile)
    return repfile

