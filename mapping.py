#!/usr/bin/env python3
"""
mapping.py (backward-compatible)

- Signature kept for orchestrator.py:
    map_virtual_components(inv, netns_info, derived_gateways, sniff_iface=None, sniff_duration=0)
- Discovers listeners via `ss` (host + optional per-netns from netns_info)
- Builds component objects from PIDs (/proc), normalizes service_ports, computes _ports_count
- Robust Scapy sniff: enumerates real interfaces when iface=='any', always sniffs 'lo' briefly
- Marks observed_in_sniff (IP+port) and adds port+proto fallback
- Optional active TCP probe: set env ORAN_PROBE_AFTER=0 to disable (default ON)
"""

import os
import re
import json
import time
import socket
import subprocess
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# -----------------------------
# Utilities
# -----------------------------
def _run_cmd(args):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    return p.stdout.splitlines()

def _safe_read(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except Exception:
        return None

# -----------------------------
# /proc helpers
# -----------------------------
def pid_cmdline(pid):
    b = _safe_read(f"/proc/{pid}/cmdline")
    if not b:
        return None
    parts = [p.decode(errors="ignore") for p in b.split(b"\0") if p]
    return " ".join(parts) if parts else None

def pid_exe(pid):
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except Exception:
        return None

def pid_netns_inode(pid):
    try:
        s = os.readlink(f"/proc/{pid}/ns/net")
        m = re.search(r'\[(\d+)\]', s)
        if m:
            return int(m.group(1))
        return s
    except Exception:
        return None

def pid_interfaces(pid):
    txt = _safe_read(f"/proc/{pid}/net/dev")
    if not txt:
        return []
    try:
        s = txt.decode(errors="ignore")
    except Exception:
        return []
    ifs = []
    for ln in s.splitlines():
        ln = ln.strip()
        if not ln or ":" not in ln or ln.startswith("Inter-|"):
            continue
        ifs.append(ln.split(":")[0].strip())
    return list(set(ifs))

# -----------------------------
# ss parsing (host + per-netns)
# -----------------------------
def parse_ss_list(args, proto_label):
    try:
        lines = _run_cmd(args)
    except Exception:
        return []
    listeners = []
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("Netid") or ln.startswith("State"):
            continue
        parts = re.split(r'\s+', ln)
        local = None
        for tok in parts:
            if ':' in tok and not tok.startswith('users:'):
                local = tok
                break
        if not local:
            continue
        m = re.match(r'\[?([0-9A-Fa-f:\.]+)\]?:([0-9]+)$', local)
        if m:
            ip = m.group(1); port = int(m.group(2))
        else:
            m2 = re.match(r'\*:(\d+)$', local)
            if m2:
                ip = "0.0.0.0"; port = int(m2.group(1))
            else:
                continue
        pid = None; proc = None
        u = re.search(r'users:\(\("([^"]+)",pid=(\d+),', ln)
        if u:
            proc = u.group(1); pid = int(u.group(2))
        else:
            u2 = re.search(r'users:\(\(([^,]+),pid=(\d+),', ln)
            if u2:
                proc = u2.group(1).strip('"'); pid = int(u2.group(2))
        listeners.append({"proto": proto_label, "local_ip": ip, "local_port": port, "pid": pid, "process": proc, "raw": ln})
    return listeners

def get_ss_listeners():
    return parse_ss_list(["ss","-ltnp"], "tcp") + parse_ss_list(["ss","-lunp"], "udp")

def get_ss_listeners_for_netns(netns):
    res = []
    try:
        lines = _run_cmd(["ip","netns","exec",netns,"ss","-ltnp"]) + _run_cmd(["ip","netns","exec",netns,"ss","-lunp"])
    except Exception:
        return res
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("Netid") or ln.startswith("State"):
            continue
        parts = re.split(r'\s+', ln)
        local = None
        for tok in parts:
            if ':' in tok and not tok.startswith('users:'):
                local = tok
                break
        if not local:
            continue
        m = re.match(r'\[?([0-9A-Fa-f:\.]+)\]?:([0-9]+)$', local)
        if m:
            ip = m.group(1); port = int(m.group(2))
        else:
            m2 = re.match(r'\*:(\d+)$', local)
            if m2:
                ip = "0.0.0.0"; port = int(m2.group(1))
            else:
                continue
        pid = None; proc = None
        u = re.search(r'users:\(\("([^"]+)",pid=(\d+),', ln)
        if u:
            proc = u.group(1); pid = int(u.group(2))
        else:
            u2 = re.search(r'users:\(\(([^,]+),pid=(\d+),', ln)
            if u2:
                proc = u2.group(1).strip('"'); pid = int(u2.group(2))
        res.append({"proto": "tcp" if "tcp" in ln.lower() else "udp", "local_ip": ip, "local_port": port, "pid": pid, "process": proc, "raw": ln, "netns": netns})
    return res

# -----------------------------
# Build components from listeners
# -----------------------------
def build_components_from_listeners(listeners):
    comps_by_pid = {}
    anon = []
    for L in listeners:
        pid = L.get("pid")
        if pid:
            if pid not in comps_by_pid:
                comps_by_pid[pid] = {
                    "pid": pid,
                    "cmdline": pid_cmdline(pid),
                    "exe": pid_exe(pid),
                    "namespace_inode": pid_netns_inode(pid),
                    "interfaces": pid_interfaces(pid),
                    "service_ports": [],
                    "observed_flows": []
                }
            comps_by_pid[pid]["service_ports"].append({
                "host": None,
                "ip": L["local_ip"],
                "port": int(L["local_port"]),
                "proto": (L["proto"] or "").lower(),
                "process": L.get("process"),
                "pid": pid,
                "source": "ss-listener",
                "raw": L.get("raw")
            })
        else:
            anon.append({
                "host": None,
                "ip": L["local_ip"],
                "port": int(L["local_port"]),
                "proto": (L["proto"] or "").lower(),
                "process": None,
                "pid": None,
                "source": "ss-listener-unknown",
                "raw": L.get("raw")
            })

    components = []
    for pid, meta in comps_by_pid.items():
        if meta["cmdline"]:
            name = meta["cmdline"].split()[0].split("/")[-1]
        elif meta["exe"]:
            name = meta["exe"].split("/")[-1]
        else:
            name = f"proc-{pid}"
        components.append({
            "id": f"pid-{pid}",
            "name": name,
            "pid": pid,
            "cmdline": meta["cmdline"],
            "exe": meta["exe"],
            "namespace_inode": meta["namespace_inode"],
            "interfaces": meta["interfaces"],
            "service_ports": meta["service_ports"],
            "addresses": [],
            "observed_flows": []
        })

    for i, s in enumerate(anon):
        components.append({
            "id": f"anon-{i}",
            "name": f"anon-service-{i}",
            "pid": None,
            "cmdline": None,
            "exe": None,
            "namespace_inode": None,
            "interfaces": [],
            "service_ports": [s],
            "addresses": [],
            "observed_flows": []
        })
    return components

# -----------------------------
# Robust sniff (Scapy)
# -----------------------------
def _list_ifaces_for_any():
    # enumerate from /sys/class/net (fallback to socket.if_nameindex)
    ifaces = []
    netdir = "/sys/class/net"
    if os.path.isdir(netdir):
        for name in os.listdir(netdir):
            try:
                state = open(os.path.join(netdir, name, "operstate")).read().strip()
            except Exception:
                state = "unknown"
            if state in ("up", "unknown"):
                ifaces.append(name)
    else:
        try:
            ifaces = [n for _, n in socket.if_nameindex()]
        except Exception:
            ifaces = []
    # keep order deterministic; lo will be sniffed separately anyway
    return [i for i in sorted(set(ifaces)) if i != "lo"]

def _sniff_collect_flows(iface, duration):
    """
    Return list of flows: dicts {src,dst,sport,dport,proto}
    """
    flows = []
    try:
        from scapy.all import sniff, IP, IPv6, TCP, UDP
    except Exception as e:
        # scapy not installed or import failed
        return flows

    def pkt_cb(pkt):
        try:
            if IP in pkt:
                ip = pkt[IP]
            elif IPv6 in pkt:
                ip = pkt[IPv6]
            else:
                return
            proto = None; sport = dport = None
            if TCP in pkt:
                proto = "tcp"; sport = int(pkt[TCP].sport); dport = int(pkt[TCP].dport)
            elif UDP in pkt:
                proto = "udp"; sport = int(pkt[UDP].sport); dport = int(pkt[UDP].dport)
            else:
                return
            flows.append({"src": ip.src, "dst": ip.dst, "sport": sport, "dport": dport, "proto": proto})
        except Exception:
            return

    try:
        sniff(iface=iface, prn=pkt_cb, timeout=int(duration), store=False)
    except Exception:
        return []
    # dedupe
    seen = set(); out = []
    for f in flows:
        key = (f["src"], f["dst"], f["sport"], f["dport"], f["proto"])
        if key in seen: continue
        seen.add(key); out.append(f)
    return out

def sniff_flows(iface=None, duration=20):
    """
    - If iface == 'any', sniff each real interface for a slice of time and also sniff 'lo' briefly.
    - Else sniff the given iface and also sniff 'lo' briefly (if iface != lo).
    """
    merged = []
    if duration and duration > 0:
        if iface and str(iface).lower() == "any":
            ifs = _list_ifaces_for_any()
            per = max(1, int(duration // max(1, len(ifs) or 1)))
            for iif in ifs:
                merged.extend(_sniff_collect_flows(iif, per))
            merged.extend(_sniff_collect_flows("lo", min(5, max(1, int(duration)))))
        else:
            merged.extend(_sniff_collect_flows(iface, duration))
            if str(iface).lower() != "lo":
                merged.extend(_sniff_collect_flows("lo", min(5, max(1, int(duration)))))
    # dedupe again
    seen = set(); out = []
    for f in merged:
        key = (f["src"], f["dst"], f["sport"], f["dport"], f["proto"])
        if key in seen: continue
        seen.add(key); out.append(f)
    return out

# -----------------------------
# Flow matching & attach
# -----------------------------
def _ip_loopback_equiv(a, b):
    # treat 127.* family and ::1 as loopback-equivalent
    if (str(a).startswith("127.") and str(b).startswith("127.")): return True
    if (str(a) == "::1" and str(b) == "::1"): return True
    return False

def attach_flows_to_components(flows, components):
    port_index = defaultdict(list)
    ip_index = defaultdict(list)
    for comp in components:
        for p in comp.get("service_ports", []):
            key = (int(p.get("port") or 0), (p.get("proto") or "").lower())
            port_index[key].append(comp)
        for ip in comp.get("addresses", []):
            ip_index[ip].append(comp)
        for ifc in comp.get("interfaces", []):
            ip_index[ifc].append(comp)
    for f in flows:
        proto = (f.get("proto") or "").lower()
        try:
            dport = int(f.get("dport") or 0)
            sport = int(f.get("sport") or 0)
        except Exception:
            dport = sport = 0
        k = (dport, proto); matched = False
        for comp in port_index.get(k, []):
            comp.setdefault("observed_flows", []).append({
                "src": f["src"], "dst": f["dst"], "sport": sport, "dport": dport, "proto": proto, "source": "sniff"
            })
            matched = True
        if matched: continue
        # ip-based fallback
        if f.get("dst") in ip_index:
            for comp in ip_index[f["dst"]]:
                comp.setdefault("observed_flows", []).append({
                    "src": f["src"], "dst": f["dst"], "sport": sport, "dport": dport, "proto": proto, "source": "sniff-ip"
                })
    return components

def mark_observed_in_service_ports(comp_map, flows):
    # IP+port first, then port+proto fallback
    svc = comp_map.get("service_ports", {})
    # build a set of observed (port,proto)
    observed_pp = set()
    for f in flows:
        try:
            observed_pp.add((int(f.get("dport") or 0), (f.get("proto") or "").lower()))
            observed_pp.add((int(f.get("sport") or 0), (f.get("proto") or "").lower()))
        except Exception:
            continue
    for host_key, arr in svc.items():
        for entry in arr:
            entry.setdefault("observed_in_sniff", False)
            entry_proto = (entry.get("proto") or "").lower()
            try:
                entry_port = int(entry.get("port") or 0)
            except Exception:
                entry_port = 0
            eip = entry.get("ip")
            # exact IP+port match
            for f in flows:
                if (f.get("proto") == entry_proto
                    and (int(f.get("dport") or 0) == entry_port or int(f.get("sport") or 0) == entry_port)):
                    # IP match or wildcard/loopback family
                    if not eip or eip.startswith("0.0.0.0") or f.get("dst") == eip or f.get("src") == eip or _ip_loopback_equiv(eip, f.get("dst")) or _ip_loopback_equiv(eip, f.get("src")):
                        entry["observed_in_sniff"] = True
                        break
            # port+proto fallback
            if not entry["observed_in_sniff"] and (entry_port, entry_proto) in observed_pp:
                entry["observed_in_sniff"] = True
    return comp_map

# -----------------------------
# TCP active probe (optional)
# -----------------------------
def _probe_tcp(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, int(port)))
        s.close()
        return True
    except Exception:
        return False

def run_active_probe(comp_map, timeout=0.9, workers=50):
    targets = []
    for host_key, entries in comp_map.get("service_ports", {}).items():
        for idx, e in enumerate(entries):
            if (e.get("proto") or "").lower() != "tcp": 
                continue
            ip = e.get("ip")
            port = e.get("port")
            if ip is None or port is None: 
                continue
            ip_probe = "127.0.0.1" if str(ip).startswith("0.0.0.0") else ip
            targets.append((host_key, idx, ip_probe, int(port)))
    if not targets: 
        return comp_map
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_probe_tcp, ip, port, timeout): (hk, idx) for (hk, idx, ip, port) in targets}
        for fut in as_completed(futs):
            hk, idx = futs[fut]
            ok = fut.result()
            try:
                comp_map["service_ports"][hk][idx]["observed_by_probe"] = bool(ok)
            except Exception:
                pass
    return comp_map

# -----------------------------
# Main API (BACKWARD-COMPATIBLE)
# -----------------------------
def map_virtual_components(inv, netns_info, derived_gateways, sniff_iface=None, sniff_duration=0):
    """
    Backward-compatible entrypoint expected by orchestrator.py.
    Writes 'component_map.json' into current working directory.
    """
    start_ts = int(time.time())
    comp_map = {
        "generated_at": start_ts,
        "generator": "mapping.map_virtual_components",
        "inventory_snapshot": inv or {},
        "netns_info": netns_info or {},
        "derived_gateways": derived_gateways or [],
        "service_ports": {},
        "components": []
    }

    # 1) Discover listeners (host)
    listeners = get_ss_listeners()

    # 1b) Per-netns listeners if netns_info provided
    try:
        ns_names = []
        if isinstance(netns_info, dict) and "netns" in netns_info and isinstance(netns_info["netns"], list):
            ns_names = [n.get("name") or n.get("id") for n in netns_info["netns"] if n.get("name") or n.get("id")]
        elif isinstance(netns_info, dict):
            for k, v in netns_info.get("netns", {}).items():
                ns_names.append(k)
        elif isinstance(netns_info, list):
            for n in netns_info:
                ns_names.append(n.get("name") or n.get("id"))
        ns_names = [n for n in set(ns_names) if n]
        for ns in ns_names:
            try:
                listeners.extend(get_ss_listeners_for_netns(ns))
            except Exception:
                continue
    except Exception:
    # swallow netns parsing issues; continue with host listeners
        pass

    comp_map["_listeners_count"] = len(listeners)

    # 2) Build components
    components = build_components_from_listeners(listeners)

    # 3) Passive sniff (robust)
    sniffed_flows = []
    if sniff_duration and int(sniff_duration) > 0:
        try:
            sniffed_flows = sniff_flows(iface=sniff_iface, duration=int(sniff_duration))
            comp_map["_sniff_summary"] = {"sniff_iface": sniff_iface, "sniff_duration": sniff_duration, "flows_captured": len(sniffed_flows)}
        except Exception as e:
            comp_map["_sniff_summary"] = {"error": str(e)}
            sniffed_flows = []
    else:
        comp_map["_sniff_summary"] = {"flows_captured": 0}

    # 4) Attach flows to components and build top-level service_ports by component name
    if sniffed_flows:
        components = attach_flows_to_components(sniffed_flows, components)

    for comp in components:
        comp_name = comp.get("name") or comp.get("id") or "host"
        for sp in comp.get("service_ports", []):
            comp_map.setdefault("service_ports", {}).setdefault(comp_name, []).append({
                "ip": sp.get("ip"),
                "port": sp.get("port"),
                "proto": (sp.get("proto") or "").lower(),
                "process": sp.get("process"),
                "pid": sp.get("pid"),
                "source": sp.get("source", "ss-listener"),
                "observed_in_sniff": False,
                "host": comp_name
            })

    # 5) Mark observed_in_sniff in service_ports (ip+port + fallback)
    if sniffed_flows:
        comp_map = mark_observed_in_service_ports(comp_map, sniffed_flows)

    # 6) Normalize + compute _ports_count
    for host_key, entries in list(comp_map.get("service_ports", {}).items()):
        normalized = []
        for e in entries:
            try:
                e_port = int(e.get("port")) if e.get("port") is not None else None
            except Exception:
                e_port = None
            e_proto = (e.get("proto") or "").lower()
            e_host = e.get("host") or host_key or "host"
            e["port"] = e_port; e["proto"] = e_proto; e["host"] = e_host
            normalized.append(e)
        comp_map["service_ports"][host_key] = normalized

    for comp in components:
        name = comp.get("name") or comp.get("id")
        cnt = 0
        for host_key, arr in comp_map.get("service_ports", {}).items():
            if host_key == name:
                cnt += len(arr)
        if cnt == 0 and isinstance(comp.get("service_ports"), list):
            cnt = len(comp.get("service_ports"))
        comp["_ports_count"] = cnt

    comp_map["components"] = components
    comp_map["_summary"] = {
        "components_count": len(comp_map.get("components", [])),
        "service_ports_hosts": list(comp_map.get("service_ports", {}).keys()),
        "total_service_ports": sum(len(v) for v in comp_map.get("service_ports", {}).values())
    }

    # 7) Optional active probe (enable by default; disable with ORAN_PROBE_AFTER=0)
    if os.getenv("ORAN_PROBE_AFTER", "1") == "1":
        try:
            comp_map = run_active_probe(comp_map, timeout=0.9, workers=50)
            comp_map["_probe_summary"] = {
                "probed_tcp_endpoints": sum(1 for _ in (x for v in comp_map.get("service_ports", {}).values() for x in v if (x.get('proto')=='tcp'))),
                "responsive": sum(1 for v in comp_map.get("service_ports", {}).values() for x in v if (x.get('proto')=='tcp' and x.get('observed_by_probe')))
            }
        except Exception as e:
            comp_map["_probe_summary"] = {"error": str(e)}

    # 8) Write JSON to CWD (orchestrator sets CWD to workdir)
    out_path = "component_map.json"
    with open(out_path, "w") as fo:
        json.dump(comp_map, fo, indent=2)

    return comp_map

# -----------------------------
# CLI (debug)
# -----------------------------
if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default=None)
    ap.add_argument("--duration", type=int, default=0)
    args = ap.parse_args()
    if os.geteuid() != 0:
        print("Warning: run as root for best results")
    # Run minimal discovery+mapping
    m = map_virtual_components(inv={}, netns_info={}, derived_gateways=[], sniff_iface=args.iface, sniff_duration=args.duration)
    print("Wrote component_map.json")

