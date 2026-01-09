#!/usr/bin/env python3
"""
Netns inspection, listener capture inside netns and derivation of UE gateways.

This version expects run_cmd_capture to return (rc, stdout, stderr).
"""

from common import ensure_work_dir, run_cmd_capture, now_ts
import os, json, logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def list_netns_and_veths():
    ns = []
    rc, out, err = run_cmd_capture("ip netns list 2>/dev/null || true", timeout=3)
    if rc == 0 and out:
        for line in out.splitlines():
            part = line.strip()
            if part:
                ns.append(part.split()[0])
    else:
        # No netns or permission issue — return empty list (not fatal)
        if err and not out:
            logging.debug("ip netns list stderr: %s", err)
    veths = []
    rc2, out2, err2 = run_cmd_capture("ip -o link show 2>/dev/null", timeout=3)
    if rc2 == 0 and out2:
        for line in out2.splitlines():
            # parse interface name
            if ':' in line:
                first = line.split(':', 2)[1].strip()
            else:
                first = line
            parts = first.split()
            if parts:
                name = parts[0]
                if name.startswith("v-") or name.startswith("veth") or "@if" in name:
                    veths.append({"raw": line, "name": name})
    else:
        if err2 and not out2:
            logging.debug("ip link show stderr: %s", err2)
    return {"netns": ns, "veths": veths}

def inspect_netns(ns):
    result = {"processes": [], "listeners": [], "ips": [], "routes": [], "notes": []}
    # IP addresses
    rc, out, err = run_cmd_capture(f"sudo ip netns exec {ns} ip -o -4 addr show 2>/dev/null || true", timeout=6)
    if rc == 0 and out:
        result["ips"] = [l.strip() for l in out.splitlines() if l.strip()]
    else:
        if err:
            result["notes"].append(f"ip_addr_err:{err.strip()[:200]}")
        else:
            result["notes"].append("no_ips_or_no_permission")
    # routes
    rc, out, err = run_cmd_capture(f"sudo ip netns exec {ns} ip route 2>/dev/null || true", timeout=5)
    if rc == 0 and out:
        result["routes"] = [l.strip() for l in out.splitlines() if l.strip()]
    else:
        if err:
            result["notes"].append(f"ip_route_err:{err.strip()[:200]}")
    # listeners
    rc, out, err = run_cmd_capture(f"sudo ip netns exec {ns} ss -lntup 2>/dev/null || true", timeout=6)
    if rc == 0 and out:
        result["listeners"] = [l.strip() for l in out.splitlines() if l.strip()]
    else:
        if err:
            result["notes"].append(f"ss_err:{err.strip()[:200]}")
    # processes
    rc, out, err = run_cmd_capture(f"sudo ip netns exec {ns} ps -eo pid,comm,args 2>/dev/null || true", timeout=8)
    if rc == 0 and out:
        procs = []
        for l in out.splitlines()[1:]:
            if l.strip():
                procs.append(l.strip())
        result["processes"] = procs
    else:
        if err:
            result["notes"].append(f"ps_err:{err.strip()[:200]}")
    return result

def derive_gateways(netns_details):
    derived = []
    for ns, info in netns_details.items():
        for r in info.get("routes", []):
            parts = r.split()
            if len(parts) >= 3 and parts[0] == "default" and parts[1] == "via":
                gw = parts[2]
                derived.append({
                    "name": f"{ns}_gateway",
                    "ip": gw,
                    "roles": ["ue_gateway"],
                    "ssh_port": 22,
                    "local_api": False,
                    "ssh_capable": False,
                    "derived_from_netns": ns
                })
    # dedupe by IP
    uniq = {}
    for d in derived:
        uniq[d["ip"]] = d
    return list(uniq.values())

def collect_netns_info():
    wd = ensure_work_dir()
    netns_info = {"timestamp": now_ts(), "netns": {}}
    listing = list_netns_and_veths()
    for ns in listing.get("netns", []):
        try:
            netns_info["netns"][ns] = inspect_netns(ns)
        except Exception as e:
            logging.warning("inspect_netns failed for %s: %s", ns, e)
            netns_info["netns"][ns] = {"notes": [f"inspect_failed:{e}"]}
    outp = os.path.join(wd, "netns_info.json")
    try:
        with open(outp, "w") as f:
            json.dump(netns_info, f, indent=2)
        logging.info("Netns info written to %s", outp)
    except Exception as e:
        logging.warning("Failed to write netns_info.json: %s", e)
    derived = derive_gateways(netns_info["netns"])
    return netns_info, derived

if __name__ == "__main__":
    ni, derived = collect_netns_info()
    print("Netns info and derived gateways written to", ensure_work_dir())

