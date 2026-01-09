#!/usr/bin/env python3
"""
probe_services.py

Usage:
  python3 probe_services.py ./oran_orchestrator_work/component_map.json ./oran_orchestrator_work/component_map_probed.json --timeout 1 --workers 40

Notes:
 - Only TCP connect probes are performed (UDP probing is unreliable without protocol-specific payloads).
 - The script runs non-root; no special privileges required for TCP connect.
 - Use --workers to speed up scanning.
"""
import json, sys, socket, argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

def load_map(path):
    with open(path, "r") as f:
        return json.load(f)

def save_map(obj, path):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)

def gather_targets(comp_map):
    targets = []  # tuples (host_key, ip, port, proto, entry_ref)
    for host_key, entries in comp_map.get("service_ports", {}).items():
        for idx, e in enumerate(entries):
            ip = e.get("ip")
            port = e.get("port")
            proto = (e.get("proto") or "").lower()
            if ip and port and proto == "tcp":
                targets.append((host_key, ip, int(port), proto, (host_key, idx)))
    return targets

def probe_one(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.close()
        return True, None
    except Exception as ex:
        return False, str(ex)

def probe_all(comp_map, timeout=1.0, workers=40):
    targets = gather_targets(comp_map)
    results = {}
    if not targets:
        return comp_map, results
    with ThreadPoolExecutor(max_workers=workers) as exe:
        futures = {}
        for host_key, ip, port, proto, ref in targets:
            fut = exe.submit(probe_one, ip, port, float(timeout))
            futures[fut] = (host_key, ip, port, proto, ref)
        for fut in as_completed(futures):
            host_key, ip, port, proto, (hk, idx) = futures[fut]
            ok, err = fut.result()
            results.setdefault((hk, idx), {"ip": ip, "port": port, "proto": proto, "ok": ok, "err": err})
            # update comp_map in-place (observed_by_probe)
            try:
                comp_map["service_ports"][hk][idx]["observed_by_probe"] = bool(ok)
            except Exception:
                pass
    return comp_map, results

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("infile")
    parser.add_argument("outfile")
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--workers", type=int, default=40)
    args = parser.parse_args()
    comp_map = load_map(args.infile)
    comp_map, results = probe_all(comp_map, timeout=args.timeout, workers=args.workers)
    save_map(comp_map, args.outfile)
    # print a short summary
    total = len(results)
    up = sum(1 for v in results.values() if v["ok"])
    print(f"Probed {total} TCP endpoints: {up} responsive, {total-up} closed/unreachable")
    # Optionally print some responsive endpoints
    for k,v in list(results.items())[:50]:
        if v["ok"]:
            print("OK", v["ip"], v["port"])
    return 0

if __name__ == "__main__":
    sys.exit(main())

