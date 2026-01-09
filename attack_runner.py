#!/usr/bin/env python3
"""
attack_runner.py

Central runner to create emulated PCAPs (using attack_emulator.py), analyze them,
and write per-attack result JSON files in the workdir.

Produces files:
 - workdir/attacks/<attack_name>.pcap
 - workdir/attacks/<attack_name>.summary.json

Also writes aggregated workdir/attacks/summary.json for the dashboard.
"""

import os, json, time
from collections import Counter
from scapy.all import rdpcap
from attack_emulator import emulate_ue_sniff_pcap, emulate_ran_locate_ue_pcap, emulate_core_flood_pcap

def analyze_pcap(path, max_preview=20):
    pkts = rdpcap(path)
    total = len(pkts)
    flows = set()
    src_count = Counter()
    dst_count = Counter()
    preview = []
    for i, p in enumerate(pkts):
        ip = p.getlayer("IP")
        if ip:
            src = ip.src; dst = ip.dst
            sport = None; dport = None; proto = None
            if p.haslayer("TCP"):
                proto = "tcp"; sport = int(p["TCP"].sport); dport = int(p["TCP"].dport)
            elif p.haslayer("UDP"):
                proto = "udp"; sport = int(p["UDP"].sport); dport = int(p["UDP"].dport)
            else:
                proto = "ip"
            flows.add((src, dst, sport, dport, proto))
            src_count[src] += 1
            dst_count[dst] += 1
            if len(preview) < max_preview:
                preview.append({"src": src, "dst": dst, "sport": sport, "dport": dport, "proto": proto, "len": len(p)})
    return {
        "path": path,
        "total_packets": total,
        "unique_flows": len(flows),
        "top_src": src_count.most_common(5),
        "top_dst": dst_count.most_common(5),
        "preview": preview
    }

def run_all(workdir="./oran_orchestrator_work"):
    attacks_dir = os.path.join(workdir, "attacks")
    os.makedirs(attacks_dir, exist_ok=True)
    results = {}
    # 1) UE sniff pcap
    ue_pcap = os.path.join(attacks_dir, "ue_sniff.pcap")
    emulate_ue_sniff_pcap(ue_pcap)
    results["ue_sniff"] = analyze_pcap(ue_pcap)
    with open(os.path.join(attacks_dir, "ue_sniff.summary.json"), "w") as fh:
        json.dump(results["ue_sniff"], fh, indent=2)
    # 2) RAN locate UE pcap
    ran_pcap = os.path.join(attacks_dir, "ran_locate_ue.pcap")
    emulate_ran_locate_ue_pcap(ran_pcap)
    results["ran_locate_ue"] = analyze_pcap(ran_pcap)
    with open(os.path.join(attacks_dir, "ran_locate_ue.summary.json"), "w") as fh:
        json.dump(results["ran_locate_ue"], fh, indent=2)
    # 3) Core flood pcap
    core_pcap = os.path.join(attacks_dir, "core_flood.pcap")
    emulate_core_flood_pcap(core_pcap, packet_count=2000)
    results["core_flood"] = analyze_pcap(core_pcap)
    with open(os.path.join(attacks_dir, "core_flood.summary.json"), "w") as fh:
        json.dump(results["core_flood"], fh, indent=2)
    # aggregate summary
    agg = {
        "generated_at": int(time.time()),
        "attacks": results
    }
    with open(os.path.join(attacks_dir, "summary.json"), "w") as fh:
        json.dump(agg, fh, indent=2)
    print("Attack emulation + analysis done. Results in", attacks_dir)
    return agg

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", default="./oran_orchestrator_work")
    args = ap.parse_args()
    run_all(workdir=args.workdir)

