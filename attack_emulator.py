#!/usr/bin/env python3
"""
attack_emulator.py — Safe PCAP emulation for FiGHT techniques.

These functions generate PCAP files to disk that emulate observable packet patterns
for:

 - UE network sniffing (user-plane flows)
 - RAN signaling reconnaissance (small control-plane-like messages)
 - Core signalling flood (many small packets to a core port)

All generation is local and only writes pcap files; no packets are sent on the network.
"""

import time, os
from scapy.all import Ether, IP, IPv6, UDP, TCP, Raw, wrpcap

def ensure_dir(d):
    if not os.path.exists(d):
        os.makedirs(d, exist_ok=True)

def emulate_ue_sniff_pcap(outpath, ue_ips=None, servers=None, count_per_flow=10):
    """
    Create a pcap that looks like multiple UE <-> server flows (DNS-like UDP, TCP handshakes).
    ue_ips: list of UE ips (strings) — defaults to ['127.0.0.10','127.0.0.11']
    servers: list of server ips — defaults to ['127.0.0.200','127.0.0.201']
    """
    ensure_dir(os.path.dirname(outpath) or ".")
    if ue_ips is None:
        ue_ips = ["127.0.0.10", "127.0.0.11"]
    if servers is None:
        servers = ["127.0.0.200", "127.0.0.201"]
    pkts = []
    ts = time.time()
    for ue in ue_ips:
        for srv in servers:
            # small UDP DNS-like exchange
            for i in range(2):
                p1 = IP(src=ue, dst=srv)/UDP(sport=40000+i, dport=53)/Raw(load=b"DNS_QUERY_"+bytes([i]))
                p2 = IP(src=srv, dst=ue)/UDP(sport=53, dport=40000+i)/Raw(load=b"DNS_RESP_"+bytes([i]))
                pkts.append(p1)
                pkts.append(p2)
            # TCP handshake-like small flow
            for n in range(count_per_flow):
                sport = 50000 + n
                dport = 443
                # SYN (placeholder)
                pkts.append(IP(src=ue, dst=srv)/TCP(sport=sport, dport=dport, flags="S")/Raw(load=b""))
                # SYN-ACK
                pkts.append(IP(src=srv, dst=ue)/TCP(sport=dport, dport=sport, flags="SA")/Raw(load=b""))
                # ACK + data
                pkts.append(IP(src=ue, dst=srv)/TCP(sport=sport, dport=dport, flags="A")/Raw(load=b"GET /index"))
    wrpcap(outpath, pkts)
    return outpath

def emulate_ran_locate_ue_pcap(outpath, gnb_ips=None, amf_ip="127.0.0.1", msg_count=200):
    """
    Emulate RAN control-plane signaling pattern: many small messages from gNB IPs to AMF-like port.
    This writes UDP-like short messages to represent many registration/location attempts.
    """
    ensure_dir(os.path.dirname(outpath) or ".")
    if gnb_ips is None:
        gnb_ips = ["127.0.0.5", "127.0.0.6", "127.0.0.7"]
    pkts = []
    base_port = 8805  # arbitrary control-plane-like port for simulation
    for i in range(msg_count):
        src = gnb_ips[i % len(gnb_ips)]
        sport = 30000 + (i % 1000)
        # small payload that looks like a short signalling message
        payload = b"SIG_REG|" + bytes(str(i), "ascii")
        pkts.append(IP(src=src, dst=amf_ip)/UDP(sport=sport, dport=base_port)/Raw(load=payload))
    wrpcap(outpath, pkts)
    return outpath

def emulate_core_flood_pcap(outpath, attacker_ips=None, core_ip="127.0.0.100", packet_count=5000):
    """
    Emulate a large flood targeting a core IP/port. Create many small TCP or UDP packets in the pcap.
    Keep the file on-disk; this function does not transmit packets.
    """
    ensure_dir(os.path.dirname(outpath) or ".")
    if attacker_ips is None:
        attacker_ips = [f"10.201.1.{i}" for i in range(2, 10)]
    pkts = []
    for i in range(packet_count):
        src = attacker_ips[i % len(attacker_ips)]
        sport = 10000 + (i % 40000)
        # use TCP SYN-like representation (no real handshake)
        pkts.append(IP(src=src, dst=core_ip)/TCP(sport=sport, dport=4043, flags="S")/Raw(load=b""))
    wrpcap(outpath, pkts)
    return outpath

# quick CLI convenience
if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default="./oran_orchestrator_work/attacks")
    ap.add_argument("--which", choices=["ue","ran","core","all"], default="all")
    args = ap.parse_args()
    ensure_dir(args.outdir)
    if args.which in ("ue","all"):
        p = os.path.join(args.outdir, "ue_sniff.pcap")
        print("writing", emulate_ue_sniff_pcap(p))
    if args.which in ("ran","all"):
        p = os.path.join(args.outdir, "ran_locate_ue.pcap")
        print("writing", emulate_ran_locate_ue_pcap(p))
    if args.which in ("core","all"):
        p = os.path.join(args.outdir, "core_flood.pcap")
        print("writing", emulate_core_flood_pcap(p, packet_count=2000))

