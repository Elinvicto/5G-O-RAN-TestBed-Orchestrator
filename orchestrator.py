#!/usr/bin/env python3
"""
orchestrator.py

Driver for the ORAN security orchestrator. This version integrates with
mapping.map_virtual_components(..., sniff_iface=..., sniff_duration=...) so
the orchestrator can optionally sniff with Scapy while building component_map.json.

Usage:
    sudo python3 orchestrator.py --prepare [--sniff-iface IFACE] [--sniff-duration SECONDS]

Notes:
 - Run as root for best results if sniffing is enabled.
 - Scapy is optional; mapping will still run without sniffing.
"""

import os
import sys
import argparse
import json
import traceback
from datetime import datetime

# Import helper functions from your repo's common.py
# ensure_work_dir() -> creates and returns working directory path
# write_json(path, obj) -> writes JSON safely
# load_json_if_exists(path) -> returns parsed JSON or None
try:
    from common import ensure_work_dir, write_json, load_json_if_exists, now_ts
except Exception as e:
    # If common.py is missing or broken, we still provide minimal fallback functions
    def ensure_work_dir():
        d = "./oran_orchestrator_work"
        os.makedirs(d, exist_ok=True)
        return d

    def write_json(path, obj):
        with open(path, "w") as f:
            json.dump(obj, f, indent=2)

    def load_json_if_exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception:
            return None

    def now_ts():
        return int(datetime.utcnow().timestamp())

WORK_DIR = "./oran_orchestrator_work"
INVENTORY_FILE = "inventory.json"
NETNS_INFO_FILE = "netns_info.json"
COMPONENT_MAP_FILENAME = "component_map.json"
DEFAULT_SNIFF_IFACE = "br0"
DEFAULT_SNIFF_DURATION = 0  # seconds; 0 disables sniffing

def load_inventory(wd):
    # Try load from current directory first, then working dir
    paths = [
        os.path.join(os.getcwd(), INVENTORY_FILE),
        os.path.join(wd, INVENTORY_FILE),
    ]
    for p in paths:
        if os.path.isfile(p):
            try:
                with open(p, "r") as fh:
                    return json.load(fh)
            except Exception:
                pass
    return {}

def load_netns_info(wd):
    # Try various locations / formats
    candidates = [
        os.path.join(wd, NETNS_INFO_FILE),
        os.path.join(os.getcwd(), NETNS_INFO_FILE),
        os.path.join(wd, "netns_info.json"),
        os.path.join(os.getcwd(), "netns_info.json"),
    ]
    for p in candidates:
        if os.path.isfile(p):
            try:
                with open(p, "r") as fh:
                    return json.load(fh)
            except Exception:
                pass
    # fallback: try to import netns_info module if present (some repos include a helper)
    try:
        import netns_info as ninfo_mod
        if hasattr(ninfo_mod, "get_netns_info"):
            return ninfo_mod.get_netns_info()
    except Exception:
        pass
    return {}

def discover_derived_gateways(inv):
    # Simple heuristic from inventory: collect hosts that look like gateways
    gws = []
    for h in inv.get("hosts", []):
        roles = h.get("roles") or []
        if isinstance(roles, str):
            roles = [roles]
        if any(r.lower() in ("gateway", "gw", "nat", "router") for r in roles):
            gws.append(h)
    return gws

def run_mapping(inv, netns_info, derived_gateways, sniff_iface=None, sniff_duration=0):
    """
    Wrapper around mapping.map_virtual_components that tries sniff-enabled mapping first,
    and falls back to non-sniff mapping on error.
    Returns the resulting component map dict (or None if mapping failed).
    """
    try:
        import mapping
    except Exception as e:
        print("[ERROR] Could not import mapping module:", e)
        traceback.print_exc()
        return None

    # First, try with sniffing enabled if requested
    if sniff_duration and int(sniff_duration) > 0:
        try:
            print(f"[INFO] Running mapping.map_virtual_components with sniff iface={sniff_iface} duration={sniff_duration}s")
            comp_map = mapping.map_virtual_components(inv, netns_info, derived_gateways, sniff_iface=sniff_iface, sniff_duration=sniff_duration)
            print("[INFO] mapping finished (sniff mode)")
            return comp_map
        except Exception as e:
            print("[WARN] mapping failed with sniffing enabled. Falling back to no-sniff mode. Error:", e)
            traceback.print_exc()

    # Fallback: run without sniffing
    try:
        print("[INFO] Running mapping.map_virtual_components without sniffing")
        comp_map = mapping.map_virtual_components(inv, netns_info, derived_gateways, sniff_iface=None, sniff_duration=0)
        print("[INFO] mapping finished (no-sniff mode)")
        return comp_map
    except Exception as e:
        print("[ERROR] mapping failed in no-sniff mode too. Error:", e)
        traceback.print_exc()
        return None

def main():
    parser = argparse.ArgumentParser(description="ORAN orchestrator driver")
    parser.add_argument("--prepare", action="store_true", help="Run the prepare sequence (discover + mapping)")
    parser.add_argument("--sniff-iface", default=None, help=f"Interface to sniff (default env / {DEFAULT_SNIFF_IFACE} / None)")
    parser.add_argument("--sniff-duration", type=int, default=None, help=f"Sniff duration seconds (default {DEFAULT_SNIFF_DURATION})")
    parser.add_argument("--workdir", default=WORK_DIR, help="Working directory for artifacts")
    args = parser.parse_args()

    wd = ensure_work_dir()
    if args.workdir:
        wd = args.workdir
        os.makedirs(wd, exist_ok=True)

    print("[MAIN] Working directory:", wd)

    if not args.prepare:
        print("[MAIN] No action requested. Use --prepare to run discovery + mapping.")
        return

    # Load inventory
    inv = load_inventory(wd)
    if not inv:
        print("[WARN] inventory.json not found or empty. continuing with empty inventory.")
    else:
        print(f"[INFO] Loaded inventory with {len(inv.get('hosts', []))} hosts")

    # Load netns info if available
    netns_info = load_netns_info(wd)
    if netns_info:
        print("[INFO] Loaded netns_info")
    else:
        print("[INFO] No netns_info found; proceeding without netns hints")

    # Derive gateways (simple heuristic)
    derived_gateways = discover_derived_gateways(inv)
    if derived_gateways:
        print(f"[INFO] Derived {len(derived_gateways)} gateway(s) from inventory")

    # sniff settings resolution: precedence CLI arg -> env -> defaults
    sniff_iface = args.sniff_iface if args.sniff_iface is not None else os.environ.get("ORAN_SNIFF_IFACE", DEFAULT_SNIFF_IFACE)
    sniff_duration = args.sniff_duration if args.sniff_duration is not None else int(os.environ.get("ORAN_SNIFF_DURATION", DEFAULT_SNIFF_DURATION))

    # Sanity log
    print(f"[INFO] Sniff settings -> iface: {sniff_iface}, duration: {sniff_duration}s")

    # Run mapping (with sniff integration)
    comp_map = run_mapping(inv, netns_info, derived_gateways, sniff_iface=sniff_iface, sniff_duration=sniff_duration)

    # Write artifacts
    if comp_map:
        try:
            out_path = os.path.join(wd, COMPONENT_MAP_FILENAME)
            write_json(out_path, comp_map)
            print(f"[INFO] Wrote component map to {out_path}")
        except Exception as e:
            # fallback: attempt simple write
            try:
                with open(os.path.join(wd, COMPONENT_MAP_FILENAME), "w") as fh:
                    json.dump(comp_map, fh, indent=2)
                print(f"[INFO] Wrote component map (fallback writer) to {os.path.join(wd, COMPONENT_MAP_FILENAME)}")
            except Exception as e2:
                print("[ERROR] Failed to write component_map.json:", e2)
    else:
        print("[ERROR] Mapping did not produce a component map. See earlier errors.")

    print("[MAIN] Done. Artifacts (if any) are in", wd)

if __name__ == "__main__":
    main()

