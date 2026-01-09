# discover.py
#!/usr/bin/env python3
"""
Discovery and baseline collection (uses common.py)
"""
from common import CONFIG, ensure_work_dir, load_inventory, run_cmd_capture, now_ts, load_json_if_exists
import os, json, logging

# optional
try:
    import psutil
except Exception:
    psutil = None

def ssh_exec_placeholder(*args, **kwargs):
    # This module avoids paramiko import — ssh_exec is implemented in other modules if needed.
    return -1, "", "ssh-not-implemented-in-discover"

def is_local_host(ip):
    if ip in ("127.0.0.1", "localhost"):
        return True
    orch_ip = CONFIG.get("orchestrator_host_ip")
    return orch_ip is not None and ip == orch_ip

def discover_from_inventory(inv):
    discovered = {"hosts": []}
    for h in inv.get("hosts", []):
        ip = h["ip"]
        ssh_capable = h.get("ssh_capable", True)
        logging.info("Probing %s (%s) ssh_capable=%s", h["name"], ip, ssh_capable)
        if h.get("local_api") or is_local_host(ip) or not ssh_capable:
            discovered_info = {"name": h["name"], "ip": ip, "roles": h.get("roles", []), "ssh_ok": ssh_capable and is_local_host(ip), "uname": "local_or_api_or_not_ssh", "ssh_err": ""}
        else:
            # fallback: try ping-like check using nc or ping
            status, out = run_cmd_capture(f"timeout 2 bash -c '</dev/tcp/{ip}/22' && echo ok || echo no")
            discovered_info = {"name": h["name"], "ip": ip, "roles": h.get("roles", []), "ssh_ok": "ok" in out, "uname": "", "ssh_err": ""}
        discovered["hosts"].append(discovered_info)
    discovered["timestamp"] = now_ts()
    wd = ensure_work_dir()
    with open(os.path.join(wd, "discovery.json"), "w") as f:
        json.dump(discovered, f, indent=2)
    return discovered

def collect_host_resources(ip, ssh_capable=True, local_api=False):
    if is_local_host(ip) or local_api:
        if psutil is None:
            return {"cpu": None, "mem": None, "net_io": None, "err": "psutil-not-installed"}
        try:
            return {"cpu": psutil.cpu_percent(interval=1), "mem": psutil.virtual_memory().percent, "net_io": psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv}
        except Exception as e:
            return {"cpu": None, "mem": None, "net_io": None, "err": f"local-psutil-err:{e}"}
    # not ssh_capable -> can't collect
    if not ssh_capable:
        return {"cpu": None, "mem": None, "net_io": None, "err": "ssh-not-attempted-not-ssh_capable"}
    # otherwise fallback: basic ping-check
    return {"cpu": None, "mem": None, "net_io": None, "err": "ssh-required-for-remote-resource"}

def collect_baseline(inv):
    wd = ensure_work_dir()
    baseline = {"hosts": {}, "timestamp": now_ts()}
    for h in inv.get("hosts", []):
        ip = h["ip"]
        logging.info("Collecting baseline for %s (%s)", h["name"], ip)
        res = collect_host_resources(ip, ssh_capable=h.get("ssh_capable", True), local_api=h.get("local_api", False))
        baseline["hosts"][h["name"]] = {"ip": ip, "roles": h.get("roles", []), "resources": res}
        # local logs only
        if is_local_host(ip) or h.get("local_api"):
            try:
                if os.path.exists("/var/log/syslog"):
                    with open("/var/log/syslog", "r", errors="ignore") as lf:
                        tail = ''.join(lf.readlines()[-200:])
                elif os.path.exists("/var/log/messages"):
                    with open("/var/log/messages", "r", errors="ignore") as lf:
                        tail = ''.join(lf.readlines()[-200:])
                else:
                    tail = ""
            except Exception as e:
                tail = f"error_reading_local_logs:{e}"
            baseline["hosts"][h["name"]]["logs_tail"] = tail[:10000]
        else:
            baseline["hosts"][h["name"]]["logs_tail"] = ""
    with open(os.path.join(ensure_work_dir(), "baseline.json"), "w") as f:
        json.dump(baseline, f, indent=2)
    return baseline

if __name__ == "__main__":
    inv = load_inventory(CONFIG["inventory_file"])
    d = discover_from_inventory(inv)
    b = collect_baseline(inv)
    print("Discovery and baseline complete. Files written to", ensure_work_dir())
