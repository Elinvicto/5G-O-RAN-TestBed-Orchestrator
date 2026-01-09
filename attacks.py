# attacks.py
#!/usr/bin/env python3
"""
Attack simulation functions (safe-by-default).
"""
from common import CONFIG, now_ts, ensure_work_dir
import subprocess, threading, time, logging, os, json

# optional
try:
    import requests
except Exception:
    requests = None

KILL_SWITCH = {"triggered": False}

def http_get(url, timeout=5):
    if requests is None:
        return None, "requests-not-installed"
    try:
        r = requests.get(url, timeout=timeout)
        return r.status_code, r.text
    except Exception as e:
        return None, str(e)

def monitor_and_maybe_kill(thresholds, duration_s=60):
    # lightweight placeholder (detailed psutil-based monitor in main orchestrator)
    time.sleep(duration_s/2)
    return

def attack_ue_malformed_attach(target_host, safe=True):
    info = {"name":"ue_malformed_attach","target":target_host,"safe":safe,"started":now_ts(),"result":None}
    emu_ip = target_host["ip"]
    url = f"http://{emu_ip}:{CONFIG['emulator_api_port']}/emulator/test_inject"
    if target_host.get("local_api") or target_host.get("ip")==CONFIG.get("orchestrator_host_ip"):
        status, text = http_get(url, timeout=5)
        info["result"] = {"status":status,"out":text}
    else:
        if not target_host.get("ssh_capable", True):
            info["result"] = {"error":"target not ssh_capable"}
        else:
            try:
                p = subprocess.run(f"curl -s -m 5 {url} || echo 'no_emulator_api'", shell=True, capture_output=True, text=True, timeout=10)
                info["result"] = {"rc":p.returncode,"out":p.stdout,"err":p.stderr}
            except Exception as e:
                info["result"] = {"error":str(e)}
    info["finished"] = now_ts()
    return info

def attack_ran_api_misconfig(target_host, safe=True):
    info = {"name":"ran_api_misconfig","target":target_host,"safe":safe,"started":now_ts(),"result":None}
    ip = target_host["ip"]
    url = f"http://{ip}:{CONFIG['emulator_api_port']}/api/v1/config"
    if target_host.get("local_api") or target_host.get("ip")==CONFIG.get("orchestrator_host_ip"):
        status, text = http_get(url, timeout=5)
        info["result"] = {"status":status,"out":text}
    else:
        if not target_host.get("ssh_capable", True):
            info["result"] = {"error":"target not ssh_capable"}
        else:
            try:
                p = subprocess.run(f"curl -s -m 5 {url} || echo 'no_api'", shell=True, capture_output=True, text=True, timeout=10)
                info["result"] = {"rc":p.returncode,"out":p.stdout,"err":p.stderr}
            except Exception as e:
                info["result"] = {"error":str(e)}
    info["finished"] = now_ts()
    return info

def attack_core_resource_flood(target_host, safe=True, duration=15):
    info = {"name":"core_resource_flood","target":target_host,"safe":safe,"started":now_ts(),"result":None}
    ip = target_host["ip"]
    rate = "20M" if safe else "1000M"
    try:
        p = subprocess.run(f"iperf3 -c {ip} -t {duration} -b {rate}", shell=True, capture_output=True, text=True, timeout=duration+20)
        info["result"] = {"rc":p.returncode,"out":p.stdout[:2000],"err":p.stderr[:2000],"rate":rate}
    except Exception as e:
        info["result"] = {"error":str(e)}
    info["finished"] = now_ts()
    return info
