#!/usr/bin/env bash
set -euo pipefail
WD=./oran_orchestrator_work
mkdir -p "$WD"
echo "[+] host ss capture"
sudo ss -lntup > "$WD/host_ss.txt" || true
echo "[+] netns captures"
sudo ip netns list | awk '{print $1}' | while read -r ns; do
  sudo ip netns exec "$ns" ss -lntup > "$WD/${ns}_ss.txt" || true
done
echo "[+] regenerate netns_info.json"
sudo python3 - <<'PY'
from orchestrator import collect_netns_info
collect_netns_info()
PY
echo "[+] run mapping"
python3 - <<'PY'
import mapping, common, os
inv = common.load_json_if_exists('inventory.json') or {'hosts':[]}
netns = common.load_json_if_exists(os.path.join(common.ensure_work_dir(),'netns_info.json')) or {'netns':{}}
mapping.map_virtual_components(inv, netns.get('netns',{}), {})
print("mapping done")
PY
echo "[+] finished"
