#!/bin/bash
set -euo pipefail
cd ~/kintsugi-dev
source .venv/bin/activate

if [ -z "${DEEPSEEK_API_KEY:-}" ]; then
  eval "$(grep 'export DEEPSEEK_API_KEY=' ~/.bashrc | tail -1 || true)"
fi

if ! pgrep -f 'syscall_filter/ebpf_load.py' >/dev/null; then
  echo "ERROR: eBPF loader not running. Start it first:"
  echo "  sudo python3 ~/kintsugi-dev/syscall_filter/ebpf_load.py"
  exit 1
fi

echo "eBPF loader is running"
python main.py --cve CVE-2025-2945 --stage 10 --validate-mode all --wait-time 90
