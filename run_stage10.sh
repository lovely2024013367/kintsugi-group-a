#!/bin/bash
set -euo pipefail
cd ~/kintsugi-dev
source .venv/bin/activate

if [ -z "${DEEPSEEK_API_KEY:-}" ]; then
  eval "$(grep 'export DEEPSEEK_API_KEY=' ~/.bashrc | tail -1)"
fi

if ! pgrep -f 'syscall_filter/ebpf_load.py' >/dev/null; then
  echo "WARNING: eBPF loader not running. Start it in another terminal:"
  echo "  sudo python3 ~/kintsugi-dev/syscall_filter/ebpf_load.py"
fi

python main.py --cve CVE-2023-5002 --stage 10 --validate-mode all --wait-time 90
