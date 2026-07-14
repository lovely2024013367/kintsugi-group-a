#!/bin/bash
set -euo pipefail
cd ~/kintsugi-dev
source .venv/bin/activate

# Ubuntu .bashrc returns early in non-interactive shells; load user config explicitly
if [ -z "${DEEPSEEK_API_KEY:-}" ]; then
  eval "$(grep 'export DEEPSEEK_API_KEY=' ~/.bashrc | tail -1)"
fi

if [ -z "${DEEPSEEK_API_KEY:-}" ]; then
  echo "ERROR: DEEPSEEK_API_KEY not found in environment or ~/.bashrc"
  exit 1
fi
echo "KEY_LEN=${#DEEPSEEK_API_KEY}"

python main.py --cve CVE-2023-5002 --stage 8-10 \
  --repair-mode filter \
  --whitelist-mode static \
  --threshold 0.5 \
  --validate-mode all
