#!/bin/bash
set -euo pipefail
cd ~/kintsugi-dev
source .venv/bin/activate

# Ubuntu .bashrc returns early in non-interactive shells; load user config explicitly
if [ -z "${DEEPSEEK_API_KEY:-}" ]; then
  eval "$(grep 'export DEEPSEEK_API_KEY=' ~/.bashrc | tail -1)"
fi
if [ -z "${DEEPSEEK_MODEL:-}" ]; then
  eval "$(grep 'export DEEPSEEK_MODEL=' ~/.bashrc | tail -1 || true)"
fi
if [ -z "${LLM_PROVIDER:-}" ]; then
  eval "$(grep 'export LLM_PROVIDER=' ~/.bashrc | tail -1 || true)"
fi

echo "KEY_LEN=${#DEEPSEEK_API_KEY}"
echo "MODEL=${DEEPSEEK_MODEL:-unset}"
echo "PROVIDER=${LLM_PROVIDER:-unset}"

if [ -z "${DEEPSEEK_API_KEY:-}" ]; then
  echo "ERROR: DEEPSEEK_API_KEY not found in environment or ~/.bashrc"
  exit 1
fi

python main.py --cve CVE-2025-2945 --stage 8 \
  --repair-mode filter \
  --whitelist-mode static \
  --threshold 0.5
