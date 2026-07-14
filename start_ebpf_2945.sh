#!/bin/bash
set -euo pipefail

# Kill any existing loader
pkill -f '/home/liuyang/kintsugi-dev/syscall_filter/ebpf_load.py' 2>/dev/null || true
sudo -n pkill -f '/home/liuyang/kintsugi-dev/syscall_filter/ebpf_load.py' 2>/dev/null || true
sleep 1

LOG=/tmp/ebpf_load_2945.log
rm -f "$LOG"

# Start with passwordless sudo for the exact allowed command
nohup sudo -n /usr/bin/python3 /home/liuyang/kintsugi-dev/syscall_filter/ebpf_load.py >"$LOG" 2>&1 &
echo "PID=$!"
sleep 8
echo "---- log ----"
tail -40 "$LOG" || true
echo "---- procs ----"
pgrep -af 'ebpf_load.py' || echo 'NO_PROCESS'
