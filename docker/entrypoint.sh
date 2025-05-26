#!/bin/bash
set -e

# 1) bpffs 마운트
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

# 2) clgctl 실행 (default: start)
exec clgctl start
