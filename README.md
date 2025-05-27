# CrossLayer Guard

CrossLayer Guard is an eBPF-based cross-layer network and system call validation library that detects magic-packet attacks and hidden system call attacks (e.g., BPFdoor) in real time.

---

## Table of Contents

1. [How It Works](#how-it-works)  
2. [Features](#features)  
3. [Prerequisites](#prerequisites)  
4. [Installation](#installation)  
5. [Quick Start (CLI)](#quick-start-cli)  
6. [C/C++ API Usage](#cc-api-usage)  
7. [Language Bindings (Go/Python)](#language-bindings-gopython)  
8. [Advanced Configuration](#advanced-configuration)  
9. [Logs & Systemd Integration](#logs--systemd-integration)  
10. [Contributing](#contributing)  

---

## How It Works

CrossLayer Guard tracks each network flow across four kernel layers to detect anomalies:

- **XDP layer**: Captures packets at the earliest point (before the kernel network stack) and assigns a flow ID.  
- **TC Ingress layer**: Records the same flow ID after L2/L3 processing.  
- **Socket layer**: Hooks socket send operations and logs the flow ID when packets exit via sockets.  
- **Syscall (Control-plane)**: Intercepts user-space `connect()` and `sendto()` syscalls and records metadata under the same flow ID.  

In user space, an aggregator maintains a bitmask (`mask_map`) for each flow ID:  
- bit 0 for XDP  
- bit 1 for TC  
- bit 2 for Socket  

When a syscall event arrives, it evaluates the bitmask:

- `mask == 0`: No packet seen but syscall occurred → **invisible syscall-only** alert  
- `(mask & (1<<0 | 1<<1)) == 0`: Packet-layer bypass → **bypassed packet-layers** alert  
- `(mask & (1<<2)) == 0`: Missing socket layer → **no socket-layer** alert  
- Otherwise: Flow is consistent → **OK** log  

This cross-layer validation effectively detects stealthy or forged flows such as BPFdoor attacks.

---

## Features

- Cross-layer tracking: XDP, TC Ingress, Socket filter, and Syscall probes  
- White-list filtering for IPv4 addresses  
- Real-time alerts: `[ALERT]`, `[INFO]`, `[OK]`, `[LOST]`  
- Static library (`libclg_user.a`) and CLI tool (`clgctl`)  
- Go and Python language bindings  
- Systemd service support for background execution  

---

## Prerequisites

- Linux kernel version ≥ 5.x with BPF CO-RE support  
- Build tools: `clang`, `llvm`, `cmake` (≥ 3.15), `make`, `pkg-config`  
- Development libraries: `libbpf-dev`, `libelf-dev`, `bpftool`  
- Optional utilities for CLI testing: `nmap-nping`, `socat`, `iproute2`  

Example (Ubuntu):
```bash
sudo apt update
sudo apt install -y \
    clang llvm build-essential cmake pkg-config \
    libbpf-dev libelf-dev linux-tools-common \
    nmap-nping socat iproute2
```

## Installation

1. Clone the repository and navigate to the project directory:  
```bash
git clone https://github.com/yourorg/crosslayer-guard.git
cd crosslayer-guard
```

2. Build and install:
```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
sudo make install
```
- eBPF object files (.o) are installed to /usr/local/lib/crosslayer-ebpf/

- The CLI tool clgctl is installed to /usr/local/bin/

- The static library libclg_user.a is installed to /usr/local/lib/

## Quick Start (CLI)

### Manage Whitelist
```bash
# List current whitelist entries
clgctl whitelist list

# Add an IP to the whitelist
clgctl whitelist add 10.1.1.1

# Remove an IP from the whitelist
clgctl whitelist del 10.1.1.1
```

### Run Monitoring
```bash
# Start monitoring on interface enp0s8
sudo clgctl /usr/local/lib/crosslayer-ebpf enp0s8
```
Real-time logs appear with tags [XDP], [TC], [SOCK], [CTRL], [ALERT], and [OK].

## Advanced Configuration
- Adjust MAX_IDS (default 1024) in include/record.h for maximum concurrent flows

- Modify log output format in src/aggregator.cpp

- Edit eBPF programs in ebpf/ and rebuild with make all_bpf

## Logs & Systemd Integration
To run as a systemd service:

```bash
sudo systemctl enable crosslayer.service
sudo systemctl start crosslayer.service
```

Logs are written to /var/log/clg.log and /var/log/clg.err:
```bash
tail -f /var/log/clg.log
```

## ERROR
###  'asm/types.h' file not found
```bash
ls -l /usr/include/asm
```
This showed that the link was pointing to aarch64-linux-gnu/asm, which is for ARM architectures. My system is x86_64, so this was wrong.

Find the correct asm/types.h I searched for types.h files in the asm directories:

find /usr/include -name "types.h" | grep asm
This pointed me to /usr/include/x86_64-linux-gnu/asm/types.h.

Fix the symbolic link I removed the incorrect link and created a new one pointing to the correct directory:
```bash
sudo rm /usr/include/asm
sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
```
Verify the fix I ran:
```bash
ls -l /usr/include/asm
```
Now the link points to /usr/include/x86_64-linux-gnu/asm.

Retry the command After this, running go generate worked perfectly without any errors.
