# CrossLayer-Guard

커널 계층 간 eBPF 트래픽 추적을 통한 파일리스 백도어 탐지 시스템  
(XDP / TC / Socket / Syscall 레이어 이벤트 크로스 분석)

---

## 목차

1. [Features](#features)  
2. [Prerequisites](#prerequisites)  
3. [Installation](#installation)  
4. [Quick Start (CLI)](#quick-start-cli)  
5. [C/C++ API Usage](#cc-api-usage)  
6. [Language Bindings (Go/Python)](#language-bindings-gopython)  
7. [Advanced Configuration](#advanced-configuration)  
8. [Logs & Systemd Integration](#logs--systemd-integration)  
9. [Contributing](#contributing)  

---

## Features

- eBPF 기반 트래픽 탐지: XDP, TC, Socket, Syscall 계층별 추적  
- Generic XDP 및 AF_PACKET 지원  
- 화이트리스트 기반 필터링 (IPv4)  
- 실시간 로그/경보: `[ALERT]`, `[OK]`, `[CTRL]` 등  
- Go / Python 바인딩 제공  
- Systemd 서비스로 실행 가능

---

## Prerequisites

Ubuntu 기준 의존 패키지 설치:

```bash
sudo apt update
sudo apt install -y \
    clang llvm build-essential cmake pkg-config \
    libbpf-dev libelf-dev bpftool \
    nmap-nping socat iproute2
```
## Installation
### 프로젝트 클론
```bash
git clone https://github.com/yourorg/crosslayer-guard.git
cd crosslayer-guard
```
### 빌드 및 설치
```bash
mkdir build && cd build
cmake
make -j$(nproc)
sudo make install
eBPF 오브젝트 파일(.o)은 /usr/local/lib/crosslayer-ebpf/에 설치

clgctl CLI 도구는 /usr/local/bin/에 설치
```
## Quick Start (CLI)
### 화이트리스트 관리
#### IP 추가
```bash
clgctl whitelist add 192.168.0.10
```
#### IP 제거
```bash
clgctl whitelist del 192.168.0.10
```
### 전체 목록 조회
```bash
clgctl whitelist list
```
### 실시간 모니터링
```bash
sudo clgctl /usr/local/lib/crosslayer-ebpf enp0s8
```


## Logs & Systemd Integration
### Systemd 서비스 등록
```bash
sudo systemctl enable crosslayer.service
sudo systemctl start crosslayer.service
```

### 로그 파일 확인:
```bash
tail -f /var/log/clg.log
```

## Contributing
```bash
레포지토리 Fork

브랜치 생성: git checkout -b feature/my-feature

작업 후 커밋: git commit -m "feat: 설명"

PR 생성

```