#ifndef MAX_IDS
#define MAX_IDS 1024
#endif

#include "crosslayer.h"
#include <arpa/inet.h>    // inet_ntop, ntohs
#include <bpf/libbpf.h>
#include <csignal>
#include <iostream>
#include "ctrl_event.h"
#include "record.h"

// ID별 레이어 플래그 저장
static uint8_t mask_map[MAX_IDS] = {};

static volatile bool exiting = false;
static void sig_int(int) { exiting = true; }

// 무해한 트래픽 판단 (DNS, DHCP, NTP, syslog, mDNS/LLMNR, NetBIOS)
static bool is_benign_traffic(uint8_t proto, uint16_t dport) {
    if (dport == 53 || dport == 67 || dport == 68) return true;
    if (dport == 123 || dport == 514)            return true;
    if (dport == 5353 || dport == 5355)          return true;
    if (dport == 137  || dport == 138  || dport == 139) return true;
    return false;
}

// XDP 콜백: 패킷 레이어 이벤트 기록 및 출력
static void handle_xdp(void *ctx, int cpu, void *data, __u32 sz) {
    auto *e = (rec_event *)data;
    uint32_t idx = e->id & (MAX_IDS - 1);
    mask_map[idx] |= (1 << 0);

    const auto &m = e->md;
    char s_src[INET_ADDRSTRLEN], s_dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &m.src_ip, s_src, sizeof(s_src));
    inet_ntop(AF_INET, &m.dst_ip, s_dst, sizeof(s_dst));

    std::cout << "[XDP]  "
              << s_src << ":" << ntohs(m.src_port)
              << " -> "
              << s_dst << ":" << ntohs(m.dst_port)
              << " proto=" << int(m.proto)
              << " id="    << e->id
              << " mask=0x" << std::hex << int(mask_map[idx]) << std::dec
              << "\n";
}

// TC 콜백: 패킷 레이어 이벤트 기록 및 출력
static void handle_tc(void *ctx, int cpu, void *data, __u32 sz) {
    auto *e = (rec_event *)data;
    uint32_t idx = e->id & (MAX_IDS - 1);
    mask_map[idx] |= (1 << 1);

    const auto &m = e->md;
    char s_src[INET_ADDRSTRLEN], s_dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &m.src_ip, s_src, sizeof(s_src));
    inet_ntop(AF_INET, &m.dst_ip, s_dst, sizeof(s_dst));

    std::cout << "[TC ]  "
              << s_src << ":" << ntohs(m.src_port)
              << " -> "
              << s_dst << ":" << ntohs(m.dst_port)
              << " proto=" << int(m.proto)
              << " id="    << e->id
              << " mask=0x" << std::hex << int(mask_map[idx]) << std::dec
              << "\n";
}

// SOCK 콜백: 패킷 레이어 이벤트 기록 및 출력
static void handle_sock(void *ctx, int cpu, void *data, __u32 sz) {
    auto *e = (rec_event *)data;
    uint32_t idx = e->id & (MAX_IDS - 1);
    mask_map[idx] |= (1 << 2);

    const auto &m = e->md;
    char s_src[INET_ADDRSTRLEN], s_dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &m.src_ip, s_src, sizeof(s_src));
    inet_ntop(AF_INET, &m.dst_ip, s_dst, sizeof(s_dst));
    if (m.src_ip == m.dst_ip && m.src_port == m.dst_port)
        return;
    std::cout << "[SOCK] "
              << s_src << ":" << ntohs(m.src_port)
              << " -> "
              << s_dst << ":" << ntohs(m.dst_port)
              << " proto=" << int(m.proto)
              << " id="    << e->id
              << " mask=0x" << std::hex << int(mask_map[idx]) << std::dec
              << "\n";
}

// CTRL 콜백: 시스템 콜 이벤트 수신 후 크로스-레이어 검증 및 출력
static void handle_ctrl(void *ctx, int cpu, void *data, __u32 sz) {
    auto *e = (ctrl_event *)data;
    uint32_t full_id = e->id;
    if (full_id == 0) return;

    uint32_t idx   = full_id & (MAX_IDS - 1);
    uint8_t  m_val = mask_map[idx];
    uint8_t  proto = e->proto;
    uint16_t dport = full_id & 0xFFFF;

    std::cout << "[CTRL] id="    << full_id
              << " code="       << int(e->code)
              << " proto="      << int(proto)
              << " dport="      << dport
              << " mask=0x"     << std::hex << int(m_val) << std::dec
              << "\n";

    // Cross-layer Validation
    if ((m_val & 0x07) == 0) {
        if (is_benign_traffic(proto, dport)) {
            std::cout << "[INFO ] benign syscall-only: id=" << full_id
                      << " proto=" << int(proto)
                      << " dport=" << dport
                      << "\n";
        } else {
            std::cout << "[ALERT] invisible syscall-only: id=" << full_id
                      << " proto=" << int(proto)
                      << " dport=" << dport
                      << "\n";
        }
    } else if (!(m_val & ((1 << 0) | (1 << 1)))) {
        std::cout << "[ALERT] bypassed packet-layers: id=" << full_id
                  << " mask=0x" << std::hex << int(m_val) << std::dec
                  << "\n";
    } else if (!(m_val & (1 << 2))) {
        std::cout << "[ALERT] no socket-layer: id=" << full_id
                  << " mask=0x" << std::hex << int(m_val) << std::dec
                  << "\n";
    } else {
        std::cout << "[OK   ] matched flow: id=" << full_id
                  << " mask=0x" << std::hex << int(m_val) << std::dec
                  << "\n";
    }

    mask_map[idx] = 0;
}

// 손실된 이벤트 보고
static void handle_lost(void *ctx, int cpu, __u64 cnt) {
    std::cerr << "[LOST] " << cnt << " events on CPU " << cpu << "\n";
}

clg_error_t clg_start_aggregator(clg_handle_t *h) {
    if (!h) return CLG_ERR_INVALID_ARG;
    // Extract perf-map FDs from handle
    int fd_xdp  = h->fd_xdp;
    int fd_tc   = h->fd_tc;
    int fd_sock = h->fd_sock;
    int fd_ctrl = h->fd_ctrl;

    struct perf_buffer *pb_xdp  = nullptr;
    struct perf_buffer *pb_tc   = nullptr;
    struct perf_buffer *pb_sock = nullptr;
    struct perf_buffer *pb_ctrl = nullptr;
    struct perf_buffer_opts opts = {};

    opts.sample_cb = handle_xdp;
    opts.lost_cb   = handle_lost;
    pb_xdp = perf_buffer__new(fd_xdp,  8, &opts);

    opts.sample_cb = handle_tc;
    pb_tc   = perf_buffer__new(fd_tc,   8, &opts);

    opts.sample_cb = handle_sock;
    pb_sock = perf_buffer__new(fd_sock, 8, &opts);

    opts.sample_cb = handle_ctrl;
    pb_ctrl = perf_buffer__new(fd_ctrl, 8, &opts);

    if (!pb_xdp || !pb_tc || !pb_sock || !pb_ctrl) {
        std::cerr << "perf_buffer setup failed\n";
        return CLG_ERR_AGGREGATOR;
    }

    std::signal(SIGINT, sig_int);
    std::signal(SIGTERM, sig_int);

    std::cout << "Starting event loop (Ctrl-C to exit)...\n";
    while (!exiting) {
        perf_buffer__poll(pb_xdp,  100);
        perf_buffer__poll(pb_tc,   100);
        perf_buffer__poll(pb_sock, 100);
        perf_buffer__poll(pb_ctrl, 100);
    }

    perf_buffer__free(pb_xdp);
    perf_buffer__free(pb_tc);
    perf_buffer__free(pb_sock);
    perf_buffer__free(pb_ctrl);
    return CLG_OK;
}