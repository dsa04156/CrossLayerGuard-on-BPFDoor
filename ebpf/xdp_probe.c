// File: ebpf/xdp_probe.c

#include "common.h"
#include <linux/if_link.h>    // XDP_FLAGS_* definitions
#include <linux/if_ether.h>   // ETH_P_IP, struct ethhdr
#include <linux/ip.h>         // struct iphdr
#include <linux/udp.h>        // struct udphdr, IPPROTO_UDP
#include <linux/tcp.h>        // struct tcphdr, IPPROTO_TCP
#include <linux/in.h>         // AF_INET

SEC("xdp")
int xdp_record(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr  *ip;
    struct pkt_md  md = {};

    /* Ethernet + IPv4 검사 */
    if ((void*)(eth + 1) > data_end)                return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    /* IP 헤더 파싱 */
    ip = (void*)eth + sizeof(*eth);
    if ((void*)(ip + 1) > data_end)                 return XDP_PASS;
    md.src_ip = ip->saddr;
    md.dst_ip = ip->daddr;
    md.proto  = ip->protocol;

    /* ── 화이트리스트 검사 ─────────────────────────────────────────── */
    // 네트워크 바이트 오더 그대로 키로 사용
    __u32 src_h = __builtin_bswap32(md.src_ip);
    if (bpf_map_lookup_elem(&whitelist_ips, &src_h))
        return XDP_PASS;
    __u32 dst_h_key = __builtin_bswap32(md.dst_ip);
    if (bpf_map_lookup_elem(&whitelist_ips, &dst_h_key))
        return XDP_PASS;
    /* ───────────────────────────────────────────────────────────────── */

    /* L4 헤더 파싱 */
    if (md.proto == IPPROTO_UDP) {
        struct udphdr *udp = (void*)ip + ip->ihl * 4;
        if ((void*)(udp + 1) > data_end)            goto out;
        md.src_port = udp->source;
        md.dst_port = udp->dest;
    } else if (md.proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void*)ip + ip->ihl * 4;
        if ((void*)(tcp + 1) > data_end)            goto out;
        md.src_port = tcp->source;
        md.dst_port = tcp->dest;
    }

out:
    {
        /* 네트워크 바이트 오더 → 호스트 바이트 오더 변환 후 ID 생성 */
        __u32 dst_h   = __builtin_bswap32(md.dst_ip);
        __u16 dport_h = __builtin_bswap16(md.dst_port);
        __u32 id      = (dst_h << 16) | dport_h;

        struct rec_event evt = {
            .id = id,
            .md = md,
        };
        /* 유저스페이스로 ID+메타데이터 전송 */
        bpf_perf_event_output(ctx, &events,
                              BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    }

    return XDP_PASS;
}

// (라이선스 섹션은 common.h에서 선언되어 있으니 여기서는 제거)
