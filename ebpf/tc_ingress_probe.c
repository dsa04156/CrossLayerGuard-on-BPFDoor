// File: ebpf/tc_record.c

#include "common.h"
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>  // ETH_P_IP, struct ethhdr
#include <linux/in.h>        // AF_INET
#include <linux/ip.h>        // struct iphdr
#include <linux/pkt_cls.h>   // TC_ACT_OK
#include <linux/tcp.h>       // struct tcphdr, IPPROTO_TCP
#include <linux/udp.h>       // struct udphdr, IPPROTO_UDP

SEC("classifier")
int tc_record(struct __sk_buff *skb) {
    struct ethhdr eth;
    struct iphdr  ip;
    struct pkt_md md = {};
    __u32 offset = 0;

    // 1) Ethernet 헤더 로드
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
        return TC_ACT_OK;
    if (eth.h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    // 2) IP 헤더 로드
    offset = sizeof(eth);
    if (bpf_skb_load_bytes(skb, offset, &ip, sizeof(ip)) < 0)
        return TC_ACT_OK;
    md.src_ip = ip.saddr;
    md.dst_ip = ip.daddr;
    md.proto  = ip.protocol;

    // ── 화이트리스트 검사 ───────────────────────────────────────────────
    // 네트워크 바이트 오더 그대로 key 로 사용합니다.
    __u8 *wh_src = bpf_map_lookup_elem(&whitelist_ips, &md.src_ip);
    if (wh_src)
        return TC_ACT_OK;
    __u8 *wh_dst = bpf_map_lookup_elem(&whitelist_ips, &md.dst_ip);
    if (wh_dst)
        return TC_ACT_OK;
    // ─────────────────────────────────────────────────────────────────────

    // 3) L4 헤더 로드
    offset += ip.ihl * 4;
    if (md.proto == IPPROTO_TCP) {
        struct tcphdr tcp;
        if (bpf_skb_load_bytes(skb, offset, &tcp, sizeof(tcp)) < 0)
            goto out;
        md.src_port = tcp.source;
        md.dst_port = tcp.dest;
    } else if (md.proto == IPPROTO_UDP) {
        struct udphdr udp;
        if (bpf_skb_load_bytes(skb, offset, &udp, sizeof(udp)) < 0)
            goto out;
        md.src_port = udp.source;
        md.dst_port = udp.dest;
    }

out:
    {
        // 네트워크 바이트 오더 → 호스트 바이트 오더 변환 후 ID 생성
        __u32 dst_h   = __builtin_bswap32(md.dst_ip);
        __u16 dport_h = __builtin_bswap16(md.dst_port);
        __u32 id      = (dst_h << 16) | dport_h;

        struct rec_event evt = {
            .id = id,
            .md = md,
        };
        // perf 이벤트로 유저스페이스에 전송
        bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    }

    return TC_ACT_OK;
}

// (라이선스은 common.h 에서 선언되어 있으니 여기서는 제거)
