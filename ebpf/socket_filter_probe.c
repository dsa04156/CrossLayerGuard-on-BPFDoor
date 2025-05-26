// File: ebpf/sock_record.c

#include "common.h"
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>   // ETH_P_IP, struct ethhdr
#include <linux/ip.h>         // struct iphdr
#include <linux/udp.h>        // struct udphdr, IPPROTO_UDP
#include <linux/tcp.h>        // struct tcphdr, IPPROTO_TCP
#include <linux/in.h>         // AF_INET

SEC("socket")
int sock_record(struct __sk_buff *skb) {
    struct ethhdr eth;
    struct iphdr  ip;
    struct pkt_md md = {};
    __u32 offset = 0;

    // 1) Ethernet 헤더 읽기
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
        return 0;
    if (eth.h_proto != __constant_htons(ETH_P_IP))
        return 0;

    // 2) IP 헤더 읽기
    offset = sizeof(eth);
    if (bpf_skb_load_bytes(skb, offset, &ip, sizeof(ip)) < 0)
        return 0;
    md.src_ip = ip.saddr;
    md.dst_ip = ip.daddr;
    md.proto  = ip.protocol;

    
    // 3) 화이트리스트 검사
    if (bpf_map_lookup_elem(&whitelist_ips, &md.src_ip)) return 0;
    if (bpf_map_lookup_elem(&whitelist_ips, &md.dst_ip)) return 0;
    

    
    // ── DEBUG: 실제 읽은 IP 출력 ────────────────────────────────────────
    // bpf_printk("DBG: src=%pI4 dst=%pI4 proto=%d\n",
    //         &md.src_ip, &md.dst_ip, md.proto);
    // ───────────────────────────────────────────────────────────────────
    // 4) L4 헤더 읽기
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
        __u32 dst_h   = __builtin_bswap32(md.dst_ip);
        __u16 dport_h = __builtin_bswap16(md.dst_port);
        __u32 id      = (dst_h << 16) | dport_h;
        struct rec_event evt = { .id = id, .md = md };
        bpf_perf_event_output(skb, &events,
                              BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    }
    return 0;
}
