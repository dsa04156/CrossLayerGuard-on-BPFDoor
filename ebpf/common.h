

#include <linux/types.h>  // __u32, __u64, __u16, __u8
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

// 패킷 메타데이터 구조체
struct pkt_md {
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
  __u8 proto;
};

// 리코드 이벤트 구조체
struct rec_event {
  __u32 id;
  struct pkt_md md;
};

// PERF 이벤트 array 맵 (XDP/TC/SOCK 3개 모두 공유)
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 64);
} events SEC(".maps");

// 컨트롤-플레인 이벤트 맵
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));   /* 항상 4바이트 */
    __uint(max_entries, 64);
} ctrl_events SEC(".maps");

// 화이트리스트 IP 맵 (BPF_ANY으로 업데이트)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);
  __type(value, __u8);
  __uint(pinning, LIBBPF_PIN_BY_NAME);

} whitelist_ips SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

