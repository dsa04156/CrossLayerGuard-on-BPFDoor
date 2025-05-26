// File: include/record.h
#ifndef __RECORD_H
#define __RECORD_H

#include <cstdint>

// eBPF와 동일한 레이아웃
struct pkt_md {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t proto;
};

struct rec_event {
  uint32_t id;
  struct pkt_md md;
};

#endif  // __RECORD_H
