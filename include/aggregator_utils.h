#ifndef AGGREGATOR_UTILS_H
#define AGGREGATOR_UTILS_H

#include <cstdint>

/**
 * is_benign_traffic
 *  - proto: IP 프로토콜 번호 (1=ICMP, 6=TCP, 17=UDP)
 *  - dport: 목적지 포트 (호스트 바이트 오더)
 * 반환: true 면 benign, false 면 alert 대상
 */
bool is_benign_traffic(uint8_t proto, uint16_t dport);

#endif // AGGREGATOR_UTILS_H
