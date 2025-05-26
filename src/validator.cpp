// src/validator.cpp

#include <cstdint>
#include <vector>    // 추가
#include <cstdio>

static const size_t MAX_IDS = 1 << 20;

// 각 ID별 계층 비트마스크 저장 (0:XDP, 1:TC, 2:SOCK)
static std::vector<uint8_t> mask_map(MAX_IDS, 0);

extern "C" void validator_record_layer(int layer, uint32_t id) {
    uint32_t idx = id & (MAX_IDS - 1);
    mask_map[idx] |= static_cast<uint8_t>(1 << layer);
}

extern "C" void validator_validate(uint32_t code, uint32_t id) {
    uint32_t idx  = id & (MAX_IDS - 1);
    uint8_t  m    = mask_map[idx];
    bool alert = false;

    // code 5 = CONNECT, 6 = SENDTO
    if ((code == 5 || code == 6) && (m & 0x03) == 0) {
        alert = true;
    }

    if (alert) {
        std::printf("[ALERT] syscall-only id=%u mask=0x%02x\n", id, m);
    }

    // 다음 이벤트를 위해 리셋
    mask_map[idx] = 0;
}
