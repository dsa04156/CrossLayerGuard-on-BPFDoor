// File: include/ctrl_event.h
#ifndef __CTRL_EVENT_H
#define __CTRL_EVENT_H

#include <cstdint>

struct ctrl_event {
  uint32_t id;
  uint32_t code;
  uint8_t proto;
};

#endif  // __CTRL_EVENT_H
