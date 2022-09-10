#ifndef FF_RSS_H
#define FF_RSS_H

#include <stdint.h>

typedef struct ff_rss_input {
  uint32_t saddr;
  uint32_t daddr;
  uint32_t sport;
  uint32_t dport;
} ff_rss_input;

int ff_get_rss_queue(uint16_t port_id, ff_rss_input *rss_inpt);

#endif