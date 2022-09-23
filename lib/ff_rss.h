#ifndef FF_RSS_H
#define FF_RSS_H

#include <rte_thash.h>
#include <stdint.h>

/* NOTE: rte_thash_tuple wants HOST byte order on all fields! can use
 * ff_rss_make_tuple as wrapper to convert from network-order to host-order. */

/* wrapper to convert NETWORK-order fields into an `rte_thash_tuple` */
void ff_rss_make_tuple(union rte_thash_tuple *tuple, uint32_t saddr,
                       uint32_t daddr, uint16_t sport, uint16_t dport);

/* return Toeplitz hash for `tuple` based on rss config of port `port_id` */
uint32_t ff_rss_hash(union rte_thash_tuple *tuple, uint16_t port_id);

/* `destination` is us, `from` is them. calculate a destination port field that
 * will land the tuple on the ReTa table at index `desired_queue,` which
 * currently maps directly to rx queue (reta goes 0,1,2,0,1,2,0,1,2,...) */
uint16_t ff_dport_for_queue(union rte_thash_tuple *tuple, uint16_t port_id,
                            uint8_t desired_queue);

/* `destination` is us, `from` is them. calculate a destination port field that
 * will land the tuple on rx queue of the calling f-stack process for port
 * `port_id` */
uint16_t ff_get_local_port(union rte_thash_tuple *tuple, uint16_t port_id);

/* calculate which queue the tuple will land on, based on rss config of port
 * `port_id` */
uint8_t ff_get_rss_queue(union rte_thash_tuple *tuple, uint16_t port_id);

/* check whether a tuple will properly land on the rx queue of the calling
 * f-stack process. */
int ff_rss_check(union rte_thash_tuple *tuple, int port_id);

#endif