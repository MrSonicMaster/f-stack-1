#include <alloca.h>
#include <rte_ethdev.h>
#include <rte_thash.h>
#include <stdint.h>

#include "ff_config.h"

#include "ff_memory.h"
#include "ff_rss.h"
#include "ff_veth.h"

extern struct lcore_conf lcore_conf;

typedef struct ff_rss_state {
  uint16_t *rss_reta;   /* rss redirection table */
  uint32_t *rss_key_be; /* RSS toeplitz hash key */
  uint32_t rss_reta_mask;
  uint32_t rss_reta_len;
  uint32_t rss_key_len;
} ff_rss_state;

ff_rss_state rss_states[RTE_MAX_ETHPORTS] = {};

int ff_get_rss_queue(uint16_t port_id, ff_rss_input *rss_inpt) {
  if (port_id > RTE_MAX_ETHPORTS)
    return 0;

  uint16_t nb_queues = lcore_conf.nb_queue_list[port_id];
  if (nb_queues <= 0)
    return 0;

  ff_rss_state *state = &rss_states[port_id];

  if (state->rss_key_be == NULL)
    return 0; /* default to queue 0 */

  int idx = rte_softrss_be((uint32_t *)rss_inpt, sizeof *rss_inpt,
                           (uint8_t *)state->rss_key_be);

  if (state->rss_reta != NULL)
    return state->rss_reta[idx & state->rss_reta_mask]; /* use ReTa update */
  else
    return idx % nb_queues; /* old rss */
}

int ff_rss_check(void *softc, uint32_t saddr, uint32_t daddr, uint16_t sport,
                 uint16_t dport) {
  struct ff_dpdk_if_context *ctx = ff_veth_softc_to_hostc(softc);
  uint16_t nb_queues = lcore_conf.nb_queue_list[ctx->port_id];

  if (nb_queues <= 1)
    return 1;

  uint16_t queueid = lcore_conf.tx_queue_id[ctx->port_id];

  ff_rss_input rss_inpt = {
      .saddr = saddr,
      .daddr = daddr,
      .sport = sport,
      .dport = dport,
  };

  return ff_get_rss_queue(ctx->port_id, &rss_inpt) == queueid;
}

void fetch_rss_state(uint16_t port_id, int reta_size) {
  ff_rss_state *state = &rss_states[port_id];

  { /* init rss key */
    struct rte_eth_rss_conf rss_conf = {
        .rss_key = alloca(52),
        .rss_key_len = 52,
        .rss_hf = 0,
    };

    int ret = rte_eth_dev_rss_hash_conf_get(port_id, &rss_conf);
    if (ret != 0) {
      fprintf(stderr, "Error getting rss_conf (port %u): %s\n", port_id,
              strerror(-ret));
      goto out_fail;
    }

    printf("rss > hash_func_mask=%lu key_len=%d key: ", rss_conf.rss_hf,
           rss_conf.rss_key_len);

    for (uint8_t i = 0; i < state->rss_key_len; i++)
      printf("%u ", rss_conf.rss_key[i]);
    printf("\n");

    if (rss_conf.rss_hf == 0) {
      fprintf(stderr, "all rss hash functions are disabled.\n");
      goto out_fail;
    } else if (rss_conf.rss_key_len == 0) {
      fprintf(stderr, "rss key is not configured or not available.\n");
      goto out_fail;
    } else if ((rss_conf.rss_key_len & 7) != 0) {
      /* should be impossible! */
      fprintf(stderr, "rss key is not a multiple of 8.\n");
      goto out_fail;
    }

    state->rss_key_be = malloc(rss_conf.rss_key_len);
    state->rss_key_len = rss_conf.rss_key_len;

    if (state->rss_key_be == NULL) {
      /* should be impossible! */
      fprintf(stderr, "failed to malloc rss_key\n");
      goto out_fail;
    }

    rte_convert_rss_key((const uint32_t *)rss_conf.rss_key,
                        (uint32_t *)state->rss_key_be, rss_conf.rss_key_len);
  }

  if (reta_size > 0) {
    int num_confs = RTE_MAX(1, reta_size / RTE_ETH_RETA_GROUP_SIZE);
    struct rte_eth_rss_reta_entry64 reta_conf[num_confs];

    int ret = rte_eth_dev_rss_reta_query(port_id, reta_conf, reta_size);
    if (ret != 0) {
      fprintf(stderr, "Error getting reta_conf (port %u): %s\n", port_id,
              strerror(-ret));
      fprintf(stderr, "RSS RETA is disabled.\n");
      return;
    }

    state->rss_reta = malloc(reta_size * sizeof(uint16_t));
    state->rss_reta_mask = reta_size - 1;
    state->rss_reta_len = reta_size;

    if (state->rss_reta == NULL) {
      fprintf(stderr, "failed to malloc rss_reta\n");
      fprintf(stderr, "RSS RETA is disabled.\n");
      return;
    }

    for (int i = 0; i < num_confs; i++) {
      for (int j = 0; j < RTE_ETH_RETA_GROUP_SIZE; j++)
        state->rss_reta[i * RTE_ETH_RETA_GROUP_SIZE + j] = reta_conf[i].reta[j];
    }

    printf("RSS reta: ");
    for (uint8_t i = 0; i < state->rss_reta_len; i++)
      printf("%u ", state->rss_reta[i]);
    printf("\n");
  }

  return;

out_fail:
  fprintf(stderr, "RSS is disabled.\n");
}
