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
  struct rte_thash_subtuple_helper *h;
  uint16_t *rss_reta;   /* rss redirection table */
  uint32_t *rss_key_be; /* RSS toeplitz hash key */
  uint32_t rss_reta_mask;
  uint32_t rss_reta_len;
  uint32_t rss_key_len;
} ff_rss_state;

ff_rss_state rss_states[RTE_MAX_ETHPORTS] = {};

#define LOG2(X) ((unsigned)(8 * sizeof(unsigned) - __builtin_clz((X)) - 1))

const uint8_t *ff_init_thash(uint8_t *initial_key, const uint32_t key_len,
                             const uint32_t reta_len, const int port_id) {
  struct rte_thash_ctx *ctx;
  int reta_sz = LOG2(reta_len);
  int ret;

  printf("RETA SIZE %u (LOG2 %u)\n", reta_len, reta_sz);

  char ctxname[] = "ff_thash00";
  sprintf(ctxname, "ff_thash%d", port_id);

  ctx = rte_thash_init_ctx(ctxname, key_len, reta_sz, initial_key,
                           RTE_THASH_MINIMAL_SEQ);
  if (ctx == NULL) {
    printf("can not create thash ctx\n");
    return NULL;
  }

  char hlprname[] = "ff_thashhlpr00";
  sprintf(hlprname, "ff_thashhlpr%d", port_id);

  ret = rte_thash_add_helper(ctx, hlprname, sizeof(uint16_t) * 8,
                             offsetof(union rte_thash_tuple, v4.sport) * 8);
  if (ret != 0) {
    printf("can not add helper, ret %d\n", ret);
    return NULL;
  }

  printf("DPDK thash initialized\n");
  return rte_thash_get_key(ctx);
}

uint32_t ff_rss_hash(union rte_thash_tuple *tuple, uint16_t port_id) {
  return rte_softrss_be((uint32_t *)tuple, RTE_THASH_V4_L4_LEN,
                        (uint8_t *)rss_states[port_id].rss_key_be);
}

uint16_t ff_dport_for_queue(union rte_thash_tuple *tuple, uint16_t port_id,
                            uint8_t desired_lsb) {
  struct rte_thash_subtuple_helper *h = rss_states[port_id].h;

  uint32_t hash = ff_rss_hash(tuple, port_id);
  // printf("prv hash is %x lsb %u (!! desired lsb %u !!)\n", hash, hash & 127,
  //        desired_lsb);

  uint32_t adj = rte_thash_get_complement(h, hash, desired_lsb);
  tuple->v4.dport ^= adj;

  // uint32_t new_hash = ff_rss_hash(tuple, port_id);
  // printf("new hash is %x lsb is %u\n", new_hash, new_hash & 127);

  return 1;
}

uint16_t ff_get_local_port(union rte_thash_tuple *tuple, uint16_t port_id) {
  return ff_dport_for_queue(tuple, port_id, lcore_conf.tx_queue_id[port_id]);
}

uint8_t ff_get_rss_queue(union rte_thash_tuple *tuple, uint16_t port_id) {
  uint16_t nr_queues = lcore_conf.nb_queue_list[port_id];
  ff_rss_state *state = &rss_states[port_id];

  if (nr_queues == 0 || state->rss_key_be == NULL)
    return 0;

  uint32_t hash = ff_rss_hash(tuple, port_id);
  // printf("FF_GET_RSS_QUEUE hash is %x lsb is %u\n", hash, hash & 127);

  return state->rss_reta != NULL
             ? state->rss_reta[hash & state->rss_reta_mask] /* ReTa update */
             : hash % nr_queues;                            /* old rss */
}

int ff_rss_check(union rte_thash_tuple *tuple, int port_id) {
  uint16_t queueid = lcore_conf.tx_queue_id[port_id];
  return ff_get_rss_queue(tuple, port_id) == queueid;
}

void ff_rss_make_tuple(union rte_thash_tuple *tuple, uint32_t saddr,
                       uint32_t daddr, uint16_t sport, uint16_t dport) {
  tuple->v4.src_addr = ntohl(saddr);
  tuple->v4.dst_addr = ntohl(daddr);
  tuple->v4.dport = ntohs(dport);
  tuple->v4.sport = ntohs(sport);
}

int __ff_rss_check(void *softc, uint32_t saddr, uint32_t daddr, uint16_t sport,
                   uint16_t dport) {
  struct ff_dpdk_if_context *ctx = ff_veth_softc_to_hostc(softc);

  uint16_t nb_queues = lcore_conf.nb_queue_list[ctx->port_id];
  if (nb_queues <= 1)
    return 1;

  union rte_thash_tuple tuple;
  ff_rss_make_tuple(&tuple, saddr, daddr, sport, dport);

  return ff_rss_check(&tuple, ctx->port_id);
}

void fetch_rss_state(uint16_t port_id, int rss_key_len, int reta_len) {
  ff_rss_state *state = &rss_states[port_id];

  printf("FETCH rss state for port %u\n", port_id);

  char ctxname[] = "ff_thash00";
  sprintf(ctxname, "ff_thash%d", port_id);

  struct rte_thash_ctx *ctx = rte_thash_find_existing(ctxname);
  if (ctx == NULL) {
    printf("can not find thash ctx\n");
    return;
  }

  char hlprname[] = "ff_thashhlpr00";
  sprintf(hlprname, "ff_thashhlpr%d", port_id);

  state->h = rte_thash_get_helper(ctx, hlprname);
  if (state->h == NULL) {
    printf("can not find thash helper\n");
    return;
  }

  { /* init rss key */
    struct rte_eth_rss_conf rss_conf = {
        .rss_key = alloca(rss_key_len),
        .rss_key_len = rss_key_len,
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

    for (uint8_t i = 0; i < rss_conf.rss_key_len; i++)
      printf("%02x", rss_conf.rss_key[i]);
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

  if (reta_len > 0) {
    int num_confs = RTE_MAX(1, reta_len / RTE_ETH_RETA_GROUP_SIZE);
    struct rte_eth_rss_reta_entry64 reta_conf[num_confs];
    for (int i = 0; i < num_confs; i++)
      reta_conf[i].mask = ~0ULL;

    int ret = rte_eth_dev_rss_reta_query(port_id, reta_conf, reta_len);
    if (ret != 0) {
      fprintf(stderr, "Error getting reta_conf (port %u): %s\n", port_id,
              strerror(-ret));
      fprintf(stderr, "RSS RETA is disabled.\n");
      return;
    }

    state->rss_reta = malloc(reta_len * sizeof(uint16_t));
    state->rss_reta_mask = reta_len - 1;
    state->rss_reta_len = reta_len;

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
