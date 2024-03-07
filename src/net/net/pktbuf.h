#ifndef PKTBUF_H
#define PKTBUF_H


#include "sys.h"
#include "nlist.h"
#include "net_cfg.h"

typedef enum {
    CONTINUE,
    NOT_CONT
} add_head_mth;

typedef struct _pktblk_t {
    int size;
    uint8_t * data;
    uint8_t payload[PKTBUF_BLK_SIZE];
    nlist_node_t node;
} pktblk_t;

typedef struct _pktbuf_t {
    int total_size;
    nlist_t blk_list;
    nlist_node_t node;
} pktbuf_t;

static inline pktblk_t * pktbuf_blk_next(pktblk_t * pktblk) {
    nlist_node_t * next = nlist_node_next(&pktblk->node);
    return nlist_entry(next, pktblk_t, node);
}

static inline pktblk_t * pktbuf_blk_first(pktbuf_t * pktbuf) {
    nlist_node_t * first = nlist_first(&pktbuf->blk_list);
    return nlist_entry(first, pktblk_t, node);
}

static inline pktblk_t * pktbuf_blk_last(pktbuf_t * pktbuf) {
    nlist_node_t * last = nlist_last(&pktbuf->blk_list);
    return nlist_entry(last, pktblk_t, node);
}


net_err_t pktbuf_init (void);
pktbuf_t * pktbuf_alloc (int size);
void pktbuf_free (pktbuf_t * buf);
net_err_t pktbuf_add_header (pktbuf_t * buf, int size, add_head_mth is_continue);
net_err_t pktbuf_remove_header (pktbuf_t * buf, int size);



#endif