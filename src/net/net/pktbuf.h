#ifndef PKTBUF_H
#define PKTBUF_H


#include "sys.h"
#include "nlist.h"
#include "net_cfg.h"

typedef struct _pktblk_t {
    int size;
    uint8_t * data;
    uint8_t payload[PKTBUF_BLK_SIZE];
} pktblk_t;

typedef struct _pktbuf_t {
    int total_size;
    nlist_t blk_list;
    nlist_node_t node;
} pktbuf_t;

net_err_t pktbuf_init (void);
pktbuf_t * pktbuf_alloc (int size);
void pktbuf_free (pktbuf_t * buf);



#endif