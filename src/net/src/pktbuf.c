#include "pktbuf.h"
#include "dbg.h"
#include "mblock.h"
#include "nlocker.h"


static pktblk_t pktblk_buffer[PKTBUF_BLK_CNT];
static mblock_t pktblk_mblock;
static pktbuf_t pktbuf_buffer[PKTBUF_BUF_CNT];
static mblock_t pktbuf_mblock;


net_err_t pktbuf_init (void) {
    net_err_t err;
    err = mblock_init(&pktblk_mblock, pktblk_buffer, sizeof(pktblk_t), PKTBUF_BLK_CNT, NLOCKER_THREAD);
    if (err != NET_ERR_OK) {
        dbg_error(DBG_BUF, "pktblk_init mblock init failed");
        return err;
    }
    err = mblock_init(&pktbuf_mblock, pktbuf_buffer, sizeof(pktbuf_t), PKTBUF_BUF_CNT, NLOCKER_THREAD);
    if (err != NET_ERR_OK) {
        dbg_error(DBG_BUF, "pktblk_init mblock init failed");
        return err;
    }
    return NET_ERR_OK;
}
pktbuf_t * pktbuf_alloc (int size) {
    pktbuf_t * pktbuf = mblock_alloc(&pktbuf_mblock, -1);
    if (!pktbuf) {
        dbg_error(DBG_BUF, "no free pktbuf");
        return (pktbuf_t *) 0;
    }
    pktbuf->total_size = 0;
    nlist_init(&pktbuf->blk_list);
    nlist_node_init(&pktbuf->node);

    while (size) {
        pktblk_t * new_pktblk = mblock_alloc(&pktblk_mblock, -1);
        if (!new_pktblk) {
            dbg_error(DBG_BUF, "no buffer for alloc (size %d)", size);
            pktbuf_free(pktbuf);
            return (pktbuf_t *) 0;
        }
        int curr_size = 0;
        curr_size = size > PKTBUF_BLK_SIZE ? PKTBUF_BLK_SIZE : size;
        size -= curr_size;
        new_pktblk->data = new_pktblk->payload + PKTBUF_BLK_SIZE - curr_size;
        new_pktblk->size = curr_size;
        nlist_insert_first(&pktbuf->blk_list, &new_pktblk->node);
    }
    return pktbuf;
}
void pktbuf_free (pktbuf_t * pktbuf) {
    pktblk_t * pktblk = pktbuf_blk_first(pktbuf);
    nlist_remove_first(&pktbuf->blk_list);
    while (pktblk) {
        plat_printf("test\n");
        mblock_free(&pktblk_mblock, pktblk);
        pktblk = pktbuf_blk_first(pktbuf);
        nlist_remove_first(&pktbuf->blk_list);
    }
    mblock_free(&pktbuf_mblock, pktbuf);
}
net_err_t pktbuf_add_header (pktbuf_t * buf, int size, add_head_mth is_continue) {

}
net_err_t pktbuf_remove_header (pktbuf_t * buf, int size) {

}


