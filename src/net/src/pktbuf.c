#include "pktbuf.h"
#include "dbg.h"
#include "mblock.h"
#include "nlocker.h"

typedef enum {
    HEAD,
    TAIL
} insert_mth;


static pktblk_t pktblk_buffer[PKTBUF_BLK_CNT];
static mblock_t pktblk_list;
static pktbuf_t pktbuf_buffer[PKTBUF_BUF_CNT];
static mblock_t pktbuf_list;





net_err_t pktbuf_init (void) {
    dbg_info(DBG_BUF, "init pktbuf");
    net_err_t result;

    result = mblock_init(&pktblk_list, pktblk_buffer, sizeof(pktblk_t), PKTBUF_BLK_CNT, NLOCKER_THREAD);
    if (result != NET_ERR_OK) {
        dbg_error(DBG_BUF, "mblock_init pktblk_list failed");
        return NET_ERR_MEM;
    }
    result = mblock_init(&pktbuf_list, pktbuf_buffer, sizeof(pktbuf_t), PKTBUF_BUF_CNT, NLOCKER_THREAD);
    if (result != NET_ERR_OK) {
        dbg_error(DBG_BUF, "mblock_init pktbuf_list failed");
        return NET_ERR_MEM;
    }

    return NET_ERR_OK;
}



pktbuf_t * pktbuf_alloc (int size) {

    pktbuf_t * new_pktbuf = mblock_alloc(&pktbuf_list, -1);

    if (!new_pktbuf) {
        dbg_error(DBG_BUF, "no pktbuf");
        return (pktbuf_t *) 0;
    }

    new_pktbuf->total_size = 0;
    nlist_init(&new_pktbuf->blk_list);
    nlist_node_init(&new_pktbuf->node);

    
    while (size) {
        int curr_size = 0;
        curr_size = size > PKTBUF_BLK_SIZE ? PKTBUF_BLK_SIZE : size;
        size -= curr_size;
        pktblk_t * new_pktblk = (pktblk_t *)mblock_alloc(&pktblk_list, -1);
        if (!new_pktblk) {
            dbg_warning(DBG_BUF, "pktblk allocation failed");
            pktbuf_free(new_pktbuf);
            return (pktbuf_t *) 0;
        }
        new_pktblk->size = curr_size;
        new_pktblk->data = new_pktblk->payload + PKTBUF_BLK_SIZE - curr_size;
        nlist_insert_first(&new_pktbuf->blk_list, (nlist_node_t *) new_pktblk);
    }
    return new_pktbuf;
}
void pktbuf_free (pktbuf_t * buf) {
    if (!buf) {
        dbg_warning(DBG_BUF, "this pktbuf is 0");
        return ;
    }
    nlist_node_t * pktblk;
    while (pktblk = nlist_remove_first(&buf->blk_list)) {
        mblock_free(&pktblk_list, (pktblk_t *) pktblk);
    }
    mblock_free(&pktbuf_list, buf);
}


