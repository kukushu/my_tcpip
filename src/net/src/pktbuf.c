#include "pktbuf.h"
#include "dbg.h"
#include "mblock.h"
#include "nlocker.h"


static pktblk_t pktblk_buffer[PKTBUF_BLK_CNT];
static mblock_t pktblk_mblock;
static pktbuf_t pktbuf_buffer[PKTBUF_BUF_CNT];
static mblock_t pktbuf_mblock;


#if DBG_DISP_ENABLED(DBG_BUF)
void pktbuf_check (pktbuf_t * pktbuf) {
    if (!pktbuf) {
        dbg_error(DBG_BUF, "invalid buf. buff == 0");
        return ;
    }

    plat_printf("check buf %p: size %d\n", pktbuf, pktbuf->total_size);
    pktblk_t * curr;
    int total_size = 0, index = 0;
    for (curr = pktbuf_blk_first(pktbuf); curr; curr = pktbuf_blk_next(curr)) {
        plat_printf("pktblk index : %d, address %p\t", index, curr);
        plat_printf("%d: ", index ++);
        if ((curr->data < curr->payload) || (curr->data >= curr->payload + PKTBUF_BLK_SIZE)) {
            dbg_error(DBG_BUF, "bad block data");
        }
        int pre_size = (int) (curr->data - curr->payload);
        plat_printf("Pre : %d b, ", pre_size);

        int used_size = curr->size;
        plat_printf("Used : %d b, ", used_size);

        int free_size = PKTBUF_BLK_SIZE - (int) (curr->data - curr->payload) - curr->size;
        plat_printf("Free : %d b, ", free_size);
        plat_printf("\n");

        int blk_total = pre_size + used_size + free_size;
        if (blk_total != PKTBUF_BLK_SIZE) {
            dbg_error(DBG_BUF, "bad block size. %d != %d", blk_total, PKTBUF_BLK_SIZE);
        }
        total_size += used_size;
    }
    if (total_size != pktbuf->total_size) {
        dbg_error(DBG_BUF, "bad buf size. %d != %d", total_size, pktbuf->total_size);
    }
}

#else
#define pktbuf_check(buf) {}
#endif


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

static inline pktblk_t * pktbuf_blk_alloc_first (pktbuf_t * pktbuf) {
    pktblk_t * new_pktblk = mblock_alloc(&pktblk_mblock, -1);
    if (!new_pktblk) {
        dbg_error(DBG_BUF, "no buffer for alloc");
        return (pktblk_t *) 0;
    }
    nlist_insert_first(&pktbuf->blk_list, &new_pktblk->node);
    return new_pktblk;
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
        pktblk_t * new_pktblk = pktbuf_blk_alloc_first(pktbuf);
        if (!new_pktblk) {
            dbg_error(DBG_BUF, "no pktblk");
            pktbuf_free(pktbuf);
            return (pktbuf_t *) 0;
        }
        int curr_size = 0;
        curr_size = size > PKTBUF_BLK_SIZE ? PKTBUF_BLK_SIZE : size;
        size -= curr_size;
        new_pktblk->data = new_pktblk->payload + PKTBUF_BLK_SIZE - curr_size;
        new_pktblk->size = curr_size;
        pktbuf->total_size += curr_size;
    }
    return pktbuf;
}
void pktbuf_free (pktbuf_t * pktbuf) {
    pktblk_t * pktblk = pktbuf_blk_first(pktbuf);
    nlist_remove_first(&pktbuf->blk_list);
    while (pktblk) {
        mblock_free(&pktblk_mblock, pktblk);
        pktblk = pktbuf_blk_first(pktbuf);
        nlist_remove_first(&pktbuf->blk_list);
    }
    mblock_free(&pktbuf_mblock, pktbuf);
}
net_err_t pktbuf_add_header (pktbuf_t * pktbuf, int size, add_head_mth is_continue) {
    if (size > PKTBUF_BLK_SIZE) {
        dbg_error(DBG_BUF, "size too large");
        return NET_ERR_MEM;
    }
    int temp_size = size;
    pktblk_t * first_blk = pktbuf_blk_first(pktbuf);
    if (!first_blk) {
        dbg_error(DBG_BUF, "pktblk empty");
        return NET_ERR_MEM;
    }
    int remain_size = (int) (first_blk->data - first_blk->payload);
    if (remain_size >= size) {
        first_blk->size += size;
        first_blk->data -= size;
    } else {
        pktblk_t * new_pktblk = pktbuf_blk_alloc_first(pktbuf);
        if (!new_pktblk) {
            dbg_error(DBG_BUF, "no pktblk");
            return NET_ERR_MEM;
        }
        if (is_continue) {
            new_pktblk->size = size;
            new_pktblk->data =  PKTBUF_BLK_SIZE + new_pktblk->payload - size;
        } else {
            size -= remain_size;
            first_blk->size += remain_size;
            first_blk->data -= remain_size;
            new_pktblk->size = size;
            new_pktblk->data = new_pktblk->payload + PKTBUF_BLK_SIZE - size;
        }
    }
    pktbuf->total_size += temp_size;
    return NET_ERR_OK;
}
net_err_t pktbuf_remove_header (pktbuf_t * pktbuf, int size) {
    if (!pktbuf) {
        dbg_error(DBG_BUF, "buf is NULL");
        return NET_ERR_MEM;
    }

    if (pktbuf->total_size < size) {
        dbg_error(DBG_BUF, "buf total_size < size");
        return NET_ERR_MEM;
    }
    while (size) {
        pktblk_t * pktblk = pktbuf_blk_first(pktbuf);
        int remove_size = size > pktblk->size ? pktblk->size : size;
        if (size < pktblk->size) {
            pktblk->data += size;
            pktblk->size -= size;
        } else {
            nlist_remove_first(&pktbuf->blk_list);
            mblock_free(&pktblk_mblock, pktblk);
        }
        size -= remove_size;
        pktbuf->total_size -= remove_size;
    }
    return NET_ERR_OK;
}


