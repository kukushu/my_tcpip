#include "exmsg.h"
#include "dbg.h"
#include "fixq.h"
#include "sys.h"
#include "mblock.h"


static void * msg_tbl[EXMSG_MSG_CNT];
static fixq_t msg_queue;

static exmsg_t msg_buffer[EXMSG_MSG_CNT];
static mblock_t msg_block;

static void do_netif_in (exmsg_t * msg) {

}

static void work_thread (void * arg) {
    dbg_info(DBG_EXMSG, "exmsg is running.....\n");

    while (1) {
        exmsg_t * msg = (exmsg_t *) fixq_recv(&msg_queue, 0);
        if (msg) {
            dbg_info(DBG_EXMSG, "recieve a msg(%p): %d", msg, msg->type);
            switch (msg->type) {
                case NET_EXMSG_NETIF_IN:
                    do_netif_in(msg);
                    break;
                case NET_EXMSG_FUN:
                    //do_func(msg->func);
                    break;
            }
            mblock_free(&msg_block, msg);
        }
    }
}

net_err_t exmsg_init (void) {
    dbg_info(DBG_EXMSG, "exmsg init");
    net_err_t err = fixq_init(&msg_queue, msg_tbl, EXMSG_MSG_CNT, EXMSG_NLOCKER);
    if (err < 0) {
        dbg_error(DBG_EXMSG, "fixq init failed");
        return err;
    }
    err = mblock_init(&msg_block, msg_buffer, sizeof(exmsg_t), EXMSG_MSG_CNT, EXMSG_NLOCKER);
    if (err < 0) {
        dbg_error(DBG_EXMSG, "mblock init failed");
        return err;
    }
    dbg_info(DBG_EXMSG, "exmsg init done");
    return NET_ERR_OK;
}

net_err_t exmsg_start (void) {
    sys_thread_t thread =sys_thread_create(work_thread, "work_thread");
    if (thread == SYS_THREAD_INVALID) {
        return NET_ERR_SYS;
    }
    return NET_ERR_OK;
}

net_err_t exmsg_netif_in (netif_t * netif) {
    exmsg_t * msg = mblock_alloc(&msg_block, -1);
    if (!msg) {
        dbg_warning(DBG_EXMSG, "no free msg");
        return NET_ERR_MEM;
    }
    msg->type = NET_EXMSG_NETIF_IN;
    msg->netif = netif;

    net_err_t err = fixq_send(&msg_queue, msg, -1);
    if (err < 0) {
        dbg_warning(DBG_EXMSG, "fixq full");
        mblock_free(&msg_block, msg);
        return err;
    }
    return NET_ERR_OK;
}