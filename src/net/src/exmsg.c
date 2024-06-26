#include "exmsg.h"
#include "dbg.h"
#include "fixq.h"
#include "sys.h"
#include "mblock.h"
#include "timer.h"
#include "ipv4.h"


static void * msg_tbl[EXMSG_MSG_CNT];
static fixq_t msg_queue;

static exmsg_t msg_buffer[EXMSG_MSG_CNT];
static mblock_t msg_block;

static void do_netif_in (exmsg_t * msg) {
    netif_t * netif = (netif_t *) msg->netif;

    pktbuf_t * pktbuf;
    while (pktbuf = netif_get_in(netif, -1)) {
        dbg_info(DBG_EXMSG, "recv a packet");
        net_err_t err;
        if (netif->link_layer) {
            err = netif->link_layer->in(netif, pktbuf);
            if (err != NET_ERR_OK) {
                dbg_warning(DBG_EXMSG, "do netif in failed, link_layer failed");
                pktbuf_free(pktbuf);
            }
        } else {
            dbg_error(DBG_EXMSG, "no link layer, deal with after");
            err = ipv4_in(netif, pktbuf);
            if (err != NET_ERR_OK) {
                dbg_warning(DBG_EXMSG, "no link layer, ipv4_in failed");
                pktbuf_free(pktbuf);
            }
        }
    }
}

void do_func (func_msg_t * func_msg) {
    dbg_info(DBG_EXMSG, "call func");

    func_msg->err = func_msg->func(func_msg->param);
    sys_sem_notify(func_msg->wait_sem);
    dbg_info(DBG_EXMSG, "func exec complete");
}

static void work_thread (void * arg) {
    dbg_info(DBG_EXMSG, "exmsg is running.....\n");

    net_time_t time;
    sys_time_curr(&time);
    int index = 0;
    int time_last = TIMER_SCAN_PERIOD;
    while (1) {
        int first_tmo = net_timer_first_tmo();
        exmsg_t * msg = (exmsg_t *) fixq_recv(&msg_queue, first_tmo);
        
        int diff_ms = sys_time_goes(&time);
        time_last -= diff_ms;
        if (time_last < 0) {
            net_timer_check_tmo(diff_ms);
            time_last = TIMER_SCAN_PERIOD;
        }

        if (msg) {
            dbg_info(DBG_EXMSG, "recieve a msg(%p): %d", msg, msg->type);
            switch (msg->type) {
                case NET_EXMSG_NETIF_IN:
                    do_netif_in(msg);
                    break;
                case NET_EXMSG_FUN:
                    do_func(msg->func);
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

net_err_t exmsg_func_exec (exmsg_func_t func, void * param) {
    func_msg_t func_msg;
    func_msg.thread = sys_thread_self();
    func_msg.func = func;
    func_msg.param = param;
    func_msg.err = NET_ERR_OK;
    func_msg.wait_sem = sys_sem_create(0);
    if (func_msg.wait_sem == SYS_SEM_INVALID) {
        dbg_error(DBG_EXMSG, "create func msg failed");
        return NET_ERR_MEM;
    }

    exmsg_t * msg = (exmsg_t *) mblock_alloc(&msg_block, 0);
    msg->type = NET_EXMSG_FUN;
    msg->func = &func_msg;

    dbg_info(DBG_EXMSG, "send func msg");
    net_err_t err = fixq_send(&msg_queue, msg, 0);
    if (err < 0) {
        dbg_error(DBG_EXMSG, "send func msg failed");
        mblock_free(&msg_block, msg);
        sys_sem_free(func_msg.wait_sem);
        return err;
    }

    sys_sem_wait(func_msg.wait_sem, 0);
    dbg_info(DBG_EXMSG, "the end of func msg");
    sys_sem_free(func_msg.wait_sem);
    return func_msg.err;
}