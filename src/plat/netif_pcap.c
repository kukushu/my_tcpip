#include "netif_pcap.h"
#include "sys_plat.h"
#include "exmsg.h"
#include "dbg.h"

void recv_thread (void * arg) {
    plat_printf("recv thread is running\n");
    while (1) {
        sys_sleep(1000);
        net_err_t err = exmsg_netif_in();
        if (err < 0) {
            dbg_error(DBG_EXMSG, "recv_thread failed");
        }
    }
}

void xmit_thread (void * arg) {
    plat_printf("xmit thread is running\n");
    while (1) {
        sys_sleep(1);
    }
}
net_err_t netif_pcap_open (void) {
    sys_thread_create(recv_thread, (void *) 0);
    sys_thread_create(xmit_thread, (void *) 0);
    return NET_ERR_OK;
}
