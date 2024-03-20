#include "net.h"
#include "exmsg.h"
#include "net_plat.h"
#include "dbg.h"
#include "netif.h"
#include "pktbuf.h"
#include "loop.h"
#include "ether.h"
#include "arp.h"
#include "tools.h"
#include "timer.h"
 
net_err_t net_init (void) {
    dbg_info(DBG_INIT, "net_init");
    net_plat_init();
    tools_init();
    exmsg_init();
    pktbuf_init();
    netif_init();
    timer_init();
    ether_init();
    loop_init();
    arp_init();
    return NET_ERR_OK;
}

net_err_t net_start (void) {
    exmsg_start();
    return NET_ERR_OK;
}