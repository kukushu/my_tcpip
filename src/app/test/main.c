#include "sys_plat.h"
#include "net.h"
#include "netif_pcap.h"
#include "dbg.h"
#include "net_cfg.h"

net_err_t netdev_init (void) {
    netif_pcap_open();
    return NET_ERR_OK;
}

void dbg_test (void) {
    dbg_error(DBG_TEST, "dbg_info : %s\n", "just_for_test");
    dbg_warning(DBG_TEST, "dbg_info : %s\n", "just_for_test");
    dbg_info(DBG_TEST, "dbg_info : %s\n", "just_for_test");
    dbg_debug(2 == 1, "failed");

}


int main (void) 
{
    //dbg_test();
    net_init();
    net_start();

    netdev_init();



    while (1) {
        sys_sleep(10);
    }

    return 0;
}