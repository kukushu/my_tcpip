#include "sys_plat.h"
#include "net.h"
#include "netif_pcap.h"


net_err_t netdev_init (void) {
    netif_pcap_open();
    return NET_ERR_OK;
}

int main (void) 
{
    net_init();
    net_start();

    netdev_init();



    while (1) {
        sys_sleep(10);
    }

    return 0;
}