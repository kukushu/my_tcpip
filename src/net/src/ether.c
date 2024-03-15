#include "ether.h"
#include "dbg.h"
#include "netif.h"

const uint8_t * ether_broadcast_addr (void) {
    static const uint8_t broadcast_addr[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    return broadcast_addr;
}
net_err_t ether_open (netif_t * netif) {

    return NET_ERR_OK;
}
void ether_close (netif_t * netif) {

}
net_err_t ether_in (netif_t * netif, pktbuf_t * buf) {
    return NET_ERR_OK;
}

net_err_t ether_out (netif_t * netif, ipaddr_t * ip_addr, pktbuf_t * pktbuf) {
    return NET_ERR_OK;
}

net_err_t ether_init (void) {
    static const link_layer_t link_layer = {
        .type = NETIF_TYPE_ETHER,
        .open = ether_open,
        .close = ether_close,
        .in = ether_in,
        .out = ether_out,
    };

    dbg_info(DBG_ETHER, "init ether");
    net_err_t err;
    err = netif_register_layer(&link_layer); 
    if (err != NET_ERR_OK) {
        dbg_error(DBG_ETHER, "netif_register_layer failed");
        return err;
    }
    dbg_info(DBG_ETHER, "ether init done");

    return NET_ERR_OK;
}