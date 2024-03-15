#include "loop.h"

static net_err_t loop_open (struct _netif_t * netif, void * data) {
    netif->type = NETIF_TYPE_LOOP;
    return NET_ERR_OK;
}
static void loop_close (struct _netif_t * netif)  {

}
static net_err_t loop_xmit (struct _netif_t * netif) {
    return NET_ERR_OK;
}


static const netif_ops_t loop_ops = {
    .open = loop_open,
    .close = loop_close,
    .xmit = loop_xmit,
};

net_err_t loop_init (void) {
    dbg_info(DBG_NETIF, "loop init");
    netif_t * netif = netif_open("loop", &loop_ops, (void *) 0);
    if (!netif) {
        dbg_error(DBG_NETIF, "open loop err");
        return NET_ERR_NONE;
    }
    dbg_info(DBG_NETIF, "loop init done");
    return NET_ERR_OK;
}


