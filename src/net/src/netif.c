#include "netif.h"
#include "mblock.h"
#include "fixq.h"
#include "exmsg.h"

static netif_t netif_buffer[NETIF_DEV_CNT];
static mblock_t netif_mblock;
static nlist_t netif_list;
static netif_t * netif_default;
static const link_layer_t * link_layers[NETIF_TYPE_SIZE];

netif_t * netif_get_default (void) {
    return netif_default;
}

static void netif_set_default (netif_t * netif) {
    
    netif_default = netif;
}

net_err_t netif_register_layer (const link_layer_t * link_layer) {
    if ((link_layer->type == NETIF_TYPE_NONE) || (link_layer->type > NETIF_TYPE_SIZE)) {
        dbg_error(DBG_NETIF, "link_layer type not supported");
        return NET_ERR_PARAM;
    }
    if (link_layers[link_layer->type]) {
        dbg_error(DBG_NETIF, "link_layer already registered");
        return NET_ERR_EXIST;
    }
    link_layers[link_layer->type] = link_layer;
        
    return NET_ERR_OK;
}


static const link_layer_t * netif_get_layer (int type) {
    if ((type < 0) || (type >= NETIF_TYPE_SIZE)) {
        return (const link_layer_t *) 0;
    }
    return link_layers[type];
}

void * netif_set_hwaddr (netif_t * netif, const uint8_t * hwaddr, int len) {
    plat_memcpy(&netif->hwaddr, hwaddr, len);
    netif->hwaddr.len = len;
}

net_err_t netif_init (void) {
    dbg_info(DBG_NETIF, "netif init netif");

    nlist_init(&netif_list);
    mblock_init(&netif_mblock, netif_buffer, sizeof(netif_t), NETIF_DEV_CNT, NLOCKER_NONE);



    netif_default = (netif_t *) 0;

    plat_memset(link_layers, 0, sizeof(link_layer_t));

    dbg_info(DBG_NETIF, "netif init done");
    return NET_ERR_OK;
}

netif_t * netif_open (const char * dev_name, const netif_ops_t * ops, void * ops_data) {

    netif_t * netif = (netif_t *) mblock_alloc(&netif_mblock, -1);
    if (!netif) {
        dbg_error(DBG_NETIF, "no netif");
        return (netif_t *) 0;
    }
    
    ipaddr_set_any(&netif->ipaddr);
    ipaddr_set_any(&netif->netmask);
    ipaddr_set_any(&netif->gateway);

    plat_strncpy(netif->name, dev_name, NETIF_NAME_SIZE);
    netif->name[NETIF_NAME_SIZE - 1] = '\0';
    netif->ops = ops;
    netif->ops_data = ops_data;

    plat_memset(&netif->hwaddr, 0, sizeof(netif_hwaddr_t));
    netif->type = NETIF_TYPE_NONE;
    netif->mtu = 0;
    nlist_node_init(&netif->node);

    net_err_t err = fixq_init(&netif->in_q, netif->in_q_buf, NETIF_INQ_SIZE, NLOCKER_THREAD);
    if (err < 0) {
        dbg_error(DBG_NETIF, "netif in_q init failed");
        goto fixq_return_in;
    }
    err = fixq_init(&netif->out_q, netif->out_q_buf, NETIF_OUTQ_SIZE, NLOCKER_THREAD); 
    if (err < 0) {
        dbg_error(DBG_NETIF, "netif out_q init failed");
        goto fixq_return_out;
    }

    err = ops->open(netif, ops_data);
    if (err < 0) {
        dbg_error(DBG_NETIF, "netif ops open err");
        goto free_return;
    }

    netif->state = NETIF_OPENED;
    if (netif->type == NETIF_TYPE_NONE) {
        dbg_error(DBG_NETIF, "netif type unknown");
        goto free_return;
    }

    netif->link_layer = netif_get_layer(netif->type);
    if (!netif->link_layer && (netif->type != NETIF_TYPE_LOOP)) {
        dbg_error(DBG_NETIF, "no link layer. netif name: %s", netif->name);
        goto free_return;
    }

    nlist_insert_last(&netif_list, &netif->node);
    return netif;
    

free_return:

    fixq_destroy(&netif->in_q);
    fixq_destroy(&netif->out_q);
    mblock_free(&netif_mblock, netif);

fixq_return_out:
    fixq_destroy(&netif->out_q);
fixq_return_in:
    fixq_destroy(&netif->in_q);
    return (netif_t *) 0;
}


net_err_t netif_put_in (netif_t * netif, pktbuf_t * pktbuf, int tmo) {
    net_err_t err;
    err = fixq_send(&netif->in_q, pktbuf, tmo);
    if (err != NET_ERR_OK) {
        dbg_warning(DBG_NETIF, "netif_put_in failed fixq_in is full");
        return NET_ERR_FULL;
    }
    exmsg_netif_in(netif);
    return NET_ERR_OK;
}
pktbuf_t * netif_get_in (netif_t * netif, int tmo) {
    pktbuf_t * buf = fixq_recv(&netif->in_q, tmo);
    if (buf) {
        pktbuf_reset_acc(buf);
        return buf;
    } 
    dbg_info(DBG_NETIF, "netif %s in_q empty", netif->name);
    return (pktbuf_t *) 0;
}
net_err_t netif_put_out (netif_t * netif, pktbuf_t * pktbuf, int tmo) {
    net_err_t err;
    err = fixq_send(&netif->out_q, pktbuf, tmo);
    if (err != NET_ERR_OK) {
        dbg_warning(DBG_NETIF, "netif_put_out failed fixq_out is full");
        return NET_ERR_FULL;
    }
    return NET_ERR_OK;
}
pktbuf_t * netif_get_out (netif_t * netif, int tmo) {
    pktbuf_t * buf = fixq_recv(&netif->out_q, tmo);
    if (buf) {
        pktbuf_reset_acc(buf);
        return buf;
    }
    dbg_info(DBG_NETIF, "netif %s out_q empty", netif->name);
    return (pktbuf_t *) 0;
}
net_err_t netif_set_addr (netif_t * netif, ipaddr_t * ip, ipaddr_t * netmask, ipaddr_t * gateway) {

    ipaddr_copy(&netif->ipaddr, ip ? ip : ipaddr_get_any());
    ipaddr_copy(&netif->gateway, gateway ? gateway : ipaddr_get_any());
    ipaddr_copy(&netif->netmask, netmask ? netmask : ipaddr_get_any());

    return NET_ERR_OK;
}


net_err_t netif_set_active(netif_t * netif) {
    if (netif->state != NETIF_OPENED) {
        dbg_error(DBG_NETIF, "netif is not opened");
        return NET_ERR_STATE;
    }
    if (!netif_default && (netif->type != NETIF_TYPE_LOOP)) {
        netif_set_default(netif);
    }
    if (netif->link_layer) {
        net_err_t err = netif->link_layer->open(netif);
        if (err < 0) {
            dbg_info(DBG_NETIF, "active error.");
            return err;
        }
    }
}

net_err_t netif_out (netif_t * netif, ipaddr_t * ipaddr, pktbuf_t * pktbuf) {
    if (netif->link_layer) {
        net_err_t err = netif->link_layer->out(netif, ipaddr, pktbuf);
        if (err < 0) {
            dbg_warning(DBG_NETIF, "netif link out error %d", err);
            pktbuf_free(pktbuf);
            return err;
        }
        return NET_ERR_OK;
    } else {
        net_err_t err = netif_put_out(netif, pktbuf, -1);
        if (err < 0) {
            dbg_info(DBG_NETIF, "send to netif queue failed %d", err);
            pktbuf_free(pktbuf);
            return err;
        }
    }
    return netif->ops->xmit(netif);
}