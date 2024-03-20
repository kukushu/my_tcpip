#include "ether.h"
#include "dbg.h"
#include "netif.h"
#include "tools.h"
#include "arp.h"
#include "protocol.h"

static net_err_t is_pkt_ok(ether_pkt_t * frame, int total_size) {
    if (total_size > (sizeof(ether_hdr_t) + ETH_MTU)) {
        dbg_warning(DBG_ETHER, "frame size too big: %d", total_size);
        return NET_ERR_SIZE;
    }

    // 虽然以太网规定最小60字节，但是底层驱动收到可能小于这么多
    if (total_size < (sizeof(ether_hdr_t))) {
        dbg_warning(DBG_ETHER, "frame size too small: %d", total_size);
        return NET_ERR_SIZE;
    }

    return NET_ERR_OK;
}

const uint8_t * ether_broadcast_addr (void) {
    static const uint8_t broadcast_addr[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    return broadcast_addr;
}

#if DBG_DISP_ENABLED(DBG_ETHER)
static void display_ether_pkt(char * title, ether_pkt_t * pkt, int size) {
    ether_hdr_t * hdr = (ether_hdr_t *)pkt;

    plat_printf("\n--------------- %s ------------------ \n", title);
    plat_printf("\tlen: %d bytes\n", size);
    dump_mac("\tdest:", hdr->dest);
    dump_mac("\tsrc:", hdr->src);
    plat_printf("\ttype: %04x - ", x_ntohs(hdr->protocol));
    switch (x_ntohs(hdr->protocol)) {
    case NET_PROTOCOL_ARP:
        plat_printf("ARP\n");
        break;
    case NET_PROTOCOL_IPv4:
        plat_printf("IP\n");
        break;
    default:
        plat_printf("Unknown\n");
        break;
    }
    plat_printf("\n");
}
#else
#define display_ether_pkt(title, pkt, size)
#endif

net_err_t ether_raw_out (netif_t * netif, uint16_t protocol, const uint8_t * dest, pktbuf_t * pktbuf) {
    net_err_t err;
    int size = pktbuf_total(pktbuf);
    if (size < ETH_DATA_MIN) {
        dbg_info(DBG_ETHER, "resize from %d to %d", size, (int) ETH_DATA_MIN);
        err = pktbuf_resize(pktbuf, ETH_DATA_MIN);
        if (err < 0) {
            dbg_error(DBG_ETHER, "resize failed: %d", err);
            return err;
        }

        pktbuf_reset_acc(pktbuf);
        pktbuf_seek(pktbuf, size);
        pktbuf_fill(pktbuf, 0, ETH_DATA_MIN - size);
    }
    err = pktbuf_add_header(pktbuf, sizeof(ether_hdr_t), 1);
    if (err < 0) {
        dbg_error(DBG_ETHER, "add header failed: %d", err);
        return NET_ERR_SIZE;
    }

    // 填充以太网帧头，发送
    ether_pkt_t * pkt = (ether_pkt_t*)pktbuf_data(pktbuf);
    plat_memcpy(pkt->hdr.dest, dest, ETH_HWA_SIZE);
    plat_memcpy(pkt->hdr.src, netif->hwaddr.addr, ETH_HWA_SIZE);
    pkt->hdr.protocol = x_htons(protocol);        

    // 显示包信息
    display_ether_pkt("ether out", pkt, size);


    if (plat_memcmp(netif->hwaddr.addr, dest, ETH_HWA_SIZE) == 0) {
       return netif_put_in(netif, pktbuf, -1);
    } else {
        err = netif_put_out(netif, pktbuf, -1);
        if (err < 0) {
            dbg_warning(DBG_ETHER, "put pkt out failed: %d", err);
            return err;
        }
    }
    return netif->ops->xmit(netif);
}

static net_err_t ether_open (netif_t * netif) {
    dbg_info(DBG_ETHER, "ether opened");

    return arp_make_no_reply(netif);
}
static void ether_close (netif_t * netif) {
    arp_clear(netif);
}
static net_err_t ether_in (netif_t * netif, pktbuf_t * buf) {
    dbg_info(DBG_ETHER, "ether in:");

    pktbuf_set_cont(buf, sizeof(ether_hdr_t));
    net_err_t err;

    ether_pkt_t * pkt = (ether_pkt_t *) pktbuf_data(buf);
    if ((err = is_pkt_ok(pkt, buf->total_size)) != NET_ERR_OK) {
        dbg_error(DBG_ETHER, "ether pkt error");
        return err;
    }

    display_ether_pkt("ether in", pkt, buf->total_size);

    switch (x_ntohs(pkt->hdr.protocol)) {
        case NET_PROTOCOL_ARP: {
            dbg_info(DBG_ETHER, "received ARP packet");
            err = pktbuf_remove_header(buf, sizeof(ether_hdr_t));
            if (err < 0) {
                dbg_error(DBG_ETHER, "remove header failed");
            }
            return arp_in(netif,buf);
            break;
        }

        case NET_PROTOCOL_IPv4: {
            dbg_info(DBG_ETHER, "received IPv4 packet");

            break;
        }
    }
    pktbuf_free(buf);
    return NET_ERR_OK;
}
static net_err_t ether_out (netif_t * netif, ipaddr_t * ipaddr, pktbuf_t * pktbuf) {
    if (ipaddr_is_equal(&netif->ipaddr, ipaddr)) {
        return ether_raw_out(netif, NET_PROTOCOL_IPv4, (const uint8_t *)netif->hwaddr.addr, pktbuf);
    }

    const uint8_t * hwaddr = arp_find(netif, ipaddr);
    if (!hwaddr) {
        return arp_resolve(netif, ipaddr, pktbuf);
    } else {
        return ether_raw_out(netif, NET_PROTOCOL_IPv4, hwaddr, pktbuf);
    }
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