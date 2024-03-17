#include "netif_pcap.h"
#include "sys_plat.h"
#include "exmsg.h"
#include "dbg.h"
#include "netif.h"
#include "ether.h"

void recv_thread (void * arg) {
    plat_printf("recv thread is running\n");

    netif_t * netif = (netif_t *) arg;
    pcap_t * pcap = (pcap_t *) netif->ops_data;

    while (1) {
        struct pcap_pkthdr * pkthdr;
        const uint8_t * pkt_data;
        if (pcap_next_ex(pcap, &pkthdr, &pkt_data) != 1) {
            continue;
        }

        pktbuf_t * pktbuf = pktbuf_alloc(pkthdr->len);
        if (pktbuf == (pktbuf_t *) 0) {
            dbg_warning(DBG_NETIF, "pktbuf alloc failed");
            continue;
        }

        pktbuf_write(pktbuf, (uint8_t *) pkt_data, pkthdr->len);
        net_err_t err = netif_put_in(netif, pktbuf, -1);
        if (err < 0) {
            dbg_error(DBG_EXMSG, "recv_thread failed");
        }
    }
}

void xmit_thread (void * arg) {
    plat_printf("xmit thread is running\n");
    static uint8_t rw_buffer[1514];
    netif_t * netif = (netif_t *) arg;
    pcap_t * pcap = (pcap_t *) netif->ops_data;
    while (1) {
        pktbuf_t * pktbuf = netif_get_out(netif, 0);
        if (pktbuf == (pktbuf_t *) 0) {
            continue;
        } 
        int total_size = pktbuf->total_size;
        plat_memset(rw_buffer, 0, sizeof(rw_buffer));
        pktbuf_read(pktbuf, rw_buffer, total_size);
        pktbuf_free(pktbuf);
        if (pcap_inject(pcap, rw_buffer, total_size) == -1) {
            fprintf(stderr, "pcap_inject failed\n");
            continue;
        }
    }
}
net_err_t netif_pcap_open (netif_t * netif, void * ops_data) {
    pcap_data_t * pcap_data = (pcap_data_t *) ops_data;
    pcap_t * pcap = pcap_device_open(pcap_data->ip, pcap_data->hwaddr);
    if (pcap == (pcap_t *) 0) {
        dbg_error(DBG_NETIF, "pcap open failed! name: %s", netif->name);
        return NET_ERR_SYS;
    }

    netif->ops_data = pcap;

    netif->type = NETIF_TYPE_ETHER;
    netif->mtu = ETH_MTU;
    netif_set_hwaddr(netif, pcap_data->hwaddr, NETIF_HWADDR_SIZE);

    sys_thread_create(recv_thread, netif);
    sys_thread_create(xmit_thread, netif);
    return NET_ERR_OK;
}

void netif_pcap_close (netif_t * netif) {
    pcap_t * pcap = (pcap_t *) netif->ops_data;
    pcap_close(pcap);
}

net_err_t netif_pcap_xmit (netif_t * netif) {
    return NET_ERR_OK;
}

const netif_ops_t netdev_ops = {
    .open = netif_pcap_open,
    .close = netif_pcap_close,
    .xmit = netif_pcap_xmit,
};
