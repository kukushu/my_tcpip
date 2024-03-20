#include "arp.h"
#include "protocol.h"
#include "dbg.h"
#include "tools.h"
#include "mblock.h"
#include "timer.h"

#define to_scan_cnt(tmo)     (tmo / ARP_TIMER_TMO)

static net_timer_t cache_timer;
static arp_entry_t cache_tbl[ARP_CACHE_SIZE];
static mblock_t cache_mblock;
static nlist_t cache_list;
static const uint8_t empty_hwaddr[] = { 0, 0, 0, 0, 0, 0 };

#if DBG_DISP_ENABLED(DBG_ARP)

void display_arp_entry(arp_entry_t* entry) {
    plat_printf("%d: ", (int)(entry - cache_tbl));       // 序号
    dump_ip_buf(" ip:", entry->paddr);
    dump_mac(" mac:", entry->haddr);
    plat_printf(" tmo: %d, retry: %d, %s, buf: %d\n",
        entry->tmo, entry->retry, entry->state == NET_ARP_RESOLVED ? "stable" : "pending",
        nlist_count(&entry->buf_list));
}

/**
 * @brief 显示ARP表中所有项
 */
void display_arp_tbl(void) {
    plat_printf("\n------------- ARP table start ---------- \n");

    arp_entry_t* entry = cache_tbl;
    for (int i = 0; i < ARP_CACHE_SIZE; i++, entry++) {
        /*
        if ((entry->state != NET_ARP_FREE) && (entry->state != NET_ARP_RESOLVED)) {
            continue;
        }
        */
        display_arp_entry(entry);
    }

    plat_printf("------------- ARP table end ---------- \n");
}


static void arp_pkt_display (arp_pkt_t * packet) {
    uint16_t opcode = x_ntohs(packet->opcode);

    plat_printf("--------------- arp start ------------------\n");
    plat_printf("    htype:%x\n", x_ntohs(packet->htype));
    plat_printf("    pype:%x\n", x_ntohs(packet->ptype));
    plat_printf("    hlen: %x\n", packet->hlen);
    plat_printf("    plen:%x\n", packet->plen);
    plat_printf("    type:%04x  ", opcode);
    switch (opcode) {
    case ARP_REQUEST:
        plat_printf("request\n");
        break;;
    case ARP_REPLY:
        plat_printf("reply\n");
        break;
    default:
        plat_printf("unknown\n");
        break;
    }
    dump_ip_buf("    sender:", packet->send_paddr);
    dump_mac("  mac:", packet->send_haddr);
    plat_printf("\n");
    dump_ip_buf("    target:", packet->target_paddr);
    dump_mac("  mac:", packet->target_haddr);
    plat_printf("\n");
    plat_printf("--------------- arp end ------------------ \n");
}

#else 
#define arp_pkt_display(packet)
#define display_arp_entry(entry)
#define display_arp_tbl()
#endif


static net_err_t is_pkt_ok(arp_pkt_t* arp_packet, uint16_t size, netif_t* netif) {
    if (size < sizeof(arp_pkt_t)) {
        dbg_warning(DBG_ARP, "packet size error: %d < %d", size, (int)sizeof(arp_pkt_t));
        return NET_ERR_SIZE;
    }

    // 上层协议和硬件类型不同的要丢掉
    if ((x_ntohs(arp_packet->htype) != ARP_HW_ETHER) ||
        (arp_packet->hlen != ETH_HWA_SIZE) ||
        (x_ntohs(arp_packet->ptype) != NET_PROTOCOL_IPv4) ||
        (arp_packet->plen != IPV4_ADDR_SIZE)) {
        dbg_warning(DBG_ARP, "packet incorrect");
        return NET_ERR_NOT_SUPPORTED;
    }

    // 可能还有RARP等类型，全部丢掉
    uint32_t opcode = x_ntohs(arp_packet->opcode);
    if ((opcode != ARP_REQUEST) && (opcode != ARP_REPLY)) {
        dbg_warning(DBG_ARP, "unknown opcode=%d", arp_packet->opcode);
        return NET_ERR_NOT_SUPPORTED;
    }

    return NET_ERR_OK;
}

static net_err_t cache_init () {
    nlist_init(&cache_list);

    net_err_t err = mblock_init(&cache_mblock, cache_tbl, sizeof(arp_entry_t), ARP_CACHE_SIZE, NLOCKER_THREAD);
    if (err != NET_ERR_OK) {
        return err;
    }
    return NET_ERR_OK;
}

static void cache_clear_all(arp_entry_t * entry) {
    dbg_info(DBG_ARP, "clear %d packet:", nlist_count(&entry->buf_list));
    dbg_dump_ip_buf(DBG_ARP, "ip:", entry->paddr);
    dbg_dump_mac(DBG_ARP, "mac:", entry->haddr);

    nlist_node_t * first;
    while (first = nlist_remove_first(&entry->buf_list)) {
        pktbuf_t * buf = nlist_entry(first, pktbuf_t, node);
        pktbuf_free(buf);
    }
}

static arp_entry_t * cache_alloc (int force) {
    arp_entry_t * cache = mblock_alloc(&cache_mblock, -1);
    if ((cache == (arp_entry_t *) 0) && force) {
        nlist_node_t * node = nlist_remove_last(&cache_list);
        if (!node) {
            dbg_warning(DBG_ARP, "allocate arp entry failed");
            return (arp_entry_t *) 0;
        }
        cache = nlist_entry(node, arp_entry_t, node);
        cache_clear_all(cache);
    }
    if (cache) {
        plat_memset(cache, 0, sizeof(arp_entry_t));
        cache->state = NET_ARP_FREE;
        nlist_node_init(&cache->node);
        nlist_init(&cache->buf_list);
    }
    return cache;
}

static void cache_free (arp_entry_t * entry) {
    cache_clear_all(entry);
    nlist_remove(&cache_list, &entry->node);
    mblock_free(&cache_mblock, entry);
}

static arp_entry_t * cache_find (uint8_t * ipaddr) {
    nlist_node_t * node = nlist_first(&cache_list);
    while (node) {
        arp_entry_t * entry = nlist_entry(node, arp_entry_t, node);
        if (plat_memcmp(entry->paddr, ipaddr, IPV4_ADDR_SIZE) == 0) {
            nlist_remove(&cache_list, node);
            nlist_insert_first(&cache_list, node);
            return entry;
        } else {
            node = nlist_node_next(node);
        }
    }
    return (arp_entry_t *) 0;
}

static void cache_entry_set(arp_entry_t * entry, const uint8_t * ipaddr, const uint8_t * hwaddr, netif_t * netif, int state) {
    entry->netif = netif;
    plat_memcpy(entry->haddr, hwaddr, ETH_HWA_SIZE);
    plat_memcpy(entry->paddr, ipaddr, IPV4_ADDR_SIZE);
    entry->state = state;

    if (state == NET_ARP_RESOLVED) {
        entry->tmo = to_scan_cnt(ARP_ENTRY_STABLE_TMO);
    } else {
        entry->tmo = to_scan_cnt(ARP_ENTRY_PENDING_TMO);
    }
    entry->retry = ARP_ENTRY_RETRY_CNT;

}

static net_err_t cache_send_all (arp_entry_t * entry) {
    dbg_info(DBG_ARP, "send %d packet:", nlist_count(&entry->buf_list));
    dbg_dump_ip_buf(DBG_ARP, "ip: ", entry->paddr);
    dbg_dump_mac(DBG_ARP, "mac: ", entry->haddr);

    nlist_node_t * first;
    while ((first = nlist_remove_first(&entry->buf_list))) {
        pktbuf_t* buf = nlist_entry(first, pktbuf_t, node);

        // 将数据包通过以太网发送出去，发往指定的mac地址
        net_err_t err = ether_raw_out(entry->netif, NET_PROTOCOL_IPv4, entry->haddr, buf);
        if (err < 0) {
            // 发送成功时，由底层释放，失败由自己发送
            pktbuf_free(buf);
            return err;
        }
    }

    return  NET_ERR_OK;
}

static net_err_t cache_insert (netif_t * netif, uint8_t * ipaddr, uint8_t * hwaddr, int force) {
    arp_entry_t * entry = cache_find(ipaddr);
    if (!entry) {
        entry = cache_alloc(force);
        if (!entry) {
            dbg_dump_ip_buf(DBG_ARP, "alloc failed! sender ip:", ipaddr);
            return NET_ERR_NONE;
        }
        cache_entry_set(entry, ipaddr, hwaddr, netif, NET_ARP_RESOLVED);
        nlist_insert_first(&cache_list, &entry->node);
        dbg_dump_ip_buf(DBG_ARP, "insert an entry, sender ip:", ipaddr);
    } else {
        dbg_dump_ip_buf(DBG_ARP, "update arp entry, sender ip:", ipaddr);
        dbg_dump_mac(DBG_ARP, "sender mac:", hwaddr);
        cache_entry_set(entry, ipaddr, hwaddr, netif, NET_ARP_RESOLVED);
        if (nlist_first(&cache_list) != &entry->node) {
            nlist_remove(&cache_list, &entry->node);
            nlist_insert_first(&cache_list, &entry->node);
        }
        net_err_t err = cache_send_all(entry);
        if (err < 0) {
            dbg_error(DBG_ARP, "send pakcet in entry failed");
            return err;
        } 
    }
    display_arp_tbl();
    return NET_ERR_OK;
}

const uint8_t * arp_find (netif_t * netif, ipaddr_t * ipaddr) {
    if (ipaddr_is_local_broadcast(ipaddr) || ipaddr_is_direct_broadcast(ipaddr, &netif->netmask)) {
        return ether_broadcast_addr();
    }
    arp_entry_t * entry = cache_find(ipaddr->a_addr);
    if (entry && (entry->state == NET_ARP_RESOLVED)) {
        return entry->haddr;
    }
    return (const uint8_t *) 0;
}

void arp_cache_tmo (struct _net_timer_t * timer, void * arg) {
    nlist_node_t * curr, * next;
    int changed_cnt = 0;

    for (curr = cache_list.first; curr; curr = next) {
        next = nlist_node_next(curr);
        arp_entry_t * entry = nlist_entry(curr, arp_entry_t, node);
        if (--entry->tmo > 0) {
            continue;
        }
        changed_cnt ++;
        switch (entry->state) {
            case NET_ARP_RESOLVED: 
                dbg_info(DBG_ARP, "state to waiting");
                ipaddr_t ipaddr;
                ipaddr_from_buf(&ipaddr, entry->paddr);
                entry->state = NET_ARP_WAITING;
                entry->tmo = to_scan_cnt(ARP_ENTRY_PENDING_TMO);
                entry->retry = to_scan_cnt(ARP_ENTRY_RETRY_CNT);
                arp_make_request(entry->netif, &ipaddr);
                break;
            case NET_ARP_WAITING:
                if (--entry->retry == 0) {
                    dbg_info(DBG_ARP, "waiting tmo, free it");
                    display_arp_entry(entry);
                    cache_free(entry);
                } else {
                    dbg_info(DBG_ARP, "waiting tmo, send request");
                    display_arp_entry(entry);
                    ipaddr_t ipaddr;
                    ipaddr_from_buf(&ipaddr, entry->paddr);
                    entry->tmo = to_scan_cnt(ARP_ENTRY_PENDING_TMO);
                    arp_make_request(entry->netif, &ipaddr);
                } 
                break;
            default:
                dbg_error(DBG_ARP, "unknown state");
                break;
        }
    }
    display_arp_tbl();
    if (changed_cnt) {
        dbg_info (DBG_ARP, "%d arp entry changed", changed_cnt);
        display_arp_tbl();
    }
}

net_err_t arp_init (void) {
    net_err_t err = cache_init();

    if (err < 0) {
        dbg_error(DBG_ARP, "arp cache init failed");
        return err;
    }

    //err = net_timer_add(&cache_timer, "arp timer", arp_cache_tmo, (void *) 0, ARP_TIMER_TMO * 1000, NET_TIMER_RELOAD);


    return NET_ERR_OK;
}
net_err_t arp_make_request (netif_t * netif, ipaddr_t * ip_addr) {
    pktbuf_t * pktbuf = pktbuf_alloc(sizeof(arp_pkt_t));
    if (pktbuf == (pktbuf_t *) 0) {
        dbg_dump_ip(DBG_ARP, "allocate arp packet failed. ip :", ip_addr);
        return NET_ERR_NONE;
    }
    pktbuf_set_cont(pktbuf, sizeof(arp_pkt_t));
    
    arp_pkt_t * arp_packet = (arp_pkt_t *) pktbuf_data(pktbuf);
    arp_packet->htype = x_htons(ARP_HW_ETHER);
    arp_packet->ptype = x_htons(NET_PROTOCOL_IPv4);
    arp_packet->hlen = ETH_HWA_SIZE;
    arp_packet->plen = IPV4_ADDR_SIZE;
    arp_packet->opcode = x_htons(ARP_REQUEST);
    plat_memcpy(arp_packet->send_haddr, netif->hwaddr.addr, ETH_HWA_SIZE);
    ipaddr_to_buf(&netif->ipaddr, arp_packet->send_paddr);
    plat_memcpy(arp_packet->target_haddr, empty_hwaddr, ETH_HWA_SIZE);
    ipaddr_to_buf(ip_addr, arp_packet->target_paddr);

    arp_pkt_display(arp_packet);

    net_err_t err = ether_raw_out(netif, NET_PROTOCOL_ARP, ether_broadcast_addr(), pktbuf);
    if (err < 0) {
        pktbuf_free(pktbuf);
    }

    return err;
}

net_err_t arp_make_no_reply (netif_t * netif) {
    dbg_info(DBG_ARP, "send an no_reply packet");
    return arp_make_request(netif, &netif->ipaddr); 
}

net_err_t arp_make_reply(netif_t * netif, pktbuf_t * pktbuf) {
    arp_pkt_t * arp_packet = (arp_pkt_t *) pktbuf_data(pktbuf);

    arp_packet->opcode = x_htons(ARP_REPLY);
    plat_memcpy(arp_packet->target_haddr, arp_packet->send_haddr, ETH_HWA_SIZE);
    plat_memcpy(arp_packet->target_paddr, arp_packet->send_paddr, IPV4_ADDR_SIZE);
    plat_memcpy(arp_packet->send_haddr, netif->hwaddr.addr, ETH_HWA_SIZE);
    ipaddr_to_buf(&netif->ipaddr, arp_packet->send_paddr);
    
    arp_pkt_display(arp_packet);
    return ether_raw_out(netif, NET_PROTOCOL_ARP, arp_packet->target_haddr, pktbuf);
}

net_err_t arp_in (netif_t * netif, pktbuf_t * pktbuf) {
    dbg_info(DBG_ARP, "arp in");
    net_err_t err = pktbuf_set_cont(pktbuf, sizeof(arp_pkt_t));
    if (err < 0) {
        return err;
    }
    arp_pkt_t * arp_packet = (arp_pkt_t *) pktbuf_data(pktbuf);
    if (is_pkt_ok(arp_packet, pktbuf->total_size, netif) != NET_ERR_OK) {
        return err;
    }
    arp_pkt_display(arp_packet);

    ipaddr_t target_ip;
    ipaddr_from_buf(&target_ip, arp_packet->target_paddr);
    if (ipaddr_is_equal(&target_ip, &netif->ipaddr)) {
        dbg_info(DBG_ARP, "received an arp for me");
        cache_insert(netif, arp_packet->send_paddr, arp_packet->send_haddr, 1);
        if (x_ntohs(arp_packet->opcode) == ARP_REQUEST) {
            dbg_info(DBG_ARP, "arp is request. try to send reply");
            return arp_make_reply(netif, pktbuf);
        }
    } else {
        dbg_info(DBG_ARP, "received an arp not for me");
        cache_insert(netif, arp_packet->send_paddr, arp_packet->send_haddr, 0);
    }

    pktbuf_free(pktbuf);
    return NET_ERR_OK;
}

net_err_t arp_resolve (netif_t * netif, ipaddr_t * _ipaddr, pktbuf_t * pktbuf) {
    uint8_t * ipaddr = _ipaddr->a_addr;
    arp_entry_t * entry = cache_find(ipaddr);
    if (entry) {
        dbg_info(DBG_ARP, "found an arp entry");
        if (entry->state == NET_ARP_RESOLVED) {
            return ether_raw_out(netif, NET_PROTOCOL_IPv4, entry->haddr, pktbuf);
        }
        if (nlist_count(&entry->buf_list) <= ARP_MAX_PKT_WAIT) {
            dbg_info(DBG_ARP, "insert packet to arp entry");
            nlist_insert_last(&entry->buf_list, &pktbuf->node);
            return NET_ERR_OK;
        } else {
            dbg_warning(DBG_ARP, "too many");
            return NET_ERR_FULL;
        }
    } else {
        entry = cache_alloc(1);
        if (entry == (arp_entry_t *) 0) {
            dbg_error(DBG_ARP, "alloc arp failed");
            return NET_ERR_MEM;
        }
        cache_entry_set(entry, ipaddr, empty_hwaddr, netif, NET_ARP_WAITING);
        nlist_insert_first(&cache_list, &entry->node);
        dbg_info(DBG_ARP, "insert packet to arp");
        nlist_insert_last(&entry->buf_list, &pktbuf->node);

        display_arp_tbl();
        return arp_make_request(netif, _ipaddr);
    }
}

void arp_clear (netif_t * netif) {
    nlist_node_t * node;
    for (node = nlist_first(&cache_list); node; ) {
        nlist_node_t * next = nlist_node_next(node);
        arp_entry_t * e = nlist_entry(node, arp_entry_t, node);
        if (e->netif == netif) {
            cache_clear_all(e);
            nlist_remove(&cache_list, node);
            mblock_free(&cache_mblock, e);
        }
        node = next;
    }
}





