#ifndef ARP_H
#define ARP_H

#include "sys.h"
#include "netif.h"
#include "ipaddr.h"
#include "ether.h"

#define ARP_HW_ETHER            0x1             // 以太网类型
#define ARP_REQUEST             0x1             // ARP请求包
#define ARP_REPLY               0x2             // ARP响应包


#pragma pack(1)
typedef struct _apr_pkt_t {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t send_haddr[ETH_HWA_SIZE];
    uint8_t send_paddr[IPV4_ADDR_SIZE];
    uint8_t target_haddr[ETH_HWA_SIZE];
    uint8_t target_paddr[IPV4_ADDR_SIZE];
} arp_pkt_t;

#pragma pack()


typedef struct _arp_entry_t {
    nlist_node_t no_node;
    uint8_t paddr[IPV4_ADDR_SIZE];
    uint8_t haddr[ETH_HWA_SIZE];
    enum {
        NET_ARP_FREE,
        NET_ARP_RESOLVED,
        NET_ARP_WAITING,
    } state;

    int tmo;
    int retry;              // 请求重试次数，因目标主机可能暂时未能处理，或丢包
    netif_t* netif;         // 包项所对应的网络接口，可用于发包
    nlist_node_t node;       // 下一个表项链接结点
    nlist_t buf_list;        // 待发送的数据包队列
} arp_entry_t;



const uint8_t * arp_find (netif_t * netif, ipaddr_t * ip_addr);
net_err_t arp_init (void);
net_err_t arp_make_request (netif_t * netif, ipaddr_t * ip_addr);
net_err_t arp_make_no_reply (netif_t * netif);
net_err_t arp_in (netif_t * netif, pktbuf_t * pktbuf);
net_err_t arp_make_reply(netif_t * netif, pktbuf_t * pktbuf);
net_err_t arp_resolve (netif_t * netif, ipaddr_t * ipaddr, pktbuf_t * pktbuf);
void arp_clear (netif_t * netif);
void arp_update_from_ipbuf (netif_t * netif, pktbuf_t * pkt);



#endif