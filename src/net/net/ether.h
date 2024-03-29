#ifndef ETHER_H
#define ETHER_H

#include "netif.h"
#include "pktbuf.h"
#include "sys.h"

#define ETH_HWA_SIZE        6
#define ETH_MTU             1500
#define ETH_DATA_MIN        46

#pragma pack(1)

typedef struct _ether_hdr_t {
    uint8_t dest[ETH_HWA_SIZE];
    uint8_t src[ETH_HWA_SIZE];
    uint16_t protocol;
} ether_hdr_t;

typedef struct _ether_pkt_t {
    ether_hdr_t hdr;
    uint8_t data[ETH_MTU];
} ether_pkt_t;

#pragma pack()

const uint8_t * ether_broadcast_addr (void);
net_err_t ether_raw_out (netif_t * netif, uint16_t protocol, const uint8_t * dest, pktbuf_t * pktbuf);
net_err_t ether_init (void);

#endif