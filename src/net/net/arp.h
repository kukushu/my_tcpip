#ifndef ARP_H
#define ARP_H

#include "sys.h"
#include "netif.h"
#include "ipaddr.h"

const uint8_t * arp_find (netif_t * netif, ipaddr_t * ip_addr);


#endif