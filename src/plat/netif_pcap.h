#ifndef NETIF_PCAP_H
#define NETIF_PCAP_H

#include "sys.h"
#include "net_err.h"

typedef struct _pcap_data_t {
    const char * ip;
    const uint8_t * hwaddr;
} pcap_data_t;


#endif