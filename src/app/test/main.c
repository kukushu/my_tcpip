#include <stdio.h>
#include "sys_plat.h"


void thread1(void * string) {
    while (1) {
        plat_printf("thread1: %s\n", (char *) string);
        sys_sleep(1000);
    }
}
void thread2(void * string) {
    while (1) {
        plat_printf("thread2: %s\n", (char *) string);
        sys_sleep(1000);
    }
}

int main (void) 
{
    sys_thread_create(thread1, "AAAAA");
    sys_thread_create(thread2, "BBBBB");


    pcap_t * pcap = pcap_device_open(netdev0_phy_ip_linux, netdev0_hwaddr_linux);
    while (pcap) {
        static uint8_t buffer[1514];
        static int counter = 0;
        struct pcap_pkthdr * pkthdr;
        const uint8_t * pkt_data;



        plat_printf("begin test: %d\n", counter ++);
        if (pcap_next_ex(pcap, &pkthdr, &pkt_data) != 1) {
            continue;
        }

        int len = pkthdr->len;
        plat_memcpy(buffer, pkt_data, len);
        buffer[0] = 1;
        buffer[1] = 2;
        buffer[3] = 3;

        if (pcap_inject(pcap, buffer, len) == -1) {
            plat_printf("pcap send: send packet failed %s\n", pcap_geterr(pcap));
            break;
        }
    }
    return 0;
}