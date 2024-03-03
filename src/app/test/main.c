#include <stdio.h>
#include "sys_plat.h"
#include <stdatomic.h>

static sys_sem_t read_sem, write_sem;
static sys_mutex_t mutex;
static int count;



static char test_buffer[100];
static int write_index, read_index;

void thread1(void * string) {
    for (int i = 0; i < 2 * sizeof(test_buffer); i ++) {
        sys_sem_wait(read_sem, 0);
        uint8_t data = test_buffer[read_index ++];
        if (read_index >= sizeof(test_buffer)) {
            read_index = 0;
        }
        plat_printf("thread 1 : read data %d\n", data);
        sys_sem_notify(write_sem);
        sys_sleep(200);
    }
}
void thread2(void * string) {
    for (int i = 0; i < 2 * sizeof(test_buffer); i ++) {
        sys_sem_wait(write_sem, 0);
        test_buffer[write_index ++] = i;
        if (write_index >= sizeof(test_buffer)) {
            write_index = 0;
        }
        plat_printf("thread 2 : write data = %d\n", i);
        sys_sem_notify(read_sem);
    }
}

int main (void) 
{
    mutex = sys_mutex_create();
    read_sem = sys_sem_create(0);
    write_sem = sys_sem_create(100);
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