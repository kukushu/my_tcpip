#include "sys.h"
#include "net.h"
#include "netif_pcap.h"
#include "dbg.h"
#include "net_cfg.h"
#include "nlist.h"
#include "mblock.h"
#include "pktbuf.h"


net_err_t netdev_init (void) {
    netif_pcap_open();
    return NET_ERR_OK;
}

void dbg_test (void) {
    dbg_error(DBG_TEST, "dbg_info : %s\n", "just_for_test");
    dbg_warning(DBG_TEST, "dbg_info : %s\n", "just_for_test");
    dbg_info(DBG_TEST, "dbg_info : %s\n", "just_for_test");
    dbg_assert(2 == 1, "failed");

}


typedef struct _tnode_t {
    int id;
    nlist_node_t node;
} tnode_t;
void nlist_test (void) {
    #define NODE_CNT    10
    tnode_t node[NODE_CNT];
    nlist_t list;
    nlist_node_t * p;

    nlist_init(&list);
    for (int i = 0; i < NODE_CNT; i ++) {
        node[i].id = i;
        nlist_insert_first(&list, &node[i].node);
    }

    plat_printf("insert first\n");
    nlist_for_each(p, list) {
        tnode_t * tnode = nlist_entry(p, tnode_t, node);
        plat_printf("%d\n", tnode->id);
    }

    plat_printf("remove first\n");
    for (int i = 0; i < NODE_CNT; i ++) {
        p = nlist_remove_first(&list);
        plat_printf("id: %d\n", nlist_entry(p, tnode_t, node)->id);
    }        

    for (int i = 0; i < NODE_CNT; i ++) {
        nlist_insert_last(&list, &node[i].node);
    }

    plat_printf("insert last\n");
    nlist_for_each(p, list) {
        tnode_t * tnode = nlist_entry(p, tnode_t, node);
        plat_printf("%d\n", tnode->id);
    }

    plat_printf("remove last\n");
    for (int i = 0; i < NODE_CNT; i ++) {
        p = nlist_remove_last(&list);
        plat_printf("id: %d\n", nlist_entry(p, tnode_t, node)->id);
    }

    plat_printf("insert after\n");
    for (int i = 0; i < NODE_CNT; i ++) {
        nlist_insert_after(&list, nlist_first(&list), &node[i].node);
    }
    nlist_for_each(p, list) {
        tnode_t * tnode = nlist_entry(p, tnode_t, node);
        plat_printf("%d\n", tnode->id);
    }

}

void mblock_test (void) {
    mblock_t blist;
    static uint8_t buffer[10][100];

    void * temp[10];
    mblock_init(&blist, buffer, 100, 10, NLOCKER_THREAD);
    for (int i = 0; i < 10; i ++) {
        temp[i] = mblock_alloc(&blist, 0);
        printf("block: %p, free count: %d\n", temp[i], mblock_free_cnt(&blist));
    }
    for (int i = 0; i < 10; i ++) {
        mblock_free(&blist, temp[i]);
        printf("free count: %d\n", mblock_free_cnt(&blist));
    }
    mblock_destroy(&blist);
}

void pktbuf_test(void) {
    static uint16_t temp[1000];
    static uint16_t read_temp[1000];

    for (int i = 0; i < 1024; i ++) {
        temp[i] = i;
    }


    net_err_t err;
    pktbuf_t * buf = pktbuf_alloc(200);
    pktbuf_check(buf);
    for (int i = 0; i < 3; i ++) {
        err = pktbuf_add_header(buf, 80, NOT_CONT);
        dbg_assert(err == NET_ERR_OK, "pktbuf_add_header continue failed");
    }
    pktbuf_check(buf);
    for (int i = 0; i < 3; i ++) {
        err = pktbuf_remove_header(buf, 78); 
        dbg_assert(err == NET_ERR_OK, "pktbuf_remove_header failed");
        pktbuf_check(buf);
    }





}
void basic_test (void) {
    //nlist_test();
    //mblock_test();
    pktbuf_test();
}

int main (void) 
{
    //dbg_test();
    net_init();
    basic_test();
    net_start();

    netdev_init();



    while (1) {
        sys_sleep(10);
    }

    return 0;
}