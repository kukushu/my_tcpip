#include "sys_plat.h"
#include "net.h"
#include "netif_pcap.h"
#include "dbg.h"
#include "net_cfg.h"
#include "nlist.h"



net_err_t netdev_init (void) {
    netif_pcap_open();
    return NET_ERR_OK;
}

void dbg_test (void) {
    dbg_error(DBG_TEST, "dbg_info : %s\n", "just_for_test");
    dbg_warning(DBG_TEST, "dbg_info : %s\n", "just_for_test");
    dbg_info(DBG_TEST, "dbg_info : %s\n", "just_for_test");
    dbg_debug(2 == 1, "failed");

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

void basic_test (void) {
    //nlist_test();
}

int main (void) 
{
    //dbg_test();
    basic_test();
    net_init();
    net_start();

    netdev_init();



    while (1) {
        sys_sleep(10);
    }

    return 0;
}