#include "sys.h"
#include "protocol.h"
#include "net.h"
#include "netif_pcap.h"
#include "dbg.h"
#include "net_cfg.h"
#include "nlist.h"
#include "mblock.h"
#include "pktbuf.h"
#include "netif.h"
#include "timer.h"
#include "ipaddr.h"
#include "ipv4.h"
#include "ping/ping.h"

pcap_data_t netdev0_data = {.ip = netdev0_phy_ip_linux, .hwaddr = netdev0_hwaddr_linux};
extern const netif_ops_t netdev_ops;

net_err_t netdev_init (void) {

    netif_t * netif = netif_open("netif 0", &netdev_ops, &netdev0_data);
    if (netif == (netif_t *) 0) {
        dbg_error(DBG_INIT,"netif open failed");
        exit(-1);
    }

	ipaddr_t ip, mask, gw;
	ipaddr_from_str(&ip, netdev0_ip);
	ipaddr_from_str(&mask, netdev0_mask);
	ipaddr_from_str(&gw, netdev0_gw);
	netif_set_addr(netif, &ip, &mask, &gw);

	netif_set_active(netif);

	pktbuf_t * pktbuf = pktbuf_alloc(32);
	pktbuf_fill(pktbuf, 0x53, 32);
	ipaddr_t dest_ipaddr;
	ipaddr_from_str(&dest_ipaddr, "192.168.48.1");
	/*
	netif_out(netif, (ipaddr_t *) &ipaddr, pktbuf);

	pktbuf = pktbuf_alloc(32);
	pktbuf_fill(pktbuf, 0xa5, 32);
	ipaddr_from_str(&ipaddr, "192.168.48.255");
	netif_out(netif, (ipaddr_t *) &ipaddr, pktbuf);
	*/
	ipaddr_t src_ipaddr;
	ipaddr_from_str(&src_ipaddr, "192.168.48.3");
	//ipv4_out(NET_PROTOCOL_ICMPv4, &dest_ipaddr, &src_ipaddr, pktbuf);
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
    nlist_for_each(p, &list) {
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
    nlist_for_each(p, &list) {
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
    nlist_for_each(p, &list) {
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

    // 初始化数据空间
	for (int i = 0; i < 1024; i++) {
		temp[i] = i;
	}

    // 简单的分配和释放, 2000字节.注意打开pktbuf的显示，方便观察
	pktbuf_t * buf = pktbuf_alloc(200);
	
	pktbuf_free(buf);

	// 添加头部空间
	buf = pktbuf_alloc(200);

    // 要求连续的头部添加。最终可以到看，有些包的头部会有一些空间小于33
    // 由于空间不够，只能舍弃
	for (int i = 0; i < 5; i++) {
		pktbuf_add_header(buf, 33, 1);      // 连续的空间
	}
	for (int i = 0; i < 5; i++) {
		pktbuf_remove_header(buf, 33);      // 移除
	}

    // 与连续分配的要求相比，总的包数量小一些，且除第一个块外，其它
    // 块没有开头浪费的空间
	for (int i = 0; i < 5; i++) {
		pktbuf_add_header(buf, 33, 0);		// 非连续添加
	}
	for (int i = 0; i < 5; i++) {
		pktbuf_remove_header(buf, 33);
	}
	pktbuf_free(buf);

	// 大小的调整，先变大变小
	buf = pktbuf_alloc(0);  // 大小为0
	pktbuf_resize(buf, 32);
	pktbuf_resize(buf, 288);
	pktbuf_resize(buf, 4922);
	pktbuf_resize(buf, 1921);
	pktbuf_resize(buf, 288);
	pktbuf_resize(buf, 32);
	pktbuf_resize(buf, 0);
	pktbuf_free(buf);

	// 两个包的连接。在最终的显示结果中，可以看到两个包之间的连接交叉处
	buf = pktbuf_alloc(689);
	pktbuf_t * sbuf = pktbuf_alloc(892);
	pktbuf_join(buf, sbuf);
	pktbuf_free(buf);

	// 小包的连接测试并调整连续性.先合并一些小的包，以形成很多个小包的连接
    // 然后再调整连续性，可以使链的连接在不断变短
	buf = pktbuf_alloc(32);
	pktbuf_join(buf, pktbuf_alloc(4));
	pktbuf_join(buf, pktbuf_alloc(16));
	pktbuf_join(buf, pktbuf_alloc(54));
	pktbuf_join(buf, pktbuf_alloc(32));
	pktbuf_join(buf, pktbuf_alloc(38));
	pktbuf_set_cont(buf, 44);			// 合并成功，簇变短
	pktbuf_set_cont(buf, 60);			// 合并成功，簇变短
	pktbuf_set_cont(buf, 64);			// 合并成功，簇变短
	pktbuf_set_cont(buf, 128);			// 合并成功，簇变短
	pktbuf_set_cont(buf, 135);			// 失败，超过128
	pktbuf_free(buf);

	// 准备一些不同大小的包链，方便后面读写测试
	buf = pktbuf_alloc(32);
	pktbuf_join(buf, pktbuf_alloc(4));
	pktbuf_join(buf, pktbuf_alloc(16));
	pktbuf_join(buf, pktbuf_alloc(54));
	pktbuf_join(buf, pktbuf_alloc(32));
	pktbuf_join(buf, pktbuf_alloc(38));
	pktbuf_join(buf, pktbuf_alloc(512));

    // 读写测试。写超过1包的数据，然后读取
	pktbuf_reset_acc(buf);
	pktbuf_write(buf, (uint8_t *)temp, pktbuf_total(buf));      // 16位的读写
	plat_memset(read_temp, 0, sizeof(read_temp));
	pktbuf_reset_acc(buf);
	pktbuf_read(buf, (uint8_t*)read_temp, pktbuf_total(buf));
	if (plat_memcmp(temp, read_temp, pktbuf_total(buf)) != 0) {
		printf("not equal.");
		exit(-1);
	}

	// 定位读写，不超过1个块
	plat_memset(read_temp, 0, sizeof(read_temp));
	pktbuf_seek(buf, 18 * 2);
	pktbuf_read(buf, (uint8_t*)read_temp, 56);
	if (plat_memcmp(temp + 18, read_temp, 56) != 0) {
		printf("not equal.");
		exit(-1);
	}

    // 定位跨一个块的读写测试, 从170开始读，读56
	plat_memset(read_temp, 0, sizeof(read_temp));
	pktbuf_seek(buf, 85 * 2);
	pktbuf_read(buf, (uint8_t*)read_temp, 256);
	if (plat_memcmp(temp + 85, read_temp, 256) != 0) {
		printf("not equal.");
		exit(-1);
	}

	// 数据的复制
	pktbuf_t* dest = pktbuf_alloc(1024);
	pktbuf_seek(buf, 200);      // 从200处开始读
	pktbuf_seek(dest, 600);     // 从600处开始写
	pktbuf_copy(dest, buf, 122);    // 复制122个字节

    // 重新定位到600处开始读
	plat_memset(read_temp, 0, sizeof(read_temp));
	pktbuf_seek(dest, 600);
	pktbuf_read(dest, (uint8_t*)read_temp, 122);    // 读122个字节
	if (plat_memcmp(temp + 100, read_temp, 122) != 0) { // temp+100，实际定位到200字节偏移处
		printf("not equal.");
		exit(-1);
	}

	// 填充测试
	pktbuf_seek(dest, 0);
	pktbuf_fill(dest, 53, pktbuf_total(dest));

	plat_memset(read_temp, 0, sizeof(read_temp));
	pktbuf_seek(dest, 0);
	pktbuf_read(dest, (uint8_t*)read_temp, pktbuf_total(dest));
	for (int i = 0; i < pktbuf_total(dest); i++) {
		if (((uint8_t *)read_temp)[i] != 53) {
			printf("not equal.");
			exit(-1);
		}
	}

	pktbuf_free(dest);
	pktbuf_free(buf);       // 可以进去调试，在退出函数前看下所有块是否全部释放完毕



}

void timer0_proc(net_timer_t* timer, void * arg) {
	static int count = 1;
	printf("this is %s: %d\n", timer->name, count++);
}

void timer1_proc(net_timer_t* timer, void * arg) {
	static int count = 1;
	printf("this is %s: %d\n", timer->name, count++);
}

void timer2_proc(net_timer_t* timer, void * arg) {
	static int count = 1;
	printf("this is %s: %d\n", timer->name, count++);
}

void timer3_proc(net_timer_t* timer, void * arg) {
	static int count = 1;
	printf("this is %s: %d\n", timer->name, count++);
}


void timer_test (void) {
	static net_timer_t t0, t1, t2, t3;
	net_timer_add(&t0, "t0", timer0_proc, (void *)0, 200, 0);

	// 自动重载定时器
	net_timer_add(&t1, "t1", timer1_proc, (void *)0, 1000, NET_TIMER_RELOAD);
	net_timer_add(&t2, "t2", timer2_proc, (void *)0, 1000, NET_TIMER_RELOAD);
	net_timer_add(&t3, "t3", timer3_proc, (void *)0, 4000, NET_TIMER_RELOAD);
	net_timer_check_tmo(100);
	net_timer_check_tmo(900);
	net_timer_check_tmo(4000);
}

void basic_test (void) {
    //nlist_test();
    //mblock_test();
    //pktbuf_test();
	//timer_test();
	
}

int main (void) 
{
    net_init();
    //dbg_test();
    basic_test();

    netdev_init();

    net_start();

	ping_t ping;
	ping_run(&ping, "192.168.48.1", 4, 64, 1000);


    while (1) {
        sys_sleep(10);
    }

    return 0;
}