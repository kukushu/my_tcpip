#ifndef NET_CFG_H
#define NET_CFG_H

#define DBG_TEST        DBG_LEVEL_ERROR
#define DBG_MBLOCK      DBG_LEVEL_ERROR
#define DBG_QUEUE       DBG_LEVEL_ERROR
#define DBG_EXMSG       DBG_LEVEL_ERROR
#define DBG_BUF         DBG_LEVEL_ERROR
#define DBG_INIT        DBG_LEVEL_ERROR
#define DBG_NETIF       DBG_LEVEL_ERROR
#define DBG_ETHER       DBG_LEVEL_ERROR
#define DBG_TOOLS       DBG_LEVEL_ERROR
#define DBG_TIMER       DBG_LEVEL_ERROR
#define DBG_ARP         DBG_LEVEL_ERROR
#define DBG_IP          DBG_LEVEL_ERROR
#define DBG_ICMP        DBG_LEVEL_ERROR
#define DBG_SOCKET      DBG_LEVEL_INFO
#define DBG_RAW         DBG_LEVEL_INFO

#define NET_ENDIAN_LITTLE       1                   // 系统是否为小端


#define EXMSG_MSG_CNT  100
#define EXMSG_NLOCKER  NLOCKER_THREAD

#define PKTBUF_BLK_SIZE 128
#define PKTBUF_BLK_CNT  100
#define PKTBUF_BUF_CNT  100

#define NETIF_HWADDR_SIZE    10
#define NETIF_NAME_SIZE      10
#define NETIF_INQ_SIZE       50
#define NETIF_OUTQ_SIZE      50
#define NETIF_DEV_CNT        10


#define TIMER_NAME_SIZE      32
#define TIMER_SCAN_PERIOD    50

#define ARP_CACHE_SIZE       5
#define ARP_MAX_PKT_WAIT     5
#define ARP_TIMER_TMO        1
#define ARP_ENTRY_PENDING_TMO 3
#define ARP_ENTRY_CNT         7
#define ARP_ENTRY_RETRY_CNT   6
#define ARP_ENTRY_STABLE_TMO  100

#define IP_FRAGS_MAX_NR               10              // 最多支持的分片控制数量
#define IP_FRAG_MAX_BUF_NR             10              // 每个IP分片最多允许停留的buf数量
#define IP_FRAG_SCAN_PERIOD         (1)             // IP分片表扫描周期，以秒为单位
#define IP_FRAG_TMO                 5               // IP分片最大超时时间，以秒为单位
#define IP_RTABLE_SIZE				    16          // 路由表项数量

#define UDP_MAX_NR                  4


#define TCP_MAX_NR                  10


#define RAW_MAX_NR                  5
#define RAW_MAX_RECV                50


#endif