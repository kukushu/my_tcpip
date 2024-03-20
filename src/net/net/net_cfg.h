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
#define DBG_TIMER       DBG_LEVEL_INFO
#define DBG_ARP         DBG_LEVEL_INFO

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
#define ARP_ENTRY_STABLE_TMO  5


#endif