#ifndef NET_CFG_H
#define NET_CFG_H

#define DBG_TEST        DBG_LEVEL_INFO
#define DBG_MBLOCK      DBG_LEVEL_INFO
#define DBG_QUEUE       DBG_LEVEL_INFO
#define DBG_EXMSG       DBG_LEVEL_INFO
#define DBG_BUF         DBG_LEVEL_ERROR
#define DBG_INIT        DBG_LEVEL_INFO
#define DBG_NETIF       DBG_LEVEL_INFO
#define DBG_ETHER       DBG_LEVEL_INFO
#define DBG_TOOLS       DBG_LEVEL_INFO

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


#endif