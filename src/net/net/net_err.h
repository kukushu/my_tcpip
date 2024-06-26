#ifndef NET_ERR_H
#define NET_ERR_H

typedef enum _net_err_t {
    NET_ERR_NEED_WAIT = 1,
    NET_ERR_OK = 0,
    NET_ERR_SYS = -1,
    NET_ERR_MEM = -2,
    NET_ERR_FULL = -3,
    NET_ERR_TMO = -4,
    NET_ERR_NONE = -5,
    NET_ERR_PARAM = -6,
    NET_ERR_EXIST = -7,
    NET_ERR_SIZE = -8,
    NET_ERR_STATE = -9,
    NET_ERR_ARP = -10,
    NET_ERR_NOT_SUPPORTED = -11,
    NET_ERR_NOT_SUPPORT = -12,
    NET_ERR_UNREACH = -13,
    NET_ERR_CHKSUM = -14,
    NET_ERR_UNKNOWN = -15,
    NET_ERR_CLOSE = -16,
    NET_ERR_CONNECTED = -17,
} net_err_t;


#endif