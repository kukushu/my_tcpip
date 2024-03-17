#include "ipaddr.h"

void ipaddr_set_any (ipaddr_t * ip) {
    ip->type = IPADDR_V4;
    ip->q_addr = 0;
}


void ipaddr_set_loop (ipaddr_t * ipaddr) {
    ipaddr->a_addr[0] = 127;
    ipaddr->a_addr[1] = 0;
    ipaddr->a_addr[2] = 0;
    ipaddr->a_addr[3] = 1;
}

/**
 * @brief 将str字符串转移为ipaddr_t格式
 */
net_err_t ipaddr_from_str(ipaddr_t * dest, const char* str) {
    // 必要的参数检查
    if (!dest || !str) {
        return NET_ERR_PARAM;
    }

    // 初始值清空
    dest->q_addr = 0;

    // 不断扫描各字节串，直到字符串结束
    char c;
    uint8_t * p = dest->a_addr;
    uint8_t sub_addr = 0;
    while ((c = *str++) != '\0') {
        // 如果是数字字符，转换成数字并合并进去
        if ((c >= '0') && (c <= '9')) {
            // 数字字符转换为数字，再并入计算
            sub_addr = sub_addr * 10 + c - '0';
        } else if (c == '.') {
            // . 分隔符，进入下一个地址符，并重新计算
            *p++ = sub_addr;
            sub_addr = 0;
        } else {
            // 格式错误，包含非数字和.字符
            return NET_ERR_PARAM;
        }
    }

    // 写入最后计算的值
    *p++ = sub_addr;
    return NET_ERR_OK;
}

/**
 * 获取缺省地址
 */
ipaddr_t * ipaddr_get_any(void) {
    static ipaddr_t ipaddr_any = { .q_addr = 0 };
    return &ipaddr_any;
}

/**
 * @brief 复制ip地址
 */
void ipaddr_copy(ipaddr_t * dest, const ipaddr_t * src) {
    if (!dest || !src) {
        return;
    }

    dest->q_addr = src->q_addr;
}


int ipaddr_is_any(const ipaddr_t* ip) {
    return ip->q_addr == 0;
}

/**
 * 判断IP地址是否完成相同
 */
int ipaddr_is_equal(const ipaddr_t * ipaddr1, const ipaddr_t * ipaddr2) {
    return ipaddr1->q_addr == ipaddr2->q_addr;
}

/**
 * 将ip地址转换到缓冲区中
 * @param ip_buf ip缓冲区
 * @param src 源ip地址
 */
void ipaddr_to_buf(const ipaddr_t* src, uint8_t* ip_buf) {
    ip_buf[0] = src->a_addr[0];
    ip_buf[1] = src->a_addr[1];
    ip_buf[2] = src->a_addr[2];
    ip_buf[3] = src->a_addr[3];
}

/**
 * 复制ip地址，从指定字节内存中读取
 * @param dest 目标ip地址
 * @param ip_buf 源ip地按类似192, 168, 1, 1的字节顺序排放
 */
void ipaddr_from_buf(ipaddr_t* dest, const uint8_t * ip_buf) {
    dest->a_addr[0] = ip_buf[0];
    dest->a_addr[1] = ip_buf[1];
    dest->a_addr[2] = ip_buf[2];
    dest->a_addr[3] = ip_buf[3];
}



int ipaddr_is_local_broadcast(const ipaddr_t * ipaddr) {
    return ipaddr->q_addr == IPV4_ADDR_BROADCAST;
}

/**
 * 获取ip地址中的主机号
 * @param ipaddr 查询的ip地址
 * @param mask 子网掩码
 * @return 主机号
 */
ipaddr_t ipaddr_get_host(const ipaddr_t * ipaddr, const ipaddr_t * netmask) {
    ipaddr_t hostid;

    hostid.q_addr = ipaddr->q_addr & ~netmask->q_addr;
    return hostid;
}

/**
 * 判断ip地址是否为定向广播地址
 *
 * 即可指定向某个特定的子网发送ip地址，甚至可以跨路由器发送，意即
 * 无端系统可以向指定的子网发送数据。路径器可允许配置，禁用该定向广播
 */
int ipaddr_is_direct_broadcast(const ipaddr_t * ipaddr, const ipaddr_t * netmask) {
    ipaddr_t hostid = ipaddr_get_host(ipaddr, netmask);

    // 判断host_id部分是否为全1
    return hostid.q_addr == (IPV4_ADDR_BROADCAST & ~netmask->q_addr);
}

/**
 * 查看源ip地址是否与目的ip地址匹配
 */
int ipaddr_is_match(const ipaddr_t* dest, const ipaddr_t* src, const ipaddr_t * netmask) {
    ipaddr_t dest_netid = ipaddr_get_net(dest, netmask);
    ipaddr_t src_netid = ipaddr_get_net(src, netmask);

    // 源全1地址：本地受限广播，匹配
    if (ipaddr_is_local_broadcast(dest)) {
        return 1;
    }

    // 二者：同一子网广播，匹配
    if (ipaddr_is_direct_broadcast(dest, netmask) && ipaddr_is_equal(&dest_netid, &src_netid)) {
        return 1;
    }

    // 最后，判断是否完成相同
    return ipaddr_is_equal(dest, src);
}

/**
 * 获取ip地址中的网络号
 */
ipaddr_t ipaddr_get_net(const ipaddr_t * ipaddr, const ipaddr_t * netmask) {
    ipaddr_t netid;

    netid.q_addr = ipaddr->q_addr & netmask->q_addr;
    return netid;
}

void ipaddr_set_all_1(ipaddr_t* ip) {
    ip->q_addr = 0xFFFFFFFF;
}

int ipaddr_1_cnt(ipaddr_t* ip) {
    int cnt = 0;

    uint32_t addr = ip->q_addr;
    while (addr) {
        if (addr & 0x1) {
            cnt++;
        }

        addr >>= 1;
    }
    return cnt;
}



