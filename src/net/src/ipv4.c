#include "ipv4.h"
#include "dbg.h"
#include "tools.h"
#include "protocol.h"
#include "mblock.h"
#include "timer.h"
#include "icmpv4.h"

static uint16_t packet_id = 0;                  // 每次发包的序号

// ip包分片与重组相关
static ip_frag_t frag_array[IP_FRAGS_MAX_NR]; // 分片控制链表
static mblock_t frag_mblock;                    // 分片控制缓存
static nlist_t frag_list;                        // 等待的分片列表
static net_timer_t frag_timer;                      // 分片定时器
    
// 路由表相关配置
static nlist_t rt_list;                          // 路由表
static mblock_t rt_mblock;                      // 邮箱表分配结构
static rentry_t rt_table[IP_RTABLE_SIZE];      // 路由表


#if DBG_DISP_ENABLED(DBG_IP)
void rt_nlist_display(void) {
    plat_printf("Route table:\n");

    for (int i = 0, idx = 0; i < IP_RTABLE_SIZE; i++) {
        rentry_t* entry = rt_table + i;
        if (entry->netif) {
            plat_printf("%d: ", idx++);
            dbg_dump_ip(DBG_IP, "net:", &entry->net);
            plat_printf("\t");
            dbg_dump_ip(DBG_IP, "mask:", &entry->mask);
            plat_printf("\t");
            dbg_dump_ip(DBG_IP, "next_hop:", &entry->next_hop);
            plat_printf("\t");
            plat_printf("if: %s", entry->netif->name);
            plat_printf("\n");
        }
    }
}

static void display_ip_pkt (ipv4_pkt_t * pkt) {
    ipv4_hdr_t * ip_hdr = (ipv4_hdr_t *) pkt;
    plat_printf("-----------ip--------------\n");
    plat_printf("   version: %d\n", ip_hdr->version);
    plat_printf("   header len : %d\n", ipv4_hdr_size(pkt));
    plat_printf("   total len : %d\n", ip_hdr->total_len);
    plat_printf("   id : %d\n", ip_hdr->id);
    plat_printf("   ttl : %d\n", ip_hdr->ttl);
    plat_printf("   checksum : %d\n", ip_hdr->hdr_checksum);
    dbg_dump_ip_buf(DBG_IP, "    src ip : ", ip_hdr->src_ip);
    dbg_dump_ip_buf(DBG_IP, "    dest ip : ", ip_hdr->dest_ip);
    plat_printf("----------------ip end----------------\n");
}

#else
#define rt_nlist_display()
#define display_ip_pkt(ipv4_pkt_t * pkt);
#endif






net_err_t ipv4_init (void) {
    dbg_info(DBG_IP, "init ipv4");

    dbg_info(DBG_IP, "init ipv4 done");

    return NET_ERR_OK;
}

static net_err_t is_pkt_ok(ipv4_pkt_t* pkt, int size) {
    // 版本检查，只支持ipv4
    if (pkt->hdr.version != NET_VERSION_IPV4) {
        dbg_warning(DBG_IP, "invalid ip version, only support ipv4!\n");
        return NET_ERR_NOT_SUPPORT;
    }

    // 头部长度要合适
    int hdr_len = ipv4_hdr_size(pkt);
    if (hdr_len < sizeof(ipv4_hdr_t)) {
        dbg_warning(DBG_IP, "IPv4 header error: %d!", hdr_len);
        return NET_ERR_SIZE;
    }

    // 总长必须大于头部长，且<=缓冲区长
    // 有可能xbuf长>ip包长，因为底层发包时，可能会额外填充一些字节
    int total_size = x_ntohs(pkt->hdr.total_len);
    if ((total_size < sizeof(ipv4_hdr_t)) || (size < total_size)) {
        dbg_warning(DBG_IP, "ip packet size error: %d!\n", total_size);
        return NET_ERR_SIZE;
    }

    // 校验和为0时，即为不需要检查检验和
    if (pkt->hdr.hdr_checksum) {
        uint16_t c = checksum16(0, (uint16_t*)pkt, hdr_len, 0, 1);
        if (c != 0) {
            dbg_warning(DBG_IP, "Bad checksum: %0x(correct is: %0x)\n", pkt->hdr.hdr_checksum, c);
            return 0;
        }
    }

    return NET_ERR_OK;
}
static void iphdr_ntohs(ipv4_pkt_t* pkt) {
    pkt->hdr.total_len = x_ntohs(pkt->hdr.total_len);
    pkt->hdr.id = x_ntohs(pkt->hdr.id);
    pkt->hdr.frag_all = x_ntohs(pkt->hdr.frag_all);
}

static void iphdr_htons(ipv4_pkt_t* pkt) {
    pkt->hdr.total_len = x_htons(pkt->hdr.total_len);
    pkt->hdr.id = x_htons(pkt->hdr.id);
    pkt->hdr.frag_all = x_ntohs(pkt->hdr.frag_all);
}

static net_err_t ip_normal_in(netif_t* netif, pktbuf_t* buf, ipaddr_t* src, ipaddr_t * dest) {
    ipv4_pkt_t* pkt = (ipv4_pkt_t*)pktbuf_data(buf);
    display_ip_pkt(pkt);

    // 根据不同协议类型做不同处理， 进行多路径分解
    switch (pkt->hdr.protocol) {
    case NET_PROTOCOL_ICMPv4: {
        net_err_t err = icmpv4_in(src, &netif->ipaddr, buf);
        if (err < 0) {
            dbg_warning(DBG_IP, "icmp in failed.\n");
            return err;
        }
        return NET_ERR_OK;
    }
    case NET_PROTOCOL_UDP: {
        // 提交给UDP处理
        /*
        net_err_t err = udp_in(buf, src, dest);
        if (err < 0) {
            dbg_warning(DBG_IP, "udp in error. err = %d\n", err);

            // 发送ICMP不可达信息
            if (err == NET_ERR_UNREACH) {
                iphdr_htons(pkt);       // 注意转换回来
                icmpv4_out_unreach(src, &netif->ipaddr, ICMPv4_UNREACH_PORT, buf);
            }
            return err;
        }
        */
        iphdr_htons(pkt);       // 注意转换回来
        icmpv4_out_unreach(src, &netif->ipaddr, ICMPv4_UNREACH_PORT, buf);
        return NET_ERR_OK;
    }
        case NET_PROTOCOL_TCP: {
            // 移去包头后交由TCP模块处理
            /*
            pktbuf_remove_header(buf, ipv4_hdr_size(pkt));
            net_err_t err = tcp_in(buf, src, dest);
            if (err < 0) {
                dbg_warning(DBG_IP, "udp in error. err = %d\n", err);
                return err;
            }
            */
            return NET_ERR_OK;
        }
        default: {
            dbg_warning(DBG_IP, "unknown protocol %d, drop it.\n", pkt->hdr.protocol);
            /*
            // 其它没有处理的，交给原始套接字层处理, 原始IP数据报
            net_err_t err = raw_in(buf);
            if (err < 0) {
                dbg_warning(DBG_IP, "raw in error. err = %d\n", err);
            }
            */
            return NET_ERR_UNREACH;
        }
    }
}


net_err_t ipv4_in(netif_t *netif, pktbuf_t *buf) {
    dbg_info(DBG_IP, "ip in");
    net_err_t err = pktbuf_set_cont(buf, sizeof(ipv4_hdr_t));
    if (err < 0) {
        dbg_error(DBG_IP, "adjust header failed. err=%d\n", err);
        return err;
    }

    // 预先做一些检查
    ipv4_pkt_t* pkt = (ipv4_pkt_t*)pktbuf_data(buf);
    if (is_pkt_ok(pkt, buf->total_size) != NET_ERR_OK) {
        dbg_warning(DBG_IP, "packet is broken. drop it.\n");
        return err;
    }

    // 预先进行转换，方便后面进行处理，不用再临时转换
    iphdr_ntohs(pkt);

    // buf的整体长度可能比ip包要长，比如比较小的ip包通过以太网发送时
    // 由于底层包的长度有最小的要求，因此可能填充一些0来满足长度要求
    // 因此这里将包长度进行了缩小
    err = pktbuf_resize(buf, pkt->hdr.total_len);
    if (err < 0) {
        dbg_error(DBG_IP, "ip packet resize failed. err=%d\n", err);
        return err;
    }

    // 判断IP数据包是否是给自己的，不是给自己的包不处理
    ipaddr_t dest_ip, src_ip;
    ipaddr_from_buf(&dest_ip, pkt->hdr.dest_ip);
    ipaddr_from_buf(&src_ip, pkt->hdr.src_ip);

    // 最简单的判断：与本机网口相同, 或者广播
    if (!ipaddr_is_match(&dest_ip, &netif->ipaddr, &netif->netmask)) {
        pktbuf_free(buf);
        return NET_ERR_UNREACH;
    }
    // 发给自己的包，正常处理
    // 处理分片包的输入：该包的特点，offset不为0，或者虽为0但是more_frag不为0
    if (pkt->hdr.offset || pkt->hdr.more) {
        //err = ip_frag_in(netif, buf, &src_ip, &dest_ip);
    } else {
        err = ip_normal_in(netif, buf, &src_ip, &dest_ip);
    }
    return err;
}

net_err_t ipv4_out(uint8_t protocol, ipaddr_t* dest, ipaddr_t * src, pktbuf_t* buf) {
    dbg_info(DBG_IP,"send an ip packet.\n");
/*
    // 为目标ip选择路径，当前目标地址不一定是马上要发的地址
    rentry_t* rt = rt_find(dest);
    if (rt == (rentry_t *)0) {
        dbg_error(DBG_IP,"send failed. no route.");
        return NET_ERR_UNREACH;
    }
    ipaddr_t next_hop;
    if (ipaddr_is_any(&rt->next_hop)) {
        ipaddr_copy(&next_hop, dest);
    } else {
        ipaddr_copy(&next_hop, &rt->next_hop);
    }

    // 接口设置了MTU，但是MTU比较小，此时通过分片方式发送
    if (rt->netif->mtu && ((buf->total_size + sizeof(ipv4_hdr_t)) > rt->netif->mtu)) {
        // 允许分片，且超出MTU，则进行分片发送
        net_err_t err = ip_frag_out(protocol, dest, src, buf, &next_hop, rt->netif);
        if (err < 0) {
            dbg_warning(DBG_IP, "send ip frag packet failed. error = %d\n", err);
            return err;
        }
        return NET_ERR_OK;
    }
*/
    // 调整读写位置，预留IP包头，注意要连续存储
    net_err_t err = pktbuf_add_header(buf, sizeof(ipv4_hdr_t), 1);
    if (err < 0) {
        dbg_error(DBG_IP, "no enough space for ip header, curr size: %d\n", buf->total_size);
        return NET_ERR_SIZE;
    }

    // 构建IP数据包
    ipv4_pkt_t * pkt = (ipv4_pkt_t*)pktbuf_data(buf);
    pkt->hdr.shdr_all = 0;
    pkt->hdr.version = NET_VERSION_IPV4;
    ipv4_set_hdr_size(pkt, sizeof(ipv4_hdr_t));
    pkt->hdr.total_len = buf->total_size;
    pkt->hdr.id = packet_id ++;        // 计算不断自增
    pkt->hdr.frag_all = 0;         //
    pkt->hdr.ttl = NET_IP_DEF_TTL;
    pkt->hdr.protocol = protocol;
    pkt->hdr.hdr_checksum = 0;
    /*
    if (!src || ipaddr_is_any(src)) {
        // 未指定源地址，则使用网卡的地址
        ipaddr_to_buf(&rt->netif->ipaddr, pkt->hdr.src_ip);
    } else {
        ipaddr_to_buf(src, pkt->hdr.src_ip);
    }
    */
    ipaddr_to_buf(src, pkt->hdr.src_ip);
    ipaddr_to_buf(dest, pkt->hdr.dest_ip);

    // 大小端转换
    iphdr_htons(pkt);

    // 计算校验和
    pktbuf_reset_acc(buf);
    pkt->hdr.hdr_checksum = pktbuf_checksum16(buf, ipv4_hdr_size(pkt), 0, 1);

    // 开始发送
    display_ip_pkt(pkt);
    //err = netif_out(rt->netif, &next_hop, buf);
    err = netif_out(netif_get_default(), dest, buf);
    if (err < 0) {
        dbg_warning(DBG_IP, "send ip packet failed. error = %d\n", err);
        return err;
    }

    return NET_ERR_OK;
}