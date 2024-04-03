#include "raw.h"
#include "sock.h"
#include "mblock.h"
#include "ipv4.h"
#include "socket.h"

static raw_t raw_tbl[RAW_MAX_NR];
static mblock_t raw_mblock;
static nlist_t raw_list;

#if DBG_DISP_ENABLED(DBG_RAW)
static void display_raw_list (void) {
    plat_printf("\n--- raw list\n --- ");

    int idx = 0;
    nlist_node_t * node;

    nlist_for_each(node, &raw_list) {
        raw_t * raw = (raw_t *)nlist_entry(node, sock_t, node);
        plat_printf("[%d]\n", idx++);
        dump_ip_buf("\tlocal:", (const uint8_t *)&raw->base.local_ip.a_addr);
        dump_ip_buf("\tremote:", (const uint8_t *)&raw->base.remote_ip.a_addr);
    }
}
#else
#define display_raw_list()
#endif

net_err_t raw_init(void) {
    dbg_info(DBG_RAW, "raw init");

    mblock_init(&raw_mblock, raw_tbl, sizeof(raw_t), RAW_MAX_NR, NLOCKER_NONE);
    nlist_init(&raw_list);

    dbg_info(DBG_RAW, "raw init done");
}



static net_err_t raw_sendto (struct _sock_t * sock, const void * buf, size_t len, int flags, 
        const struct x_sockaddr * dest, x_socklen_t dest_len, ssize_t * result_len) {
    ipaddr_t dest_ip;
    struct x_sockaddr_in* addr = (struct x_sockaddr_in*)dest;
    ipaddr_from_buf(&dest_ip, addr->sin_addr.addr_array);
    if (!ipaddr_is_any(&sock->remote_ip) && !ipaddr_is_equal(&dest_ip, &sock->remote_ip)) {
        dbg_error(DBG_RAW, "dest is incorrect");
        return NET_ERR_CONNECTED;
    }

    // 分配缓存空间
    pktbuf_t* pktbuf = pktbuf_alloc((int)len);
    if (!pktbuf) {
        dbg_error(DBG_RAW, "no buffer");
        return NET_ERR_MEM;
    }

    // 数据拷贝过去
    net_err_t err = pktbuf_write(pktbuf, (uint8_t *)buf, (int)len);
    if (sock->err < 0) {
        dbg_error(DBG_RAW, "copy data error");
        goto end_sendto;
    }

    // 通过IP层发送出去
    err = ipv4_out(sock->protocol, &dest_ip, &netif_get_default()->ipaddr, pktbuf);
    //err = ipv4_out(sock->protocol, &dest_ip, &sock->local_ip, pktbuf);
    if (err < 0) {
        dbg_error(DBG_RAW, "send error");
        goto end_sendto;
    }

    *result_len = (ssize_t)len;
    return NET_ERR_OK;
end_sendto:
    pktbuf_free(pktbuf);
    return err;
}

net_err_t raw_recvfrom(struct _sock_t* sock, void* buf, size_t len, int flags,
            struct x_sockaddr* src, x_socklen_t * addr_len, ssize_t * result_len) {
    raw_t * raw = (raw_t *) sock;
    nlist_node_t * first = nlist_remove_first(&raw->recv_list);
    if (!first) {
        * result_len = 0;
        return NET_ERR_NEED_WAIT;
    }
    pktbuf_t * pktbuf = nlist_entry(first, pktbuf_t, node);
    dbg_assert(pktbuf != (pktbuf_t *)0, "pktbuf error");

    ipv4_hdr_t * ipaddr = (ipv4_hdr_t *) pktbuf_data(pktbuf);
    struct x_sockaddr_in* addr = (struct x_sockaddr_in*)src;
    plat_memset(addr, 0, sizeof(struct x_sockaddr));
    addr->sin_family = AF_INET;
    addr->sin_port = 0;
    plat_memcpy(&addr->sin_addr, ipaddr->src_ip, IPV4_ADDR_SIZE);

    // 从包中读取数据
    int size = (pktbuf->total_size > (int)len) ? (int)len : pktbuf->total_size;
    pktbuf_reset_acc(pktbuf);
    net_err_t err= pktbuf_read(pktbuf, buf, size);
    if (err < 0) {
        pktbuf_free(pktbuf);
        dbg_error(DBG_RAW, "pktbuf read error");
        return err;
    }

    pktbuf_free(pktbuf);

    *result_len = size;
    return NET_ERR_OK;
}

sock_t* raw_create(int family, int protocol) {
    static const sock_ops_t raw_ops = {
        .sendto = raw_sendto,
        .setopt = sock_setopt,
        .recvfrom = raw_recvfrom,
    };
    raw_t * raw = mblock_alloc(&raw_mblock, -1);
    if (!raw) {
        dbg_error(DBG_RAW, "no raw sock");
        return (sock_t *) 0;
    }
    net_err_t err = sock_init(&raw->base, family, protocol, &raw_ops);
    if (err < 0) {
        dbg_error(DBG_RAW, "create raw sock failed");
        mblock_free(&raw_mblock, raw);
        return (sock_t *) 0;
    }
    nlist_init(&raw->recv_list);

    raw->base.rcv_wait = &raw->rcv_wait;
    if (sock_wait_init(raw->base.rcv_wait) < 0) {
        dbg_error(DBG_RAW, "create rcv.wait failed");
        goto create_failed;
    }
    nlist_insert_last(&raw_list, &raw->base.node);
    
    display_raw_list();
    return &raw->base;

create_failed:
    sock_uninit((sock_t *) raw);
    return (sock_t *) 0;
}

static raw_t * raw_find (ipaddr_t * src, ipaddr_t * dest, int protocol) {
    nlist_node_t * node;
    raw_t * found = (raw_t *) 0;

    nlist_for_each(node, &raw_list) {
        raw_t * raw = (raw_t *) nlist_entry(node, sock_t, node);

        if (raw->base.protocol && (raw->base.protocol != protocol)) {
            continue;
        }
        if (!ipaddr_is_any(&raw->base.local_ip) && !ipaddr_is_equal(&raw->base.local_ip, dest)) {
            continue;
        }
        if (!ipaddr_is_any(&raw->base.remote_ip) && !ipaddr_is_equal(&raw->base.remote_ip, src)) {
            continue;
        }

        found = raw;
        break;
    }
    return found;
}

net_err_t raw_in(pktbuf_t* pktbuf) {
    ipv4_hdr_t * iphdr = (ipv4_hdr_t *) pktbuf_data(pktbuf);
    net_err_t err = NET_ERR_UNREACH;
    
    ipaddr_t src, dest;
    ipaddr_from_buf(&dest, iphdr->dest_ip);
    ipaddr_from_buf(&src, iphdr->src_ip);

    raw_t * raw = raw_find(&src, &dest, iphdr->protocol);
    if (raw == (raw_t *) 0) {
        dbg_warning(DBG_RAW, "no raw for this packet");
        return NET_ERR_UNREACH;
    }

    if (nlist_count(&raw->recv_list) < RAW_MAX_RECV) {
        nlist_insert_last(&raw->recv_list, &pktbuf->node);
        sock_wakeup((sock_t *) raw, SOCK_WAIT_READ, NET_ERR_OK);
    } else {
        pktbuf_free(pktbuf);
    }
    return NET_ERR_OK;
}