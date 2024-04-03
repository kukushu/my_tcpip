#include "socket.h"
#include "dbg.h"


int x_socket(int family, int type, int protocol) {
    sock_req_t req;
    req.wait = 0;
    req.sockfd = -1;
    req.create.family = family;
    req.create.type = type;
    req.create.protocol = protocol;
    net_err_t err = exmsg_func_exec(sock_create_req_in, &req);
    if (err < 0) {
        dbg_error(DBG_SOCKET, "create sock failed: %d", err);
        return -1;
    }
    return req.sockfd;
}
ssize_t x_sendto(int sockfd, const void* buf, size_t len, int flags, const struct x_sockaddr* dest, 
        x_socklen_t dest_len) {
    if ((dest_len != sizeof(struct x_sockaddr)) || !len) {
        dbg_error(DBG_SOCKET, "addr size or len error");
        return -1;
    }
    if (dest->sa_family != AF_INET) {
        dbg_error(DBG_SOCKET, "family error");
        return -1;
    }

    ssize_t send_size = 0;
    uint8_t * start = (uint8_t *)buf;
    while (len) {
        // 将要发的数据填充进消息体，请求发送
        sock_req_t req;
        req.wait = 0;
        req.sockfd = sockfd;
        req.data.buf = start;
        req.data.len = len;
        req.data.flags = flags;
        req.data.addr = (struct x_sockaddr* )dest;
        req.data.addr_len = &dest_len;
        req.data.comp_len = 0;
        net_err_t err = exmsg_func_exec(sock_sendto_req_in, &req);
        if (err < 0) {
            dbg_error(DBG_SOCKET, "write failed.");
            return -1;
        }

        // 等待数据写入发送缓存中。注意，只是写入缓存
        if (req.wait && ((err = sock_wait_enter(req.wait, req.wait_tmo)) < NET_ERR_OK)) {
            dbg_error(DBG_SOCKET, "send failed %d.", err);
            return -1;
        }

        len -= req.data.comp_len;
        send_size += (ssize_t)req.data.comp_len;
        start += req.data.comp_len;
    }

    return send_size;
}
ssize_t x_recvfrom(int sockfd, void* buf, size_t size, int flags, struct x_sockaddr* src_addr, x_socklen_t* src_len) {
    if (!size || !src_len || !src_addr) {
        dbg_error(DBG_SOCKET, "addr size or len error");
        return -1;
    }
    while (1) {
        sock_req_t req;
        req.wait = 0;
        req.sockfd = sockfd;
        req.data.buf = buf;
        req.data.len = size;
        req.data.comp_len = 0;
        req.data.addr = src_addr;
        req.data.addr_len = src_len;

        net_err_t err = exmsg_func_exec(sock_recvfrom_req_in, &req);
        if (err < 0) {
            dbg_error(DBG_SOCKET, "connect failed: ", err);
            return -1;
        }

        if (req.data.comp_len) {
            return (ssize_t) req.data.comp_len;
        }
/*
        err = sock_wait_enter(req.wait, req.wait_tmo);
        if (err == NET_ERR_CLOSE) {
            
        } else if (err < 0) {
            dbg_error(DBG_SOCKET, "recv faild %d.", err);
            return -1;
        }
        */
    }
}

int x_setsockopt(int sockfd, int level, int optname, const void * optval, int optlen) {
    if (!optval || !optlen) {
        dbg_error(DBG_SOCKET, "param error", NET_ERR_PARAM);
        return -1;
    }

    sock_req_t req;
    req.wait = 0;
    req.sockfd = sockfd;
    req.opt.level = level;
    req.opt.optname = optname;
    req.opt.optval = optval;
    req.opt.optlen = optlen;
    net_err_t err = exmsg_func_exec(sock_setsockopt_req_in, &req);
    if (err < 0) {
        dbg_error(DBG_SOCKET, "setopt: ", err);
        return -1;
    }

    return 0;
}
int x_close(int sockfd) {}
int x_connect(int sockfd, const struct x_sockaddr* addr, x_socklen_t len) {}
int x_bind(int sockfd, const struct x_sockaddr* addr, x_socklen_t len) {}
ssize_t x_send(int fd, const void* buf, size_t len, int flags) {}
ssize_t x_recv(int fd, void* buf, size_t len, int flags) {}
int x_listen(int sockfd, int backlog) {}
int x_accept(int sockfd, struct x_sockaddr* addr, x_socklen_t* len) {}
ssize_t x_write(int sockfd, const void* buf, size_t len) {}
ssize_t x_read(int sockfd, void* buf, size_t len) {}


int x_gethostbyname_r (const char *name,struct x_hostent *ret, char *buf, size_t buflen,
         struct x_hostent **result, int *h_errnop) {}