#include "sock.h"
#include "socket.h"
#include "raw.h"

#define SOCKET_MAX_NR     (RAW_MAX_NR + UDP_MAX_NR + TCP_MAX_NR)

static x_socket_t socket_tbl[SOCKET_MAX_NR];

static inline int get_index(x_socket_t * socket) {
    return (int) (socket - socket_tbl);
}

static inline x_socket_t * get_socket (int idx) {
    if ((idx < 0) || (idx >= SOCKET_MAX_NR)) {
        return (x_socket_t *) 0;
    }
    x_socket_t * socket = socket_tbl + idx;
    return socket->sock == (sock_t *) 0 ? (x_socket_t *) 0 : socket;
}

static x_socket_t * socket_alloc (void) {
    x_socket_t * socket = (x_socket_t *) 0;
    int i = 0;
    for (; i < SOCKET_MAX_NR; i ++) {
        if (socket_tbl[i].state == SOCKET_STATE_FREE) {
            socket_tbl[i].state = SOCKET_STATE_USED;
            socket = socket_tbl + i;
            break;
        }
    }
    return socket;
}

static void socket_free (x_socket_t * socket) {
    socket->sock = (sock_t *) 0;
    socket->state = SOCKET_STATE_FREE;
}

net_err_t sock_wait_init (sock_wait_t * wait) {
    wait->waiting = 0;
    wait->sem = sys_sem_create(0);
    return wait->sem == SYS_SEM_INVALID ? NET_ERR_SYS : NET_ERR_OK;
}
void sock_wait_destroy (sock_wait_t * wait) {
    if (wait->sem != SYS_SEM_INVALID) {
        sys_sem_free(wait->sem);
    }
}
void sock_wait_add (sock_wait_t * wait, int tmo, struct _sock_req_t * req) {
    req->wait = wait;
    req->wait_tmo = tmo;
    wait->waiting ++;
}
net_err_t sock_wait_enter (sock_wait_t * wait, int tmo) {
    if (sys_sem_wait(wait->sem, tmo) < 0) {
        return NET_ERR_TMO;
    }
    return wait->err;
}
void sock_wait_leave (sock_wait_t * wait, net_err_t err) {
    if (wait->waiting > 0) {
        wait->waiting --;
        wait->err = err;
        sys_sem_notify(wait->sem);
    }
}






net_err_t sock_init(sock_t* sock, int family, int protocol, const sock_ops_t * ops) {
    sock->protocol = protocol;
	sock->ops = ops;

    sock->family = family;
	ipaddr_set_any(&sock->local_ip);
	ipaddr_set_any(&sock->remote_ip);
	sock->local_port = 0;
	sock->remote_port = 0;
	sock->err = NET_ERR_OK;
	sock->rcv_tmo = 0;
    sock->snd_tmo = 0;
	nlist_node_init(&sock->node);

    sock->conn_wait = (sock_wait_t *)0;
    sock->snd_wait = (sock_wait_t *)0;
    sock->rcv_wait = (sock_wait_t *)0;
	return NET_ERR_OK;
}
void sock_uninit (sock_t * sock) {
    if (sock->snd_wait) {
        sock_wait_destroy(sock->snd_wait);
    }
    if (sock->rcv_wait) {
        sock_wait_destroy(sock->rcv_wait);
    }
    if (sock->conn_wait) {
        sock_wait_destroy(sock->conn_wait);
    }
    
}

net_err_t sock_create_req_in(sock_req_t* param) { 
    static const struct sock_info_t {
        int protocol;
        sock_t * (* create) (int family, int protocol);
    } sock_tbl[] = {
        [SOCK_RAW] = {.protocol = 0, .create = raw_create,},
    };

    sock_req_t * req = param;
    sock_create_t * create_param = &req->create;

    x_socket_t * socket = socket_alloc();
    if (socket == (x_socket_t *) 0) {
        dbg_error(DBG_SOCKET, "no socket");
        return NET_ERR_MEM;
    }

    if ((create_param->type < 0) || (create_param->type >= sizeof(sock_tbl) / sizeof(sock_tbl[0]))) {
        dbg_error(DBG_SOCKET, "unknown type : %d", create_param->type);
        socket_free(socket);
        return NET_ERR_PARAM;
    }

    const struct sock_info_t * info = sock_tbl + create_param->type;
    if (create_param->protocol == 0) {
        create_param->protocol = info->protocol;
    }
    sock_t * sock = info->create(create_param->family, create_param->protocol);
    if (!sock) {
        dbg_error(DBG_SOCKET, "create sock failed");
        socket_free(socket);
        return NET_ERR_MEM;
    }
    socket->sock = sock;
    req->sockfd = get_index(socket);
    return NET_ERR_OK;
}
net_err_t sock_sendto_req_in (sock_req_t * param) {
    sock_req_t * req = (sock_req_t *) param;
    x_socket_t* socket = get_socket(req->sockfd);
    if (!socket) {
        dbg_error(DBG_SOCKET, "param error: socket = %d.", socket);
        return NET_ERR_PARAM;
    }
    sock_t* sock = socket->sock;
	sock_data_t * data = (sock_data_t *)&req->data;
    
    // 判断是否已经实现
    if (!sock->ops->sendto) {
        dbg_error(DBG_SOCKET, "this function is not implemented");
        return NET_ERR_NOT_SUPPORT;
    }

    net_err_t err = sock->ops->sendto(sock, data->buf, data->len, data->flags,
                                data->addr, *data->addr_len, &req->data.comp_len);
    if (err == NET_ERR_NEED_WAIT) {
        if (sock->snd_wait) {
            sock_wait_add(sock->snd_wait, sock->snd_tmo, req);
        }
    }
    return err;
}
net_err_t sock_recvfrom_req_in(sock_req_t * param) {
    sock_req_t * req = (sock_req_t *) param;
    x_socket_t * socket = get_socket(req->sockfd);
    if (!socket) {
        dbg_error(DBG_SOCKET, "param error : socket = %d", socket);
        return NET_ERR_PARAM;
    }
    sock_t * sock = socket->sock;
    sock_data_t * data = (sock_data_t *) &req->data;

    if (!sock->ops->recvfrom) {
        dbg_error(DBG_SOCKET, "this function is not implemented");
        return NET_ERR_NOT_SUPPORT;
    }
    net_err_t err = sock->ops->recvfrom(sock, data->buf, data->len, data->flags, data->addr, data->addr_len, &req->data.comp_len);
    /*
    if (err == NET_ERR_NEED_WAIT) {
        if (sock->rcv_wait) {
            sock_wait_add(sock->rcv_wait, sock->rcv_tmo, req);
        }
    }
    */
    return err;
}
net_err_t sock_setsockopt_req_in(sock_req_t * param) {
    sock_req_t * req = (sock_req_t *) param;
    x_socket_t * socket = get_socket(req->sockfd);
    if (!socket) {
        dbg_error(DBG_SOCKET, "param error : socket = %d.", socket);
        return NET_ERR_PARAM;
    }
    sock_t * sock = socket->sock;
    sock_opt_t * opt = (sock_opt_t *) &req->opt;

    return sock->ops->setopt(sock, opt->level, opt->optname, opt->optval, opt->optlen);
}
net_err_t sock_close_req_in (sock_req_t* param) {}
net_err_t sock_bind_req_in(sock_req_t * param) {}
net_err_t sock_connect_req_in (sock_req_t* param) {}
net_err_t sock_send_req_in (sock_req_t * param) {}
net_err_t sock_recv_req_in(sock_req_t * param) {}
net_err_t sock_listen_req_in(sock_req_t * param) {}
net_err_t sock_accept_req_in(sock_req_t * param) {}
net_err_t sock_destroy_req_in (sock_req_t* param) {}

net_err_t sock_setopt(struct _sock_t* sock,  int level, int optname, const void * optval, int optlen) {
    if (level != SOL_SOCKET) {
        dbg_error(DBG_SOCKET, "unknown level : %d", level);
        return NET_ERR_UNKNOWN;
    }
    switch (optname) {
        case SO_RCVTIMEO:
        case SO_SNDTIMEO: {
            if (optlen != sizeof(struct x_timeval)) {
                dbg_error(DBG_SOCKET, "time size error");
                return NET_ERR_PARAM;
            }
            struct x_timeval * time = (struct x_timeval *) optval;
            int time_ms = time->tv_sec * 1000 + time->tv_usec / 1000;
            if (optname == SO_RCVTIMEO) {
                sock->rcv_tmo = time_ms;
                return NET_ERR_OK;
            } else if (optname == SO_SNDTIMEO) {
                sock->snd_tmo = time_ms;
                return NET_ERR_OK;
            } else {
                return NET_ERR_PARAM;
            }
        }
        default:
            break;
    }
    return NET_ERR_UNKNOWN;
}
net_err_t sock_bind(sock_t* sock, const struct x_sockaddr* addr, x_socklen_t len) {}
net_err_t sock_connect(sock_t* sock, const struct x_sockaddr* addr, x_socklen_t len) {}
net_err_t sock_send (struct _sock_t * sock, const void* buf, size_t len, int flags, ssize_t * result_len) {}
net_err_t sock_recv (struct _sock_t * sock, void* buf, size_t len, int flags, ssize_t * result_len) {}

net_err_t socket_init(void) {
    plat_memset(socket_tbl, 0, sizeof(socket_tbl));
    return NET_ERR_OK;
}

net_err_t sock_wait (sock_t * sock, int type) {
    
}
void sock_wakeup (sock_t * sock, int type, int err) {
    if (type & SOCK_WAIT_CONN) {
        sock_wait_leave(sock->conn_wait, err);
    }

    if (type & SOCK_WAIT_WRITE) {
        sock_wait_leave(sock->snd_wait, err);
    }

    if (type & SOCK_WAIT_READ) {
        sock_wait_leave(sock->rcv_wait, err);
    }    
    sock->err = err;
}