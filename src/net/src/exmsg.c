#include "exmsg.h"

#include "sys_plat.h"

static void work_thread (void * arg) {
    plat_printf("exmsg is running.....\n");

    while (1) {
        sys_sleep(10);
    }
}

net_err_t exmsg_init (void) {
    return NET_ERR_OK;
}

net_err_t exmsg_start (void) {
    sys_thread_t thread =sys_thread_create(work_thread, "work_thread");
    if (thread == SYS_THREAD_INVALID) {
        return NET_ERR_SYS;
    }
    return NET_ERR_OK;
}
