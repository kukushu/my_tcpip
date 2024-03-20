#include "timer.h"
#include "dbg.h"
#include "nlist.h"
#include "sys.h"

static nlist_t timer_list;

static void display_timer_list(void) {
    plat_printf("--------------- timer list ---------------\n");

    nlist_node_t* node;
    int index = 0;
    nlist_for_each(node, &timer_list) {
        net_timer_t* timer = nlist_entry(node, net_timer_t, node);

        plat_printf("%d: %s, period = %d, curr: %d ms, reload: %d ms\n",
            index++, timer->name,
            timer->flags & NET_TIMER_RELOAD ? 1 : 0,
            timer->curr, timer->reload);
    }
    plat_printf("---------------- timer list end ------------\n");
}

static void insert_timer (net_timer_t * insert) {
    nlist_node_t * node;
    nlist_node_t * pre = (nlist_node_t *) 0;
    nlist_for_each(node, &timer_list) {
        net_timer_t * curr = nlist_entry(node, net_timer_t, node);

        // 待插入的结点超时比当前结点超时大，应当继续往后寻找
        // 因此，先将自己的时间减一下，然后继续往下遍历
        if (insert->curr > curr->curr) {
            insert->curr -= curr->curr;
        } else if (insert->curr == curr->curr) {
            // 相等，插入到其之后，超时调整为0，即超时相等
            insert->curr = 0;
            nlist_insert_after(&timer_list, node, &insert->node);
            return;
        } else {
            // 比当前超时短，插入到当前之前，那么当前的超时时间要减一下
            curr->curr -= insert->curr;
            if (pre) {
                nlist_insert_after(&timer_list, pre, &insert->node);
            } else {
                nlist_insert_first(&timer_list, &insert->node);
            }
            return;
        }
        pre = node;
    }

    // 找不到合适的位置，即超时比所有的都长，插入到最后
    nlist_insert_last(&timer_list, &insert->node);
}

net_err_t timer_init (void) {
    dbg_info(DBG_TIMER, "timer init");
    nlist_init(&timer_list);
    dbg_info(DBG_TIMER, "timer init done");
    return NET_ERR_OK;
}

net_err_t net_timer_add (net_timer_t * timer, const char * name, timer_proc_t proc, void * arg, int ms, int flags) {
    dbg_info(DBG_TIMER, "add timer %s", name);
    plat_strncpy(timer->name, name, TIMER_NAME_SIZE);
    timer->name[TIMER_NAME_SIZE - 1] = '\0';
    timer->reload = ms;
    timer->curr = timer->reload;
    timer->proc = proc;
    timer->arg = arg;
    timer->flags = flags;

    insert_timer(timer);

    display_timer_list();

    return NET_ERR_OK;
}
void net_timer_remove (net_timer_t * timer) {
    dbg_info(DBG_TIMER, "remove timer: %s", timer->name);

    // 遍历列表，找到timer
    nlist_node_t * node;
    nlist_for_each(node, &timer_list) {
        net_timer_t * curr = nlist_entry(node, net_timer_t, node);
        if (curr != timer) {
            continue;
        }

        // 如果有后继结点，只需调整后继结点的值
        nlist_node_t * next = nlist_node_next(node);
        if (next) {
            net_timer_t * next_timer = nlist_entry(next, net_timer_t, node);
            next_timer->curr += curr->curr;
        }

        // 移除结点后结束
        nlist_remove(&timer_list, node);
        break;
    }

    // 更新完成后，显示下列表，方便观察
    display_timer_list();
}

net_err_t net_timer_check_tmo (int diff_ms) {   
    nlist_t wait_list;
    nlist_init(&wait_list);
    nlist_node_t * node = nlist_first(&timer_list);

    while (node) {
        nlist_node_t * next = nlist_node_next(node);
        net_timer_t * timer = (net_timer_t *) (nlist_entry(node, net_timer_t, node));
        if (timer->curr > diff_ms) {
            timer->curr -= diff_ms;
            break;
        } else {
            diff_ms -= timer->curr;
            timer->curr = 0;
            nlist_remove(&timer_list, &timer->node);
            nlist_insert_last(&wait_list, &timer->node);
        }
        node = next;
    }

    while ((node = nlist_remove_first(&wait_list)) != (nlist_node_t *) 0) {
        net_timer_t * timer = nlist_entry(node, net_timer_t, node);
        timer->proc(timer, timer->arg);
        if (timer->flags & NET_TIMER_RELOAD) {
            timer->curr = timer->reload;
            insert_timer(timer);
        }
    }
    //display_timer_list(); 

    return NET_ERR_OK;
}
int net_timer_first_tmo (void) {
    nlist_node_t * node = nlist_first(&timer_list);
    if (node) {
        net_timer_t * timer = nlist_entry(node, net_timer_t, node);
        return timer->curr;
    }
    return 0;
}
