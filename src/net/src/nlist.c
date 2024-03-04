#include "nlist.h"



void nlist_init (nlist_t * list) {
    list->first = (nlist_node_t *) 0;
    list->last = (nlist_node_t *) 0;
    list->count = 0;
}
void nlist_insert_first (nlist_t * list, nlist_node_t * node) {
    node->prev = (nlist_node_t *) 0;
    node->next = list->first;
    if (nlist_is_empty(list)) {
        list->last = list->first = node;
    } else {
        list->first->prev = node;
        list->first = node;
    }
    list->count ++;
}
void nlist_insert_last (nlist_t * list, nlist_node_t * node) {
    node->prev = list->last;
    node->next = (nlist_node_t *) 0;
    
    if (nlist_is_empty(list)) {
        list->first = list->last = node;
    } else {
        list->last->next = node;
        list->last = node;
    }
    list->count ++;
}

void nlist_insert_after (nlist_t * list, nlist_node_t * prev_node, nlist_node_t * node) {
    if (nlist_is_empty(list)) {
        nlist_insert_first(list, node);
        return ;
    }
    node->next = prev_node->next;
    node->prev = prev_node;
    if (prev_node->next) {
        prev_node->next->prev = node;
    }
    prev_node->next = node;
    if (list->last == prev_node) {
        list->last = node;
    }

    list->count ++;
}

nlist_node_t * nlist_remove (nlist_t * list, nlist_node_t * node) {
    if (node == list->first) {
        list->first = node->next;
    }
    if (node == list->last) {
        list->last = node->prev;
    }
    if (node->prev) {
        node->prev->next = node->next;
    }
    if (node->next) {
        node->next->prev = node->prev;
    }
    node->prev = node->next = (nlist_node_t *) 0;
    list->count --;
    return node;
}