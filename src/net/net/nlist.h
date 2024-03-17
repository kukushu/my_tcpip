#ifndef NLIST_H
#define NLIST_H

typedef struct _nlist_node_t {
    struct _nlist_node_t * prev;
    struct _nlist_node_t * next;
} nlist_node_t;

static inline void nlist_node_init (nlist_node_t * node) {
    node->prev = (nlist_node_t *)0;
    node->next = (nlist_node_t *)0;
}

static inline nlist_node_t * nlist_node_next (nlist_node_t * node) {
    return node->next;
}

static inline nlist_node_t * nlist_node_prev (nlist_node_t * node) {
    return node->prev;
}

static inline void nlist_node_set_next (nlist_node_t * node, nlist_node_t * next) {
    node->next = next;
}


typedef struct _nlist_t {
    nlist_node_t * first;
    nlist_node_t * last;
    int count;
} nlist_t;




static inline int nlist_is_empty (nlist_t * list) {
    return list->count == 0;
}
static inline int nlist_count (nlist_t * list) {
    return list->count;
}
static inline nlist_node_t * nlist_first (nlist_t * list) {
    return list->first;
}
static inline nlist_node_t * nlist_last (nlist_t * list) {
    return list->last;
}

void nlist_init (nlist_t * list);
void nlist_insert_first (nlist_t * list, nlist_node_t * node); 
void nlist_insert_last (nlist_t * list, nlist_node_t * node);
void nlist_insert_after (nlist_t * list, nlist_node_t * prev_node, nlist_node_t * remove_node);
nlist_node_t * nlist_remove (nlist_t * list, nlist_node_t * node);
static inline nlist_node_t * nlist_remove_first (nlist_t * list) {
    nlist_node_t * first = nlist_first(list);
    if (first) {
        nlist_remove(list, first);
    }
    return first;
}
static inline nlist_node_t * nlist_remove_last (nlist_t * list) {
    nlist_node_t * last = nlist_last(list);
    if (last) {
        nlist_remove(list, last);
    }
    return last;
}


#define noffset_in_parent(parent_type, node_name) ((char *)&(((parent_type *) 0)->node_name))
#define noffset_to_parent(node_p, parent_type, node_name) ((char *) node_p - noffset_in_parent(parent_type, node_name))
#define nlist_for_each(node_p, list) for (node_p = ((nlist_t *) list)->first; node_p; node_p = node_p->next)
#define nlist_entry(node_p, parent_type, node_name) ((parent_type *)(node_p ? noffset_to_parent(node_p, parent_type, node_name) :0))



#endif