#ifndef EDMM_PAGES_H
#define EDMM_PAGES_H

#include "pal_linux.h"

/* TODO: Setting this as 64 to start with, but will need to revisit */
#define EDMM_HEAP_RANGE_CNT 64

/* edmm_heap_range objects are taken from pre-allocated pool to avoid recursive mallocs */
#define MAX_EDMM_HEAP_RANGE 10000

DEFINE_LIST(edmm_heap_pool);
DEFINE_LISTP(edmm_heap_pool);
struct edmm_heap_pool {
    LIST_TYPE(edmm_heap_pool) list;
    void* addr;
    size_t size;
    uint32_t prot;
};

struct edmm_heap_vma {
    void* addr;
    size_t size;
    uint32_t prot; /* current prot for this vma region (not requested) */
};

struct edmm_heap_request {
    uint32_t range_cnt;
    struct edmm_heap_vma vma_range[EDMM_HEAP_RANGE_CNT];
};

size_t find_preallocated_heap_nonoverlap(void* addr, size_t size);
void edmm_update_heap_request(void* addr, size_t size, pal_prot_flags_t prot,
                              struct edmm_heap_request* heap_req);
int free_edmm_page_range(void* start, size_t size);
int get_edmm_page_range(void* start_addr, size_t size);
int relax_enclave_page_permission(void* addr, size_t size, pal_prot_flags_t prot);
int restrict_enclave_page_permission(void* addr, size_t size, pal_prot_flags_t prot);
int add_to_pending_free_epc(void* addr, size_t size, uint32_t prot);
int remove_from_pending_free_epc(void* addr, size_t size, struct edmm_heap_pool* updated_heap_alloc,
                                 struct edmm_heap_request* heap_req);
void covert_lazyfree_threshold_to_bytes(void);

#endif /* EDMM_PAGES_H */