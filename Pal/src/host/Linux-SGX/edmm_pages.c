#include "edmm_pages.h"

#include <asm/errno.h>
#include <stdalign.h>

#include "api.h"
#include "list.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"

extern void* g_heap_top;
extern spinlock_t g_heap_vma_lock;
static uint64_t g_pending_free_size;
static uint64_t g_edmm_lazyfree_th_bytes;

static LISTP_TYPE(edmm_heap_pool) g_edmm_heap_pool_list = LISTP_INIT;

static struct edmm_heap_pool g_edmm_heap_pool[MAX_EDMM_HEAP_RANGE];
static size_t g_edmm_heap_rg_cnt;
static struct edmm_heap_pool* g_edmm_heap_rg = NULL;

static void print_lazy_free_ranges(void) {
    struct edmm_heap_pool* vma;
    struct edmm_heap_pool* p;
    log_debug("print_lazy_free_ranges:");
    LISTP_FOR_EACH_ENTRY_SAFE(vma, p, &g_edmm_heap_pool_list, list) {
        log_debug("\tVMA lazy free Range: %p-%p, prot: 0x%x", vma->addr, vma->addr + vma->size,
                     vma->prot);
    }
}

void covert_lazyfree_threshold_to_bytes(void) {
    g_edmm_lazyfree_th_bytes = 0;

    if (g_pal_linuxsgx_state.manifest_keys.edmm_enable_heap &&
            g_pal_linuxsgx_state.manifest_keys.edmm_lazyfree_th) {
        uint8_t* heap_max = (uint8_t*)g_pal_linuxsgx_state.heap_max;
        uint8_t* heap_min = (uint8_t*)g_pal_linuxsgx_state.heap_min;
        g_edmm_lazyfree_th_bytes = (heap_max - heap_min) *
                                   g_pal_linuxsgx_state.manifest_keys.edmm_lazyfree_th / 100;
    }
}

#define PAGE_SHIFT (12)

#define EDMM_BITMAP_OFFSET(x) ((x) >> 6)
#define EDMM_BITMAP_BITMASK(x) (1UL << ((x)&0x3f))

static inline unsigned long edmm_bitmap_is_set(volatile unsigned long *bitmap, unsigned long addr)
{
    unsigned long pg = addr >> PAGE_SHIFT;
    unsigned long bit_val;

    bit_val = *(bitmap + EDMM_BITMAP_OFFSET(pg));

    return bit_val & EDMM_BITMAP_BITMASK(pg);
}

static inline void edmm_bitmap_set(unsigned long *bitmap, unsigned long addr)
{
    unsigned long pg = addr >> PAGE_SHIFT;
    unsigned long bit_val;

    bit_val = *(bitmap + EDMM_BITMAP_OFFSET(pg));

    bit_val |= EDMM_BITMAP_BITMASK(pg);

    *(bitmap + EDMM_BITMAP_OFFSET(pg)) = bit_val;
}

static inline void edmm_bitmap_clear(unsigned long *bitmap, unsigned long addr)
{
    unsigned long pg = addr >> PAGE_SHIFT;
    unsigned long bit_val;

    bit_val = *(unsigned long *)(bitmap + EDMM_BITMAP_OFFSET(pg));

    bit_val &= ~EDMM_BITMAP_BITMASK(pg);

    *(unsigned long *)(bitmap + EDMM_BITMAP_OFFSET(pg)) = bit_val;
}

/* returns uninitialized edmm heap range */
static struct edmm_heap_pool* __alloc_heap(void) {
    assert(spinlock_is_locked(&g_heap_vma_lock));

    if (g_edmm_heap_rg) {
        /* simple optimization: if there is a cached free vma object, use it */
        assert((uintptr_t)g_edmm_heap_rg >= (uintptr_t)&g_edmm_heap_pool[0]);
        assert((uintptr_t)g_edmm_heap_rg <= (uintptr_t)&g_edmm_heap_pool[MAX_EDMM_HEAP_RANGE - 1]);

        struct edmm_heap_pool* ret = g_edmm_heap_rg;
        g_edmm_heap_rg = NULL;
        g_edmm_heap_rg_cnt++;
        return ret;
    }

    for (size_t i = 0; i < MAX_EDMM_HEAP_RANGE; i++) {
        if (!g_edmm_heap_pool[i].addr && !g_edmm_heap_pool[i].size) {
            /* found empty slot in the pool, use it */
            g_edmm_heap_rg_cnt++;
            return &g_edmm_heap_pool[i];
        }
    }

    return NULL;
}

static void __free_heap(struct edmm_heap_pool* heap_rg) {
    assert(spinlock_is_locked(&g_heap_vma_lock));
    assert((uintptr_t)heap_rg >= (uintptr_t)&g_edmm_heap_pool[0]);
    assert((uintptr_t)heap_rg <= (uintptr_t)&g_edmm_heap_pool[MAX_EDMM_HEAP_RANGE - 1]);

    heap_rg->addr = NULL;
    heap_rg->size = 0;
    heap_rg->prot = 0;
    g_edmm_heap_rg = heap_rg;
    g_edmm_heap_rg_cnt--;
}

/* Returns size that is non overlapping with the pre-allocated heap when preheat option is turned on.
 * 0 means entire request overlaps with the pre-allocated region. */
size_t find_preallocated_heap_nonoverlap(void* addr, size_t size) {
    size_t non_overlapping_size = size;

    uint64_t preheat_enclave_size = g_pal_linuxsgx_state.manifest_keys.preheat_enclave_size;
    uint8_t* heap_max = (uint8_t*)g_pal_linuxsgx_state.heap_max;

    if (preheat_enclave_size > 0) {
        if ((uint8_t*)addr >= heap_max - preheat_enclave_size) {
            /* Full overlap: Entire request lies in the pre-allocated region */
            non_overlapping_size = 0;
        } else if ((uint8_t*)addr + size > heap_max - preheat_enclave_size) {
            /* Partial overlap: Update size to skip the overlapped region. */
            non_overlapping_size = heap_max - preheat_enclave_size - (uint8_t*)addr;
        } else {
            /* No overlap */
            non_overlapping_size = size;
        }
    }

    return non_overlapping_size;
}

static void __attribute_unused dump_heap_pool_list(void)
{
    struct edmm_heap_pool* temp;

    log_debug("Dumping heap pool list:");
    LISTP_FOR_EACH_ENTRY(temp, &g_edmm_heap_pool_list, list) {
        log_debug("\t[%p, %p)", temp->addr, temp->addr+temp->size);
    }
}

/* This function adds free EPC page requests to a global list and frees the EPC pages in a lazy
 * manner once the amount of free EPC pages exceeds a certain threshold. Returns 0 on success and
 * negative unix error code on failure. */
int add_to_pending_free_epc(void* addr, size_t size, uint32_t prot) {
    assert(spinlock_is_locked(&g_heap_vma_lock));

    /* Allocate new entry for pending_free_epc range */
    struct edmm_heap_pool* new_pending_free = __alloc_heap();
    if (!new_pending_free) {
        log_error("Adding to pending free EPC pages failed %p\n", addr);
        return -PAL_ERROR_NOMEM;
    }
    new_pending_free->addr = addr;
    new_pending_free->size = size;
    new_pending_free->prot = prot;

    struct edmm_heap_pool* pending_free_epc;
    struct edmm_heap_pool* pending_above = NULL;
    LISTP_FOR_EACH_ENTRY(pending_free_epc, &g_edmm_heap_pool_list, list) {
        if (pending_free_epc->addr < addr)
            break;
        pending_above = pending_free_epc;
    }

    struct edmm_heap_pool* pending_below = NULL;
    if (pending_above) {
        pending_below = LISTP_NEXT_ENTRY(pending_above, &g_edmm_heap_pool_list, list);
    } else {
        /* no previous entry found. This is the first entry which is below [addr, addr+size) */
        pending_below = LISTP_FIRST_ENTRY(&g_edmm_heap_pool_list, struct edmm_heap_pool, list);
    }

    /* Merge with above or/and below VMAs only if the permissions are the same. */
    if (pending_above && pending_above->addr == addr + size && pending_above->prot == prot) {
        new_pending_free->size += pending_above->size;
        struct edmm_heap_pool* pending_above_above = LISTP_PREV_ENTRY(pending_above,
                                                                      &g_edmm_heap_pool_list, list);
        LISTP_DEL(pending_above, &g_edmm_heap_pool_list, list);
         __free_heap(pending_above);

        pending_above = pending_above_above;
    }

    if (pending_below && pending_below->addr + pending_below->size == addr &&
            pending_below->prot == prot) {
        new_pending_free->addr = pending_below->addr;
        new_pending_free->size += pending_below->size;

        LISTP_DEL(pending_below, &g_edmm_heap_pool_list, list);
        __free_heap(pending_below);
    }

    INIT_LIST_HEAD(new_pending_free, list);
    LISTP_ADD_AFTER(new_pending_free, pending_above, &g_edmm_heap_pool_list, list);

    /* update the pending free size */
    g_pending_free_size += size;

    /* Keep freeing last entry from the pending_free_epc list until the pending free falls
     * below the threshold */
    while (g_pending_free_size > g_edmm_lazyfree_th_bytes) {
        struct edmm_heap_pool* last_pending_free = LISTP_LAST_ENTRY(&g_edmm_heap_pool_list,
                                                                    struct edmm_heap_pool, list);
        int ret = 0;
        if (g_pal_linuxsgx_state.edmm_demand_paging)
            ret = free_edmm_page_range_sparse(last_pending_free->addr, last_pending_free->size);
        else
            ret = free_edmm_page_range(last_pending_free->addr, last_pending_free->size);

        if (ret < 0) {
            log_error("%s:Free failed! g_edmm_lazyfree_th_bytes = 0x%lx, g_pending_free_size = 0x%lx,"
                      " last_addr = %p, last_size = 0x%lx, req_addr = %p, req_size = 0x%lx\n",
                      __func__, g_edmm_lazyfree_th_bytes, g_pending_free_size,
                      last_pending_free->addr, last_pending_free->size, addr, size);
            return ret;
        }

        if (g_pending_free_size >= last_pending_free->size) {
            g_pending_free_size -= last_pending_free->size;
        } else {
            g_pending_free_size = 0;
        }

        LISTP_DEL(last_pending_free, &g_edmm_heap_pool_list, list);
        __free_heap(last_pending_free);
    }

    print_lazy_free_ranges();
    return 0;
}

/* This function checks if the requested EPC range overlaps with range in pending free EPC list.
 * If so, removes overlapping requested range from the EPC list. This can cause the requested range
 * be fragmented into smaller requests. On success, returns number of fragmented requests and
 * negative unix error code on failure. */
int remove_from_pending_free_epc(void* addr, size_t size, struct edmm_heap_pool* updated_heap_alloc,
                                 struct edmm_heap_request* heap_req) {
    assert(spinlock_is_locked(&g_heap_vma_lock));
    /* Amount of memory that is present in the lazy-free list */
    size_t allocated = 0;
    /* Index representing entries that need to be allocated dynamically */
    int alloc_cnt = 0;


    if (!g_pal_linuxsgx_state.manifest_keys.edmm_lazyfree_th || !g_pending_free_size)
        goto out;

    struct edmm_heap_pool* pending_free_epc;
    struct edmm_heap_pool* temp;

    /* Store previous free bottom pointer to see if there is unallocated memory between two pending
    free regions */
    void* prevfree_bottom = NULL;
    LISTP_FOR_EACH_ENTRY_SAFE(pending_free_epc, temp, &g_edmm_heap_pool_list, list) {
        void* pendingfree_top = (char*)pending_free_epc->addr + pending_free_epc->size;
        void* pendingfree_bottom = pending_free_epc->addr;

        log_debug("%s: pendingfree = %p - %p, prot = 0x%x", __func__, pendingfree_top,
                  pendingfree_bottom, pending_free_epc->prot);

        if (pendingfree_bottom >= (void*)((char*)addr + size))
            continue;
        if (pendingfree_top <= addr)
            break;

        /* Unallocated region between two pending free regions */
        if (prevfree_bottom && pendingfree_top < prevfree_bottom) {
            updated_heap_alloc[alloc_cnt].addr = pendingfree_top;
            updated_heap_alloc[alloc_cnt].size = (char*)prevfree_bottom- (char*)pendingfree_top;

            size -= updated_heap_alloc[alloc_cnt].size;
            alloc_cnt++;
        }
        prevfree_bottom = pendingfree_bottom;

        if (pendingfree_bottom < addr) {
             /* create a new entry for [pendingfree_bottom, addr) */
            struct edmm_heap_pool* new_pending_free = __alloc_heap();
            if (!new_pending_free) {
                log_error("Updating pending free EPC pages failed during allocation %p", addr);
                return -ENOMEM;
            }
            new_pending_free->addr = pendingfree_bottom;
            new_pending_free->size = (char*)addr - (char*)pendingfree_bottom;
            new_pending_free->prot = pending_free_epc->prot;

            /* Update size of the current pending_free entry */
            pending_free_epc->addr = addr;
            pending_free_epc->size -= new_pending_free->size;

            /* Adjust pendingfree_bottom to reflect the updated size */
            pendingfree_bottom = pending_free_epc->addr;

            INIT_LIST_HEAD(new_pending_free, list);
            LIST_ADD(new_pending_free, pending_free_epc, list);
        }

        if (pendingfree_top <= (void*)((char*)addr + size)) {
            allocated += pending_free_epc->size;
            edmm_update_heap_request(pending_free_epc->addr, pending_free_epc->size,
                                     pending_free_epc->prot, heap_req);
            /* Update the start addr and set it to pendingfree_top as the original start address
             * was already allocated. */
            if (pendingfree_top < (void*)((char*)addr + size)) {
                addr = (void*)((char*)pending_free_epc->addr + pending_free_epc->size);
                log_error("pendingfree_top <= (void*)((char*)addr + size; addr = %p", addr);
            }
            size -= pending_free_epc->size;

            LISTP_DEL(pending_free_epc, &g_edmm_heap_pool_list, list);
            __free_heap(pending_free_epc);
        } else {
            /* Adjust pending_free_epc [addr + size, pendingfree_top) to remove allocated region */
            pending_free_epc->addr = (void*)((char*)addr + size);
            pending_free_epc->size = (char*)pendingfree_top - ((char*)addr + size);

            if (pendingfree_bottom >= addr) {
                allocated += (char*)addr + size - (char*)pendingfree_bottom;
                edmm_update_heap_request(pendingfree_bottom,
                                         (char*)addr + size - (char*)pendingfree_bottom,
                                         pending_free_epc->prot, heap_req);
                size -= (char*)addr + size - (char*)pendingfree_bottom;
            }
        }
    }

out:
    if (size) {
        updated_heap_alloc[alloc_cnt].addr = addr;
        updated_heap_alloc[alloc_cnt].size = size;
        alloc_cnt++;
    }

    /* Update the pending free size */
    if (allocated)
        g_pending_free_size -= allocated;

    return alloc_cnt;
}

void edmm_update_heap_request(void* addr, size_t size, pal_prot_flags_t prot,
                              struct edmm_heap_request* heap_req) {
    assert(heap_req->range_cnt < EDMM_HEAP_RANGE_CNT);

    int range_cnt = heap_req->range_cnt;
    heap_req->vma_range[range_cnt].addr = addr;
    heap_req->vma_range[range_cnt].size = size;
    heap_req->vma_range[range_cnt].prot = prot;
    heap_req->range_cnt += 1;
}

int relax_enclave_page_permission(void* addr, size_t size, pal_prot_flags_t prot) {

    void* start = addr;
    void* end = (void*)((char*)start + size);

    log_debug("%s: addr = %p, size = 0x%lx, prot = 0x%x", __func__, addr, size, prot);
    alignas(64) sgx_arch_sec_info_t secinfo_relax;
    memset(&secinfo_relax, 0, sizeof(secinfo_relax));

    secinfo_relax.flags |= (prot & PAL_PROT_READ) ? SGX_SECINFO_FLAGS_R : 0;
    secinfo_relax.flags |= (prot & PAL_PROT_WRITE) ? SGX_SECINFO_FLAGS_W : 0;
    secinfo_relax.flags |= (prot & PAL_PROT_EXEC) ? SGX_SECINFO_FLAGS_X : 0;

    while (start < end) {
       sgx_modpe(&secinfo_relax, start);
       start = (void*)((char*)start + g_pal_public_state.alloc_align);
    }

    /* Update OS page tables to match new EPCM permission */
    int ret = ocall_mprotect(addr, size, prot);
    if (ret < 0) {
        log_error("mprotect for relax enclave %p page permission failed (%d)\n", addr, ret);
        return ret;
    }

    return 0;
}

int restrict_enclave_page_permission(void* addr, size_t size, pal_prot_flags_t prot) {

    void* start = addr;
    void* end = (void*)((char*)start + size);

    log_debug("%s: addr = %p, size = 0x%lx, prot = 0x%x", __func__, addr, size, prot);
    uint32_t restrict_permissions;
    restrict_permissions = (prot & PAL_PROT_READ) ? SGX_SECINFO_FLAGS_R : 0;
    restrict_permissions |= (prot & PAL_PROT_WRITE) ? SGX_SECINFO_FLAGS_W : 0;
    restrict_permissions |= (prot & PAL_PROT_EXEC) ? SGX_SECINFO_FLAGS_X : 0;

    int ret = ocall_restrict_page_permissions(addr, size, restrict_permissions);
    if (ret < 0) {
        log_error("Restrict enclave page permission on %p page failed (%d)\n", addr, ret);
        return ret;
    }

    alignas(64) sgx_arch_sec_info_t secinfo_restrict;
    memset(&secinfo_restrict, 0, sizeof(secinfo_restrict));
    secinfo_restrict.flags = restrict_permissions | (SGX_SECINFO_FLAGS_REG | SGX_SECINFO_FLAGS_PR);
    while (start < end) {
        ret = sgx_accept(&secinfo_restrict, start);
        if (ret) {
            log_error("%s: EDMM accept page failed: %p %d\n", __func__, start, ret);
            return -EFAULT;
        }

        start = (void*)((char*)start + g_pal_public_state.alloc_align);
    }
}

// XXX: for demand paging, the region could be sparsely allocated
int free_edmm_page_range_sparse(void* start, size_t size) {
    void *tmp_addr = start;
    void *end_addr = start + size;

    while (1) {
        while (tmp_addr < end_addr && !edmm_bitmap_is_set(g_pal_linuxsgx_state.demand_bitmap, (unsigned long)tmp_addr))
            tmp_addr += g_page_size;

        if (tmp_addr >= end_addr)
            break;

        void *free_addr = tmp_addr;

        edmm_bitmap_clear(g_pal_linuxsgx_state.demand_bitmap, (unsigned long)tmp_addr);
        for (tmp_addr = free_addr + g_page_size;
                tmp_addr < end_addr && edmm_bitmap_is_set(g_pal_linuxsgx_state.demand_bitmap, (unsigned long)tmp_addr);
                tmp_addr += g_page_size) {
            edmm_bitmap_clear(g_pal_linuxsgx_state.demand_bitmap, (unsigned long)tmp_addr);
        }

        size_t free_size = tmp_addr - free_addr;
        free_edmm_page_range(free_addr, free_size);
    }
    return 0;
}

/* This function trims EPC pages on enclave's request. The sequence is as below:
 * 1. Enclave calls SGX driver IOCTL to change the page's type to PT_TRIM.
 * 2. Driver invokes ETRACK to track page's address on all CPUs and issues IPI to flush stale TLB
 * entries.
 * 3. Enclave issues an EACCEPT to accept changes to each EPC page.
 * 4. Enclave notifies the driver to remove EPC pages (using an IOCTL).
 * 5. Driver issues EREMOVE to complete the request. */
int free_edmm_page_range(void* start, size_t size) {
    void* addr = ALLOC_ALIGN_DOWN_PTR(start);
    void* end = (void*)((char*)addr + size);
    int ret = 0;

    log_debug("%s: addr = %p, size = 0x%lx", __func__, addr, size);
    enum sgx_page_type type = SGX_PAGE_TYPE_TRIM;
    ret = ocall_trim_epc_pages(addr, size, type);
    if (ret < 0) {
        log_error("EPC trim page on [%p, %p) failed (%d)\n", addr, end, ret);
        return ret;
    }

    alignas(64) sgx_arch_sec_info_t secinfo;
    memset(&secinfo, 0, sizeof(secinfo));
    secinfo.flags = SGX_SECINFO_FLAGS_TRIM | SGX_SECINFO_FLAGS_MODIFIED;
    for (void* page_addr = addr; page_addr < end;
        page_addr = (void*)((char*)page_addr + g_pal_public_state.alloc_align)) {
        ret = sgx_accept(&secinfo, page_addr);
        if (ret) {
            log_error("EDMM accept page failed while trimming: %p %d\n", page_addr, ret);
            return -EFAULT;
        }
    }

    ret = ocall_remove_trimmed_pages(addr, size);
    if (ret < 0) {
        log_error("EPC notify_accept on [%p, %p), %ld pages failed (%d)\n", addr, end, size, ret);
        return ret;
    }

    return 0;
}

/* This function allocates EPC pages within ELRANGE of an enclave. If EPC pages contain
 * executable code, page permissions are extended once the page is in a valid state. The
 * allocation sequence is described below:
 * 1. Enclave invokes EACCEPT on a new page request which triggers a page fault (#PF) as the page
 * is not available yet.
 * 2. Driver catches this #PF and issues EAUG for the page (at this point the page becomes VALID and
 * may be used by the enclave). The control returns back to enclave.
 * 3. Enclave continues the same EACCEPT and the instruction succeeds this time. */
int get_edmm_page_range(void* start_addr, size_t size) {
    alignas(64) sgx_arch_sec_info_t secinfo;
    secinfo.flags = SGX_SECINFO_FLAGS_R | SGX_SECINFO_FLAGS_W | SGX_SECINFO_FLAGS_REG |
                    SGX_SECINFO_FLAGS_PENDING;
    memset(&secinfo.reserved, 0, sizeof(secinfo.reserved));

    log_debug("%s: addr = %p, size = 0x%lx", __func__, start_addr, size);
    void* lo = start_addr;
    void* addr = (void*)((char*)lo + size);

    while (lo < addr) {
        addr = (void*)((char*)addr - g_pal_public_state.alloc_align);

        int ret = sgx_accept(&secinfo, addr);
        if (ret) {
            log_error("EDMM accept page failed: %p %d\n", addr, ret);
            return -EFAULT;
        }
        if (g_pal_linuxsgx_state.manifest_keys.edmm_demand_paging)
            edmm_bitmap_set(g_pal_linuxsgx_state.demand_bitmap, (unsigned long)addr);

        /* All new pages will have RW permissions initially, so after EAUG/EACCEPT, extend
         * permission of a VALID enclave page (if needed). */
        if (executable) {
            alignas(64) sgx_arch_sec_info_t secinfo_extend = secinfo;

            secinfo_extend.flags |= SGX_SECINFO_FLAGS_X;
            sgx_modpe(&secinfo_extend, addr);
        }
    }

    return 0;
}
