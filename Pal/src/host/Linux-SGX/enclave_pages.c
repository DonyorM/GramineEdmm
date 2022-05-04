#include "enclave_pages.h"

#include <asm/errno.h>
#include <stdalign.h>

#include "api.h"
#include "edmm_pages.h"
#include "asan.h"
#include "list.h"
#include "pal_error.h"
#include "pal_linux.h"
#include "spinlock.h"

/* heap_vma objects are taken from pre-allocated pool to avoid recursive mallocs */
#define MAX_HEAP_VMAS 100000

struct atomic_int g_allocated_pages;

/* list of VMAs of used memory areas kept in DESCENDING order; note that preallocated PAL internal
 * memory relies on this descending order of allocations (from high addresses to low), see
 * _DkGetAvailableUserAddressRange() for more details */
DEFINE_LIST(heap_vma);
struct heap_vma {
    LIST_TYPE(heap_vma) list;
    void* bottom;
    void* top;
    uint32_t prot;
    bool is_pal_internal;
};
DEFINE_LISTP(heap_vma);

static LISTP_TYPE(heap_vma) g_heap_vma_list = LISTP_INIT;
spinlock_t g_heap_vma_lock = INIT_SPINLOCK_UNLOCKED;
static struct heap_vma g_heap_vma_pool[MAX_HEAP_VMAS];
static size_t g_heap_vma_num = 0;
static struct heap_vma* g_free_vma = NULL;

static void print_vma_ranges(void) {
    struct heap_vma* vma;
    struct heap_vma* p;
    log_debug("print_vma_ranges:");
    LISTP_FOR_EACH_ENTRY_SAFE(vma, p, &g_heap_vma_list, list) {
        log_debug("\tVMA Range: %p-%p, prot: 0x%x", vma->top, vma->bottom, vma->prot);
    }
}

/* returns uninitialized heap_vma, the caller is responsible for setting at least bottom/top */
static struct heap_vma* __alloc_vma(void) {
    assert(spinlock_is_locked(&g_heap_vma_lock));

    if (g_free_vma) {
        /* simple optimization: if there is a cached free vma object, use it */
        assert((uintptr_t)g_free_vma >= (uintptr_t)&g_heap_vma_pool[0]);
        assert((uintptr_t)g_free_vma <= (uintptr_t)&g_heap_vma_pool[MAX_HEAP_VMAS - 1]);

        struct heap_vma* ret = g_free_vma;
        g_free_vma = NULL;
        g_heap_vma_num++;
        return ret;
    }

    /* FIXME: this loop may become perf bottleneck on large number of vma objects; however,
     * experiments show that this number typically does not exceed 20 (thanks to VMA merging) */
    for (size_t i = 0; i < MAX_HEAP_VMAS; i++) {
        if (!g_heap_vma_pool[i].bottom && !g_heap_vma_pool[i].top) {
            /* found empty slot in the pool, use it */
            g_heap_vma_num++;
            return &g_heap_vma_pool[i];
        }
    }

    return NULL;
}

static void __free_vma(struct heap_vma* vma) {
    assert(spinlock_is_locked(&g_heap_vma_lock));
    assert((uintptr_t)vma >= (uintptr_t)&g_heap_vma_pool[0]);
    assert((uintptr_t)vma <= (uintptr_t)&g_heap_vma_pool[MAX_HEAP_VMAS - 1]);

    g_free_vma  = vma;
    vma->top    = 0;
    vma->bottom = 0;
    g_heap_vma_num--;
}

static void* __create_vma_and_merge(void* addr, size_t size, pal_prot_flags_t prot,
                                    bool is_pal_internal, struct heap_vma* vma_above,
                                    struct edmm_heap_request* heap_alloc,
                                    struct edmm_heap_request* heap_perm) {
    assert(spinlock_is_locked(&g_heap_vma_lock));
    assert(addr && size);

    if (addr < g_pal_linuxsgx_state.heap_min)
        return NULL;

    /* PAL-internal memory cannot be allocated below the PAL-internal part of heap */
    if (is_pal_internal && addr < g_pal_linuxsgx_state.heap_max - g_pal_internal_mem_size)
        return NULL;

    /* find enclosing VMAs and check that pal-internal VMAs do not overlap with normal VMAs */
    struct heap_vma* vma_below;
    if (vma_above) {
        vma_below = LISTP_NEXT_ENTRY(vma_above, &g_heap_vma_list, list);
    } else {
        /* no VMA above `addr`; VMA right below `addr` must be the first (highest-address) in list */
        vma_below = LISTP_FIRST_ENTRY(&g_heap_vma_list, struct heap_vma, list);
    }

    /* check wether [addr, addr + size) overlaps with above VMAs of different type */
    struct heap_vma* check_vma_above = vma_above;
    while (check_vma_above && addr + size > check_vma_above->bottom) {
        if (check_vma_above->is_pal_internal != is_pal_internal) {
            return NULL;
        }
        check_vma_above = LISTP_PREV_ENTRY(check_vma_above, &g_heap_vma_list, list);
    }

    /* check whether [addr, addr + size) overlaps with below VMAs of different type */
    struct heap_vma* check_vma_below = vma_below;
    while (check_vma_below && addr < check_vma_below->top) {
        if (check_vma_below->is_pal_internal != is_pal_internal) {
            return NULL;
        }
        check_vma_below = LISTP_NEXT_ENTRY(check_vma_below, &g_heap_vma_list, list);
    }

    /* create VMA with [addr, addr+size); in case of existing overlapping VMAs, the created VMA is
     * merged with them and the old VMAs are discarded, similar to mmap(MAX_FIXED) */
    struct heap_vma* vma = __alloc_vma();
    if (!vma)
        return NULL;
    vma->bottom          = addr;
    vma->top             = addr + size;
    vma->is_pal_internal = is_pal_internal;
    vma->prot = prot;

    /* how much memory was freed because [addr, addr + size) overlapped with VMAs */
    size_t freed = 0;

    /* Try to merge VMAs as an optimization:
     *   (1) start from `vma_above` and iterate through VMAs with higher-addresses for merges
     *   (2) start from `vma_below` and iterate through VMAs with lower-addresses for merges.
     * Note that we never merge normal VMAs with pal-internal VMAs. */
    void* unallocated_start_addr = (vma_below) ? MAX(vma_below->top, vma->bottom) : vma->bottom;
    while (vma_above && vma_above->bottom <= vma->top &&
           vma_above->is_pal_internal == vma->is_pal_internal) {

        if (g_pal_linuxsgx_state.manifest_keys.edmm_enable_heap &&
            vma_above->top > vma->top && vma_above->prot != vma->prot) {
            size_t perm_size = vma->top - vma_above->bottom;
            if (perm_size)
                edmm_update_heap_request(vma_above->bottom, perm_size, vma_above->prot, heap_perm);

            /* Split the VMA and stop further VMA merges */
            freed += perm_size;
            vma_above->bottom = vma->top;
            break;
        }

        /* newly created VMA grows into above VMA; expand newly created VMA and free above-VMA */
        freed += vma_above->top - vma_above->bottom;
        struct heap_vma* vma_above_above = LISTP_PREV_ENTRY(vma_above, &g_heap_vma_list, list);

        /* Update edmm heap request */
        if (g_pal_linuxsgx_state.manifest_keys.edmm_enable_heap && vma_above->prot != prot) {
            size_t size = vma_above->top - vma_above->bottom;
            edmm_update_heap_request(vma_above->bottom, size, vma_above->prot, heap_perm);
        }


        /* Track unallocated memory regions between VMAs while merging `vma_above`. */
        if (g_pal_linuxsgx_state.manifest_keys.edmm_enable_heap &&
            vma_above->bottom > unallocated_start_addr) {
            size_t alloc_size = vma_above->bottom - unallocated_start_addr;
            /* This is unallocated memory so set current prot permission as R | W as this is the
             * default permission set by the driver after a page is EAUGed. */
            edmm_update_heap_request(unallocated_start_addr, alloc_size,
                                     PAL_PROT_READ | PAL_PROT_WRITE, heap_alloc);
        }

        vma->bottom = MIN(vma_above->bottom, vma->bottom);
        vma->top    = MAX(vma_above->top, vma->top);
        LISTP_DEL(vma_above, &g_heap_vma_list, list);

        /* Store vma_above->top to check for any free region between vma_above->top and
        * vma_above_above->bottom. */
        if (g_pal_linuxsgx_state.manifest_keys.edmm_enable_heap)
            unallocated_start_addr = vma_above->top;

        __free_vma(vma_above);
        vma_above = vma_above_above;

    }

    while (vma_below && vma_below->top >= vma->bottom &&
           vma_below->is_pal_internal == vma->is_pal_internal) {

        if (g_pal_linuxsgx_state.manifest_keys.edmm_enable_heap && vma_below->prot != vma->prot) {
            if (vma_below->top > vma->top) {
                /* create VMA [vma->bottom, addr); this may leave VMA [addr + size, vma->top), see below */
                struct heap_vma* new = __alloc_vma();
                if (!new) {
                    log_error("Cannot create split VMA during allocation of address %p - %p",
                              vma->top, vma->bottom);
                    ocall_exit(/*exitcode=*/1, /*is_exitgroup=*/true);
                }
                new->top             = vma_below->top;
                new->bottom          = vma->top;
                new->is_pal_internal = vma->is_pal_internal;
                new->prot            = vma_below->prot;
                INIT_LIST_HEAD(new, list);
                LISTP_ADD_AFTER(new, vma_above, &g_heap_vma_list, list);
                vma_above = new;
                vma_below->top = vma->top;
            }

            /* Split vma_below [vma_below->bottom, vma->bottom) */
            size_t perm_size = vma_below->top - vma->bottom;
            if (perm_size)
                edmm_update_heap_request(vma->bottom, perm_size, vma_below->prot, heap_perm);

            /* Split the VMA and stop further VMA merges */
            freed += perm_size;
            vma_below->top = vma->bottom;

            break;
        }

        /* newly created VMA grows into below VMA; expand newly create VMA and free below-VMA */
        freed += vma_below->top - vma_below->bottom;
        struct heap_vma* vma_below_below = LISTP_NEXT_ENTRY(vma_below, &g_heap_vma_list, list);

        /* Update edmm heap request */
        if (g_pal_linuxsgx_state.manifest_keys.edmm_enable_heap && vma_below->prot != prot) {
            size_t size = vma_below->top - vma_below->bottom;
            edmm_update_heap_request(vma_below->bottom, size, vma_below->prot, heap_perm);
        }

        vma->bottom = MIN(vma_below->bottom, vma->bottom);
        vma->top    = MAX(vma_below->top, vma->top);
        LISTP_DEL(vma_below, &g_heap_vma_list, list);

        __free_vma(vma_below);
        vma_below = vma_below_below;
    }

    INIT_LIST_HEAD(vma, list);
    LISTP_ADD_AFTER(vma, vma_above, &g_heap_vma_list, list);

    if (vma->bottom >= vma->top) {
        log_error("Bad memory bookkeeping: %p - %p", vma->bottom, vma->top);
        ocall_exit(/*exitcode=*/1, /*is_exitgroup=*/true);
    }

    assert(vma->top - vma->bottom >= (ptrdiff_t)freed);
    size_t allocated = vma->top - vma->bottom - freed;

    /* No unallocated memory regions between VMAs found */
    if (g_pal_linuxsgx_state.manifest_keys.edmm_enable_heap &&
        heap_alloc->range_cnt == 0 && allocated > 0) {
        edmm_update_heap_request(unallocated_start_addr, allocated, PAL_PROT_READ | PAL_PROT_WRITE,
                                 heap_alloc);
    }

    __atomic_add_fetch(&g_allocated_pages.counter, allocated / g_page_size, __ATOMIC_SEQ_CST);

    return addr;
}

void* get_enclave_pages(void* addr, size_t size, pal_prot_flags_t prot, bool is_pal_internal) {
    void* ret = NULL;
    /* TODO: Should we introduce a compiler switch for EDMM? */
    struct edmm_heap_request heap_alloc = {0};
    struct edmm_heap_request heap_perm = {0};

    if (!size)
        return NULL;

    size = ALIGN_UP(size, g_page_size);
    addr = ALIGN_DOWN_PTR(addr, g_page_size);

    assert(access_ok(addr, size));
    struct heap_vma* vma_above = NULL;
    struct heap_vma* vma;
    pal_prot_flags_t req_prot = (PAL_PROT_READ | PAL_PROT_WRITE | PAL_PROT_EXEC) & prot;
    /* With EDMM an EPC page is allocated with RW permission and then the desired permission is
     * is set. Restrict permission from RW -> W is architecturally not permitted and the driver will
     * returns -EINVAL error. So adding READ permission if the page permission is only WRITE. */
    if (req_prot == PAL_PROT_WRITE) {
        req_prot = PAL_PROT_READ | PAL_PROT_WRITE;
    }

    log_debug("start %s: addr = %p, size = 0x%lx, prot = 0x%x, req_prot = 0x%x", __func__, addr,
              size, prot, req_prot);

    spinlock_lock(&g_heap_vma_lock);

    print_vma_ranges();

    if (addr) {
        /* caller specified concrete address; find VMA right-above this address */
        if (addr < g_pal_linuxsgx_state.heap_min || addr + size > g_pal_linuxsgx_state.heap_max)
            goto out;

        LISTP_FOR_EACH_ENTRY(vma, &g_heap_vma_list, list) {
            if (vma->bottom < addr) {
                /* current VMA is not above `addr`, thus vma_above is VMA right-above `addr` */
                break;
            }
            vma_above = vma;
        }
        ret = __create_vma_and_merge(addr, size, req_prot, is_pal_internal, vma_above, &heap_alloc,
                                     &heap_perm);
    } else {
        /* caller did not specify address; find first (highest-address) empty slot that fits */
        void* vma_above_bottom = g_pal_linuxsgx_state.heap_max;

        LISTP_FOR_EACH_ENTRY(vma, &g_heap_vma_list, list) {
            if (vma->top < vma_above_bottom - size) {
                ret = __create_vma_and_merge(vma_above_bottom - size, size, req_prot, is_pal_internal,
                                             vma_above, &heap_alloc, &heap_perm);
                goto out;
            }
            vma_above = vma;
            vma_above_bottom = vma_above->bottom;
        }

        /* corner case: there may be enough space between heap bottom and the lowest-address VMA */
        if (g_pal_linuxsgx_state.heap_min < vma_above_bottom - size)
            ret = __create_vma_and_merge(vma_above_bottom - size, size, req_prot, is_pal_internal,
                                         vma_above, &heap_alloc, &heap_perm);
    }

out:
    /* In order to prevent already accepted pages from being accepted again, we track EPC pages that
     * aren't accepted yet (unallocated heap) and call EACCEPT only on those EPC pages. */
    if (g_pal_linuxsgx_state.manifest_keys.edmm_enable_heap && ret != NULL) {
        /* Allocate EPC memory */
        for (uint32_t i = 0; i < heap_alloc.range_cnt; i++) {
            void* alloc_addr = heap_alloc.vma_range[i].addr;
            size_t alloc_size = heap_alloc.vma_range[i].size;
            uint32_t vma_prot = heap_alloc.vma_range[i].prot;

            log_debug("heap_alloc.vma_range[%d].addr = %p, alloc_size = 0x%lx, vma_prot = 0x%x", i,
                       alloc_addr,  alloc_size, vma_prot);
            /* Check if the requested region falls within pre-allocated region and skip the
               allocation */
            size_t non_overlapping_size = find_preallocated_heap_nonoverlap(alloc_addr, alloc_size);
            if (non_overlapping_size == 0)
                continue;

            log_debug("heap_alloc.vma_range[%d].addr = %p, non_overlapping_size = 0x%lx, vma_prot = 0x%x", i,
                       alloc_addr,  non_overlapping_size, vma_prot);
            /* Check if the req. range is available in the pending_free EPC list, if so update the
             * list and continue to the next requested range. */
            struct edmm_heap_pool updated_heap_alloc[EDMM_HEAP_RANGE_CNT] = {0};
            int req_cnt = remove_from_pending_free_epc(alloc_addr, non_overlapping_size,
                                                       updated_heap_alloc, &heap_perm);
            if (req_cnt < 0 ) {
                return NULL;
            }
            for (int j= 0; j < req_cnt; j++) {
                int retval = get_edmm_page_range(updated_heap_alloc[j].addr,
                                                 updated_heap_alloc[j].size);
                if (retval < 0) {
                    ret = NULL;
                    goto release_lock;
                }

                /* Due SGX2 architectural requirement the driver sets default page permission to R | W.
                 * So, if the requested permissions is  R | W then we  skip it. */
                if (req_prot != vma_prot) {
                    edmm_update_heap_request(updated_heap_alloc[j].addr, updated_heap_alloc[j].size,
                                             vma_prot, &heap_perm);
                }
            }
        }

        /* Update page permissions */
        for (uint32_t i = 0; i < heap_perm.range_cnt; i++) {
            void* vma_addr = heap_perm.vma_range[i].addr;
            size_t vma_size = heap_perm.vma_range[i].size;
            pal_prot_flags_t vma_prot = heap_perm.vma_range[i].prot;

            log_debug("heap_perm.vma_range[%d].addr = %p, alloc_size = 0x%lx, vma_prot = 0x%x", i,
                       vma_addr, vma_size, vma_prot);
            /* Check if the requested region falls within pre-allocated region and skip the
               page change permission request. */
            size_t non_overlapping_size = find_preallocated_heap_nonoverlap(vma_addr, vma_size);
            if (non_overlapping_size == 0)
                continue;

            log_debug("heap_perm.vma_range[%d].addr = %p, non_overlapping_size = 0x%lx, vma_prot = 0x%x",
                        i, vma_addr, non_overlapping_size, vma_prot);
            if ((req_prot & vma_prot) != vma_prot) {
                int retval = restrict_enclave_page_permission(vma_addr, non_overlapping_size,
                                                              req_prot & vma_prot);
                if (retval < 0) {
                    ret = NULL;
                    goto release_lock;
                }
                vma_prot = req_prot & vma_prot;
            }

            if (req_prot & ~vma_prot) {
                int retval = relax_enclave_page_permission(vma_addr, non_overlapping_size,
                                                           req_prot | vma_prot);
                if (retval < 0) {
                    ret = NULL;
                    goto release_lock;
                }
            }
        }
    }

release_lock:
    log_debug("end %s: addr = %p, size = 0x%lx ", __func__, ret, size);
    print_vma_ranges();

    spinlock_unlock(&g_heap_vma_lock);

    if (ret) {
        if (is_pal_internal) {
            /* This should be guaranteed by the check in `__create_vma_and_merge()` */
            assert(ret >= g_pal_linuxsgx_state.heap_max - g_pal_internal_mem_size);
        } else {
            assert(ret >= g_pal_linuxsgx_state.heap_min);
        }
        assert(ret + size <= g_pal_linuxsgx_state.heap_max);

#ifdef ASAN
        asan_unpoison_region((uintptr_t)ret, size);
#endif
    }

    return ret;
}

int free_enclave_pages(void* addr, size_t size) {
    int ret = 0;
    /* TODO: Should we introduce a compiler switch for EDMM? */
    struct edmm_heap_request heap_free = {0};

    if (!size)
        return -PAL_ERROR_NOMEM;

    size = ALIGN_UP(size, g_page_size);

    if (!access_ok(addr, size)
        || !IS_ALIGNED_PTR(addr, g_page_size)
        || addr < g_pal_linuxsgx_state.heap_min
        || addr + size > g_pal_linuxsgx_state.heap_max) {
        return -PAL_ERROR_INVAL;
    }

    log_debug("start %s: addr = %p, size = 0x%lx", __func__, addr, size);
    spinlock_lock(&g_heap_vma_lock);
    print_vma_ranges();
    /* VMA list contains both normal and pal-internal VMAs; it is impossible to free an area
     * that overlaps with VMAs of two types at the same time, so we fail in such cases */
    bool is_pal_internal_set = false;
    bool is_pal_internal = false;

    /* how much memory was actually freed, since [addr, addr + size) can overlap with VMAs */
    size_t freed = 0;

    struct heap_vma* vma;
    struct heap_vma* p;
    LISTP_FOR_EACH_ENTRY_SAFE(vma, p, &g_heap_vma_list, list) {
        if (vma->bottom >= addr + size)
            continue;
        if (vma->top <= addr)
            break;

        log_debug("vma = %p - %p, prot = %x", vma->top, vma->bottom, vma->prot);
        /* found VMA overlapping with area to free; check it is either normal or pal-internal */
        if (!is_pal_internal_set) {
            is_pal_internal = vma->is_pal_internal;
            is_pal_internal_set = true;
        }

        if (is_pal_internal != vma->is_pal_internal) {
            log_error("Area to free (address %p, size %lu) overlaps with both normal and "
                      "pal-internal VMAs",
                      addr, size);
            ret = -PAL_ERROR_INVAL;
            goto out;
        }

        void* free_heap_top = MIN(vma->top, addr + size);
        void* free_heap_bottom = MAX(vma->bottom, addr);
        size_t range = free_heap_top - free_heap_bottom;
        freed += range;
        if (g_pal_linuxsgx_state.manifest_keys.edmm_enable_heap) {
            /* if range is contiguous with previous entry, update addr and size accordingly;
             * this case may be rare but the below optimization still saves us 2 OCALLs and 2
             * IOCTLs, so should be worth it */
            if (heap_free.range_cnt > 0 &&
                free_heap_top == heap_free.vma_range[heap_free.range_cnt - 1].addr &&
                vma->prot == heap_free.vma_range[heap_free.range_cnt - 1].prot) {
                heap_free.vma_range[heap_free.range_cnt - 1].addr = free_heap_bottom;
                heap_free.vma_range[heap_free.range_cnt - 1].size += range;
                heap_free.vma_range[heap_free.range_cnt - 1].prot = vma->prot;
                log_debug("heap_free vma#2 = %p - %p, prot = %x",
                    heap_free.vma_range[heap_free.range_cnt - 1].addr,
                    heap_free.vma_range[heap_free.range_cnt - 1].addr + heap_free.vma_range[heap_free.range_cnt - 1].size,
                    vma->prot);
            } else {
                assert(heap_free.range_cnt < EDMM_HEAP_RANGE_CNT);
                /* found a new non-contiguous range */
                heap_free.vma_range[heap_free.range_cnt].addr = free_heap_bottom;
                heap_free.vma_range[heap_free.range_cnt].size = range;
                heap_free.vma_range[heap_free.range_cnt].prot = vma->prot;
                heap_free.range_cnt++;
                 log_debug("heap_free vma#1 = %p - %p, prot = %x", free_heap_bottom,
                    free_heap_bottom + range, vma->prot);
            }
        }

        if (vma->bottom < addr) {
            /* create VMA [vma->bottom, addr); this may leave VMA [addr + size, vma->top), see below */
            struct heap_vma* new = __alloc_vma();
            if (!new) {
                log_error("Cannot create split VMA during freeing of address %p", addr);
                ret = -PAL_ERROR_NOMEM;
                goto out;
            }
            new->top             = addr;
            new->bottom          = vma->bottom;
            new->is_pal_internal = vma->is_pal_internal;
            new->prot            = vma->prot;
            INIT_LIST_HEAD(new, list);
            LIST_ADD(new, vma, list);
        }

        /* compress overlapping VMA to [addr + size, vma->top) */
        vma->bottom = addr + size;
        if (vma->top <= addr + size) {
            /* memory area to free completely covers/extends above the rest of the VMA */
            LISTP_DEL(vma, &g_heap_vma_list, list);
            __free_vma(vma);
        }
    }

    __atomic_sub_fetch(&g_allocated_pages.counter, freed / g_page_size, __ATOMIC_SEQ_CST);

#ifdef ASAN
    asan_poison_region((uintptr_t)addr, size, ASAN_POISON_USER);
#endif

out:
    if (ret >=0 && g_pal_linuxsgx_state.manifest_keys.edmm_enable_heap) {
        for (uint32_t i = 0; i < heap_free.range_cnt; i++) {
            size_t non_overlapping_size =
                find_preallocated_heap_nonoverlap(heap_free.vma_range[i].addr,
                                                  heap_free.vma_range[i].size);

            /* Entire request overlaps with preallocated heap, so simply return. */
            if (non_overlapping_size == 0)
                continue;

            if (g_pal_linuxsgx_state.manifest_keys.edmm_lazyfree_th > 0) {
                ret = add_to_pending_free_epc(heap_free.vma_range[i].addr, non_overlapping_size,
                                              heap_free.vma_range[i].prot);
            } else {
                ret = free_edmm_page_range(heap_free.vma_range[i].addr, non_overlapping_size);
            }

            if (ret < 0) {
                ret = -PAL_ERROR_INVAL;
                break;
            }
        }
    }
    log_debug("end %s: addr = %p, size = 0x%lx", __func__, addr, size);
    print_vma_ranges();
    spinlock_unlock(&g_heap_vma_lock);
    return ret;
}

int update_enclave_page_permissions(void* addr, size_t size, pal_prot_flags_t prot) {
    int ret;

    if (!size)
        return -PAL_ERROR_NOMEM;

    if (!access_ok(addr, size)
        || !IS_ALIGNED_PTR(addr, g_page_size)
        || !IS_ALIGNED(size, g_page_size)
        || addr < g_pal_linuxsgx_state.heap_min
        || addr + size > g_pal_linuxsgx_state.heap_max) {
        return -PAL_ERROR_INVAL;
    }

    pal_prot_flags_t req_prot = (PAL_PROT_READ | PAL_PROT_WRITE | PAL_PROT_EXEC) & prot;
    /* With EDMM an EPC page is allocated with RW permission and then the desired permission is
     * is set. Restrict permission from RW -> W is architecturally not permitted and the driver will
     * returns -EINVAL error. So adding READ permission if the page permission is only WRITE. */
    if (req_prot == PAL_PROT_WRITE) {
        req_prot = PAL_PROT_READ | PAL_PROT_WRITE;
    }

    log_debug("%s: addr = %p, size = 0x%lx, prot = 0x%x", __func__, addr, size, req_prot);
    spinlock_lock(&g_heap_vma_lock);
    print_vma_ranges();

    /* Retain original permissions for pre-allocated EPC pages */
    size_t non_overlapping_size = find_preallocated_heap_nonoverlap(addr, size);

    /* Entire request overlaps with preallocated heap, so simply return. */
    if (non_overlapping_size == 0) {
        goto out;
    }

    log_debug("%s: addr = %p, non_overlapping_size = 0x%lx, prot = 0x%x", __func__, addr,
               non_overlapping_size, req_prot);

    struct heap_vma* vma;
    struct heap_vma* p;

    bool vma_region_found = false;
    /* Find VMA associated with the request */
    LISTP_FOR_EACH_ENTRY_SAFE(vma, p, &g_heap_vma_list, list) {
        /* Since VMAs with same permissions are merged during allocation, request to change
         * permission should be within a single VMA region */
        if (addr >= vma->bottom && addr + non_overlapping_size <= vma->top) {
            vma_region_found = true;
            break;
        }
    }

    if (!vma_region_found) {
        log_error("VMA region addr = %p, size = 0x%lx not found!", addr, size);
        ret = -PAL_ERROR_INVAL;;
        goto release_lock;
    }

    pal_prot_flags_t vma_prot = vma->prot;
    if (req_prot == vma_prot) {
        log_error("%s: requested and vma perm are same, simply return!", __func__);
        goto out;
    }

    /* Check if the request encompasses the entire region. If not, split the VMA */
    if (vma->bottom < addr) {
        /* create new VMA [vma->bottom, addr) */
        struct heap_vma* new = __alloc_vma();
        if (!new) {
            log_error("Cannot split VMA during page permission update of address %p", addr);
            ret = -PAL_ERROR_NOMEM;
            goto release_lock;
        }
        new->top             = addr;
        new->bottom          = vma->bottom;
        new->prot            = vma->prot;
        new->is_pal_internal = vma->is_pal_internal;
        vma->bottom = addr;
        INIT_LIST_HEAD(new, list);
        LIST_ADD(new, vma, list);
    }

    if (vma->top > addr + non_overlapping_size) {
        /* create new VMA [addr + size, vma->top) */
        struct heap_vma* new = __alloc_vma();
        if (!new) {
            log_error("Cannot split VMA during page permission update of address %p",
                      addr + non_overlapping_size);
            ret = -PAL_ERROR_NOMEM;
            goto release_lock;
        }
        new->top             = vma->top;
        new->bottom          = addr + non_overlapping_size;
        new->prot            = vma->prot;
        new->is_pal_internal = vma->is_pal_internal;
        vma->top = addr + non_overlapping_size;
        struct heap_vma* vma_above = LISTP_PREV_ENTRY(vma, &g_heap_vma_list, list);
        INIT_LIST_HEAD(new, list);
        LISTP_ADD_AFTER(new, vma_above, &g_heap_vma_list, list);
    }

    /* Change permission for the entire VMA region. TODO: Split VMA? */
    size_t vma_size = vma->top - vma->bottom;
    void* vma_addr = vma->bottom;
    if ((req_prot & vma_prot) != vma_prot) {
        vma_prot = req_prot & vma_prot;
        ret = restrict_enclave_page_permission(vma_addr, vma_size, vma_prot);
        if (ret < 0)
            goto release_lock;
    }

    if (req_prot & ~vma_prot) {
        vma_prot = req_prot | vma_prot;
        ret = relax_enclave_page_permission(vma_addr, vma_size, vma_prot);
        if (ret < 0)
            goto release_lock;
    }

    vma->prot = req_prot;
out:
    ret = 0;
release_lock:
    log_debug("end %s: addr = %p, size = 0x%lx, prot = 0x%x", __func__, addr, size, prot);
    print_vma_ranges();
    spinlock_unlock(&g_heap_vma_lock);
    return ret;
}
