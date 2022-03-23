#include "enclave_pages.h"

#include <asm/errno.h>
#include <stdalign.h>

#include "api.h"
#include "asan.h"
#include "list.h"
#include "pal_error.h"
#include "pal_linux.h"
#include "spinlock.h"

/* heap_vma objects are taken from pre-allocated pool to avoid recursive mallocs */
#define MAX_HEAP_VMAS 100000
/* TODO: Setting this as 64 to start with, but will need to revisit */
#define EDMM_HEAP_RANGE_CNT 32

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

struct edmm_heap_vma {
    void* addr;
    size_t size;
    uint32_t prot; /* current prot for this vma region (not requested) */
};

struct edmm_heap_request {
    uint32_t range_cnt;
    struct edmm_heap_vma vma_range[EDMM_HEAP_RANGE_CNT];
};

static LISTP_TYPE(heap_vma) g_heap_vma_list = LISTP_INIT;
static spinlock_t g_heap_vma_lock = INIT_SPINLOCK_UNLOCKED;
static struct heap_vma g_heap_vma_pool[MAX_HEAP_VMAS];
static size_t g_heap_vma_num = 0;
static struct heap_vma* g_free_vma = NULL;

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

/* Returns size that is non overlapping with the pre-allocated heap when preheat option is turned on.
 * 0 means entire request overlaps with the pre-allocated region. */
static size_t find_preallocated_heap_nonoverlap(void* addr, size_t size) {
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

static void edmm_update_heap_request(void* addr, size_t size, pal_prot_flags_t prot,
                                struct edmm_heap_request* heap_req) {
    assert(heap_req->range_cnt < EDMM_HEAP_RANGE_CNT);

    int range_cnt = heap_req->range_cnt;
    heap_req->vma_range[range_cnt].addr = addr;
    heap_req->vma_range[range_cnt].size = size;
    heap_req->vma_range[range_cnt].prot = prot;
    heap_req->range_cnt += 1;
}

static int relax_enclave_page_permission(void* addr, size_t size, pal_prot_flags_t prot) {
    void* start = addr;
    void* end = (void*)((char*)start + size);

    alignas(64) sgx_arch_sec_info_t secinfo_relax;
    memset(&secinfo_relax, 0, sizeof(secinfo_relax));

    secinfo_relax.flags |= (prot & PAL_PROT_READ) ? SGX_SECINFO_FLAGS_R : 0;
    secinfo_relax.flags |= (prot & PAL_PROT_WRITE) ? SGX_SECINFO_FLAGS_W : 0;
    secinfo_relax.flags |= (prot & PAL_PROT_EXEC) ? SGX_SECINFO_FLAGS_X : 0;

    while (start < end) {
       sgx_modpe(&secinfo_relax, start);
       start = (void*)((char*)start + g_pal_public_state.alloc_align);
    }

    return 0;
}

static int restrict_enclave_page_permission(void* addr, size_t size, pal_prot_flags_t prot) {
    void* start = addr;
    void* end = (void*)((char*)start + size);

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

    return 0;
}

/* This function trims EPC pages on enclave's request. The sequence is as below:
 * 1. Enclave calls SGX driver IOCTL to change the page's type to PT_TRIM.
 * 2. Driver invokes ETRACK to track page's address on all CPUs and issues IPI to flush stale TLB
 * entries.
 * 3. Enclave issues an EACCEPT to accept changes to each EPC page.
 * 4. Enclave notifies the driver to remove EPC pages (using an IOCTL).
 * 5. Driver issues EREMOVE to complete the request. */
static int free_edmm_page_range(void* start, size_t size) {
    void* addr = ALLOC_ALIGN_DOWN_PTR(start);
    void* end = (void*)((char*)addr + size);
    int ret = 0;

    size_t non_overlapping_size = find_preallocated_heap_nonoverlap(addr, size);

    /* Entire request overlaps with preallocated heap, so simply return. */
    if (non_overlapping_size == 0) {
        return 0;
    } else {
        size = non_overlapping_size;
    }

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
static int get_edmm_page_range(void* start_addr, size_t size) {
    alignas(64) sgx_arch_sec_info_t secinfo;
    secinfo.flags = SGX_SECINFO_FLAGS_R | SGX_SECINFO_FLAGS_W | SGX_SECINFO_FLAGS_REG |
                    SGX_SECINFO_FLAGS_PENDING;
    memset(&secinfo.reserved, 0, sizeof(secinfo.reserved));

    void* lo = start_addr;
    void* addr = (void*)((char*)lo + size);

    while (lo < addr) {
        addr = (void*)((char*)addr - g_pal_public_state.alloc_align);

        int ret = sgx_accept(&secinfo, addr);
        if (ret) {
            log_error("EDMM accept page failed: %p %d\n", addr, ret);
            return -EFAULT;
        }
    }

    return 0;
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
    int alloc_count = 0, perm_count = 0;

    if (!size)
        return NULL;

    size = ALIGN_UP(size, g_page_size);
    addr = ALIGN_DOWN_PTR(addr, g_page_size);

    assert(access_ok(addr, size));
    struct heap_vma* vma_above = NULL;
    struct heap_vma* vma;
    pal_prot_flags_t req_prot = (PAL_PROT_READ | PAL_PROT_WRITE | PAL_PROT_EXEC) & prot;

    spinlock_lock(&g_heap_vma_lock);

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
            alloc_count++;
            void* alloc_addr = heap_alloc.vma_range[i].addr;
            size_t alloc_size = heap_alloc.vma_range[i].size;
            uint32_t vma_prot = heap_alloc.vma_range[i].prot;

            /* check if the requested region falls within pre-allocated region */
            size_t non_overlapping_size = find_preallocated_heap_nonoverlap(alloc_addr, alloc_size);
            log_debug("%s: preallocated heap addr = %p, org_size = %lx, updated_size=%lx\n", __func__,
                       alloc_addr, alloc_size, non_overlapping_size);
            /* Entire request overlaps with preallocated heap, so update the permissions */
            if (non_overlapping_size == 0) {
                /* pre-allocated heap regions have `R | W | X` */
                //vma_prot = vma_prot | PAL_PROT_EXEC;
                continue;
            }

            int retval = get_edmm_page_range(alloc_addr, non_overlapping_size);
            if (retval < 0) {
                ret = NULL;
                goto release_lock;
            }
            alloc_size = non_overlapping_size;

            /* Due SGX2 architectural requirement the driver sets default page permission to R | W.
             * So, if the requested permissions is  R | W then we  skip it. */
            if (req_prot != vma_prot) {
                edmm_update_heap_request(alloc_addr, alloc_size, vma_prot, &heap_perm);
            }
        }

        /* Update page permissions */
        for (uint32_t i = 0; i < heap_perm.range_cnt; i++) {
            perm_count++;
            void* vma_addr = heap_perm.vma_range[i].addr;
            size_t vma_size = heap_perm.vma_range[i].size;
            pal_prot_flags_t vma_prot = heap_perm.vma_range[i].prot;

            if ((req_prot & vma_prot) != vma_prot) {
                int retval = restrict_enclave_page_permission(vma_addr, vma_size,
                                                              req_prot & vma_prot);
                if (retval < 0) {
                    ret = NULL;
                    goto release_lock;
                }
                vma_prot = req_prot & vma_prot;
            }

            if (req_prot & ~vma_prot) {
                int retval = relax_enclave_page_permission(vma_addr, vma_size, req_prot | vma_prot);
                if (retval < 0) {
                    ret = NULL;
                    goto release_lock;
                }
            }
        }
    }

release_lock:
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

    log_debug("%s: end edmm alloc addr = %p, size = 0x%lx. alloc_cnt = %d, perm_cnt =%d\n",
               __func__, ret, size, alloc_count, perm_count);
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

    spinlock_lock(&g_heap_vma_lock);

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
                free_heap_top == heap_free.vma_range[heap_free.range_cnt - 1].addr) {
                heap_free.vma_range[heap_free.range_cnt - 1].addr = free_heap_bottom;
                heap_free.vma_range[heap_free.range_cnt - 1].size += range;
            } else {
                assert(heap_free.range_cnt < EDMM_HEAP_RANGE_CNT);
                /* found a new non-contiguous range */
                heap_free.vma_range[heap_free.range_cnt].addr = free_heap_bottom;
                heap_free.vma_range[heap_free.range_cnt].size = range;
                heap_free.range_cnt++;
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
            ret = free_edmm_page_range(heap_free.vma_range[i].addr, heap_free.vma_range[i].size);
            if (ret < 0) {
                ret = -PAL_ERROR_INVAL;
                break;
            }
        }
    }
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
    spinlock_lock(&g_heap_vma_lock);

    struct heap_vma* vma;
    struct heap_vma* p;


    bool vma_region_found = false;
    /* Find VMA associated with the request */
    LISTP_FOR_EACH_ENTRY_SAFE(vma, p, &g_heap_vma_list, list) {
        /* Since VMAs with same permissions are merged during allocation, request to change
         * permission should be within a single VMA region */
        if (addr >= vma->bottom && addr + size <= vma->top) {
            vma_region_found = true;
            break;
        }
    }

    if (!vma_region_found) {
        ret = -PAL_ERROR_INVAL;
        goto release_lock;
    }

    pal_prot_flags_t vma_prot = vma->prot;
    if (req_prot == vma_prot) {
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

    if (vma->top > addr + size) {
        /* create new VMA [addr + size, vma->top) */
        struct heap_vma* new = __alloc_vma();
        if (!new) {
            log_error("Cannot split VMA during page permission update of address %p", addr + size);
            ret = -PAL_ERROR_NOMEM;
            goto release_lock;
        }
        new->top             = vma->top;
        new->bottom          = addr + size;
        new->prot            = vma->prot;
        new->is_pal_internal = vma->is_pal_internal;
        vma->top = addr + size;
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
    spinlock_unlock(&g_heap_vma_lock);
    log_debug("%s: End update permissions: start_addr = %p, size = 0x%lx, prot = 0x%x\n",
              __func__, addr, size, prot);
    return ret;
}
