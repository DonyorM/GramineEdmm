#include <stdbool.h>
#include <stddef.h>

#include "pal.h"

void* get_enclave_pages(void* addr, size_t size, pal_prot_flags_t prot, bool is_pal_internal);
int update_enclave_page_permissions(void* addr, size_t size, pal_prot_flags_t prot);
int free_enclave_pages(void* addr, size_t size);
pal_alloc_flags_t get_page_perms(void* addr);
int set_prot_for_new_page(void* addr);
