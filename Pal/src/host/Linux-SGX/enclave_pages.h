#include <stdbool.h>
#include <stddef.h>

#include "pal.h"

void* get_enclave_pages(void* addr, size_t size, pal_prot_flags_t prot, bool is_pal_internal);
int update_enclave_page_permissions(void* addr, size_t size, pal_prot_flags_t prot);
int free_enclave_pages(void* addr, size_t size);
