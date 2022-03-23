#ifndef SGX_ENCLAVE_H
#define SGX_ENCLAVE_H

#include <stddef.h>

#include "sgx_arch.h"
#include "pal_topology.h"

/* SGX manifest options */
struct pal_sgx_manifest_config {
    bool edmm_enable_heap;
    uint64_t preheat_enclave_size;
};

int ecall_enclave_start(char* libpal_uri, char* args, size_t args_size, char* env, size_t env_size,
                        int parent_stream_fd, sgx_target_info_t* qe_targetinfo,
                        struct pal_topo_info* topo_info,
                        struct pal_sgx_manifest_config* manifest_keys);

int ecall_thread_start(void);

int ecall_thread_reset(void);

#endif /* SGX_ENCLAVE_H */
