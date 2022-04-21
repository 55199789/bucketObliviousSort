#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_ObliviousSort(int* cArr, uint32_t cnt);
void ecall_BucketObliviousSort(uint8_t* buf, int* cArr, uint32_t cnt);
sgx_status_t ecallEncryptArr(uint8_t* pSrc, uint8_t* pDst, uint32_t cipher_len);
sgx_status_t ecallDecryptArr(uint8_t* pSrc, uint8_t* pDst, uint32_t cipher_len);
void ecall_loop(int tid);
void ecall_threads_down(void);
sgx_status_t sl_init_switchless(void* sl_data);
sgx_status_t sl_run_switchless_tworker(void);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
