#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_ObliviousSort_t {
	int* ms_cArr;
	uint32_t ms_cnt;
} ms_ecall_ObliviousSort_t;

typedef struct ms_ecall_BucketObliviousSort_t {
	uint8_t* ms_buf;
	int* ms_cArr;
	uint32_t ms_cnt;
} ms_ecall_BucketObliviousSort_t;

typedef struct ms_ecallEncryptArr_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pSrc;
	uint8_t* ms_pDst;
	uint32_t ms_cipher_len;
} ms_ecallEncryptArr_t;

typedef struct ms_ecallDecryptArr_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pSrc;
	uint8_t* ms_pDst;
	uint32_t ms_cipher_len;
} ms_ecallDecryptArr_t;

typedef struct ms_ecall_loop_t {
	int ms_tid;
} ms_ecall_loop_t;

typedef struct ms_sl_init_switchless_t {
	sgx_status_t ms_retval;
	void* ms_sl_data;
} ms_sl_init_switchless_t;

typedef struct ms_sl_run_switchless_tworker_t {
	sgx_status_t ms_retval;
} ms_sl_run_switchless_tworker_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[6];
} ocall_table_Enclave = {
	6,
	{
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_ObliviousSort(sgx_enclave_id_t eid, int* cArr, uint32_t cnt)
{
	sgx_status_t status;
	ms_ecall_ObliviousSort_t ms;
	ms.ms_cArr = cArr;
	ms.ms_cnt = cnt;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_BucketObliviousSort(sgx_enclave_id_t eid, uint8_t* buf, int* cArr, uint32_t cnt)
{
	sgx_status_t status;
	ms_ecall_BucketObliviousSort_t ms;
	ms.ms_buf = buf;
	ms.ms_cArr = cArr;
	ms.ms_cnt = cnt;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecallEncryptArr(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* pSrc, uint8_t* pDst, uint32_t cipher_len)
{
	sgx_status_t status;
	ms_ecallEncryptArr_t ms;
	ms.ms_pSrc = pSrc;
	ms.ms_pDst = pDst;
	ms.ms_cipher_len = cipher_len;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecallDecryptArr(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* pSrc, uint8_t* pDst, uint32_t cipher_len)
{
	sgx_status_t status;
	ms_ecallDecryptArr_t ms;
	ms.ms_pSrc = pSrc;
	ms.ms_pDst = pDst;
	ms.ms_cipher_len = cipher_len;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_loop(sgx_enclave_id_t eid, int tid)
{
	sgx_status_t status;
	ms_ecall_loop_t ms;
	ms.ms_tid = tid;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_threads_down(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t sl_init_switchless(sgx_enclave_id_t eid, sgx_status_t* retval, void* sl_data)
{
	sgx_status_t status;
	ms_sl_init_switchless_t ms;
	ms.ms_sl_data = sl_data;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sl_run_switchless_tworker(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_sl_run_switchless_tworker_t ms;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

