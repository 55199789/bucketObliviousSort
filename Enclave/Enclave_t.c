#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_ObliviousSort(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_ObliviousSort_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_ObliviousSort_t* ms = SGX_CAST(ms_ecall_ObliviousSort_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_cArr = ms->ms_cArr;



	ecall_ObliviousSort(_tmp_cArr, ms->ms_cnt);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_BucketObliviousSort(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_BucketObliviousSort_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_BucketObliviousSort_t* ms = SGX_CAST(ms_ecall_BucketObliviousSort_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_buf = ms->ms_buf;
	int* _tmp_cArr = ms->ms_cArr;



	ecall_BucketObliviousSort(_tmp_buf, _tmp_cArr, ms->ms_cnt);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecallEncryptArr(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecallEncryptArr_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecallEncryptArr_t* ms = SGX_CAST(ms_ecallEncryptArr_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_pSrc = ms->ms_pSrc;
	uint8_t* _tmp_pDst = ms->ms_pDst;



	ms->ms_retval = ecallEncryptArr(_tmp_pSrc, _tmp_pDst, ms->ms_cipher_len);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecallDecryptArr(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecallDecryptArr_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecallDecryptArr_t* ms = SGX_CAST(ms_ecallDecryptArr_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_pSrc = ms->ms_pSrc;
	uint8_t* _tmp_pDst = ms->ms_pDst;



	ms->ms_retval = ecallDecryptArr(_tmp_pSrc, _tmp_pDst, ms->ms_cipher_len);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_loop(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_loop_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_loop_t* ms = SGX_CAST(ms_ecall_loop_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_loop(ms->ms_tid);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_threads_down(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_threads_down();
	return status;
}

static sgx_status_t SGX_CDECL sgx_sl_init_switchless(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sl_init_switchless_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sl_init_switchless_t* ms = SGX_CAST(ms_sl_init_switchless_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_sl_data = ms->ms_sl_data;



	ms->ms_retval = sl_init_switchless(_tmp_sl_data);


	return status;
}

static sgx_status_t SGX_CDECL sgx_sl_run_switchless_tworker(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sl_run_switchless_tworker_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sl_run_switchless_tworker_t* ms = SGX_CAST(ms_sl_run_switchless_tworker_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = sl_run_switchless_tworker();


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[8];
} g_ecall_table = {
	8,
	{
		{(void*)(uintptr_t)sgx_ecall_ObliviousSort, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_BucketObliviousSort, 0, 0},
		{(void*)(uintptr_t)sgx_ecallEncryptArr, 0, 0},
		{(void*)(uintptr_t)sgx_ecallDecryptArr, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_loop, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_threads_down, 0, 0},
		{(void*)(uintptr_t)sgx_sl_init_switchless, 0, 0},
		{(void*)(uintptr_t)sgx_sl_run_switchless_tworker, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[6][8];
} g_dyn_entry_table = {
	6,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

