/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <math.h>
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <random>
#include <string.h>
#include <functional>
#include <queue>
#include <vector>
#include <thread>
#include <numeric>
#include <algorithm>
#include <chrono>
#include "sgx_eid.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_thread.h"
#include "sgx_tseal.h"
#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include "../App/threads_conf.h"
/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
sgx_aes_ctr_128bit_key_t* p_key = NULL;
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

// multi-threading
bool volatile is_exit = false;
std::atomic<bool> sync_flag_[THREAD_NUM];
std::function<void()> fun_ptrs[THREAD_NUM];


void task_notify(int threads) {
    for (int i = 1; i < threads; i++) {
        sync_flag_[i] = true;
    }
}

void ecall_loop(int tid) {

    while(true) {
        {
            while(sync_flag_[tid] == false);
            if (is_exit == true) 
                return;
            if (fun_ptrs[tid] == NULL)
                printf("[ecall_loop][%d][func is null]\n", tid);
            fun_ptrs[tid]();
            fun_ptrs[tid] = NULL;
            sync_flag_[tid] = false;
        }
    }
}

void task_wait_done(int threads) {
    for (int i = 1; i < threads; i++) {
        while(sync_flag_[i] == true);
    }
}


void ecall_threads_down() {
    is_exit = true;
    for (int i = 1; i < THREAD_NUM; i++)
        sync_flag_[i] = true;
}

sgx_status_t ecallEncryptArr(uint8_t* pSrc, uint8_t* pDst, const uint32_t cipher_len)
{
    sgx_status_t resp;
    if(p_key==NULL) 
    {
        const uint32_t len = sizeof(sgx_aes_ctr_128bit_key_t);
        p_key = (sgx_aes_ctr_128bit_key_t*)(new uint8_t[len]);
        resp = sgx_read_rand((uint8_t*)p_key, len);
        if (resp != SGX_SUCCESS)
            return resp;
    }

    uint8_t ctr[16]={0};
    resp = sgx_aes_ctr_encrypt(
        p_key,
        pSrc,
        cipher_len,
        ctr, 128,
        pDst);

    return resp;
}

sgx_status_t ecallDecryptArr(uint8_t* pSrc, uint8_t* pDst, uint32_t cipher_len)
{
    uint8_t ctr[16]={0};
    sgx_status_t resp = sgx_aes_ctr_decrypt(
        p_key,
        pSrc,
        cipher_len,
        ctr, 128,
        pDst);

    return resp;
}

template<typename Key>
static void bitonicMerge(Key a[], int low, int cnt, bool dir) 
{
    if (cnt>1) 
    {
        int k = 1;
        while(k<cnt) k<<=1;
        k>>=1;
        for (int i=low; i<low+cnt-k; i++)
            if(dir==(a[i]>a[i+k]))
                std::swap(a[i], a[i+k]);
        bitonicMerge<Key>(a, low, k, dir);
        bitonicMerge<Key>(a, low+k, cnt-k, dir);
    }
}

template<typename Key>
void bitonicSort(Key *arr, uint32_t low, uint32_t cnt, bool dir)
{
    if (cnt>1)
    {
        int k = cnt/2;
        bitonicSort<Key>(arr, low, k, !dir);
        bitonicSort<Key>(arr, low+k, cnt - k, dir);
        bitonicMerge<Key>(arr, low, cnt, dir);
    }
}

template<typename Key>
void bitonicSortNonRecursive(Key *arr, uint32_t cnt)
{
    // cnt must be a power of 2
    for(uint32_t k=2;k<=cnt;k<<=1)
        for(uint32_t j=k>>1;j>0;j>>=1) 
            for(uint32_t i=0;i<cnt;i++)
            {
                uint32_t l = i^j; 
                if(l>i)
                    if((i&k)==0 && arr[i]>arr[l] ||
                    (i&k)!=0 && arr[i]<arr[l])
                    std::swap(arr[i], arr[j]);
            }
}

template<typename Key>
void bitonicSortParallel(Key *arr, uint32_t cnt, const uint32_t maxThreadNum = THREAD_NUM)
{
    uint32_t threadNum = 1;
    uint32_t lvl = 0;
    while(threadNum<=maxThreadNum) 
    {
        threadNum<<=1;
        lvl++;
    }
    threadNum>>=1;
    if(threadNum==1)
    {
        bitonicSort<Key>(arr, 0, cnt, 1); 
        return;
    }
    // bitonicSort each interval
    uint32_t st[threadNum];
    uint32_t actualCnt[threadNum];
    bool actualDir[threadNum];

    actualDir[0] = lvl&1;
    for(int tid=0;tid<threadNum-1;tid++)
    {
        for(int i = 0;i<(1<<tid);i++)
            actualDir[i+(1<<tid)]=!actualDir[i];
    }

    int subcnt = cnt/threadNum;
    for(int tid=0;tid<threadNum;tid++) 
    {
        st[tid] = subcnt*tid;
        actualCnt[tid] = subcnt<(cnt-st[tid])?subcnt:(cnt-st[tid]);
        fun_ptrs[tid] = [tid, arr, &st, &actualCnt, &actualDir](){
            bitonicSort<Key>(arr, st[tid], actualCnt[tid], actualDir[tid]);
        };
    }
    task_notify(threadNum);
    fun_ptrs[0]();
    task_wait_done(threadNum);

    threadNum>>=1;
    while(threadNum)
    {
        for(int tid=0;tid<threadNum;tid++) 
        {
            st[tid] = st[tid*2];
            actualCnt[tid] = actualCnt[tid*2] + actualCnt[tid*2+1];
            actualDir[tid] = !actualDir[tid*2];
        }
        // merge two intervals
        for(int tid=0;tid<threadNum;tid++) 
        {
            fun_ptrs[tid] = [tid, arr, &st, &actualCnt, &actualDir](){
                bitonicMerge<Key>(arr, st[tid], actualCnt[tid], actualDir[tid]);
            };
        }
        task_notify(threadNum);
        fun_ptrs[0]();
        task_wait_done(threadNum);

        threadNum>>=1;
    }
}

template<class T>
struct SortBall
{
    uint32_t key;
    T   val;
};

template<class Key> 
sgx_status_t bucketObliviousSortInit(SortBall<Key> *currArr, Key *arr, uint32_t cnt, uint32_t Z, 
                        uint32_t B, const uint32_t maxThreadNum)
{
    uint8_t ctr[16]={0};
    Key *plainText = new Key[Z];
    const uint32_t groupSize = uint32_t(ceil((ceil(1.0*cnt/B)*sizeof(Key))/16) * 16)/sizeof(Key);
    uint32_t num = 0;
    uint32_t groups = 0;
    SortBall<Key> *curGroup = new SortBall<Key>[Z];
    uint32_t dest = B;
    sgx_status_t ret = SGX_SUCCESS;

    std::random_device dev;
    std::mt19937 rng(dev());
    std::uniform_int_distribution<std::mt19937::result_type> dist6(0, B-1);
    
    for(uint32_t i = 0;i<cnt;i+=groupSize) 
    {
        groups++;
        num = std::min(groupSize, cnt-i);
        ret = sgx_aes_ctr_decrypt(p_key, (uint8_t *)arr, num*sizeof(Key), ctr, 128, (uint8_t *)plainText);
        if(ret != SGX_SUCCESS)
            goto RET;
        arr+=num;

        for(uint32_t j=0;j<num;++j) 
        {
            // ret = sgx_read_rand((uint8_t*)&dest, sizeof(uint32_t));
            // if(ret != SGX_SUCCESS)
            //     goto RET;
            dest = dist6(rng);
            curGroup[j].key = dest%B;
            curGroup[j].val = plainText[j];
        }

        // Padding with dummy
        for(uint32_t j=num;j<Z;++j)
        {
            curGroup[j].key = B*2-1;
            // memset(&curGroup[j].val, -1, sizeof(Key));
        }

        uint8_t groupCtr[16]={0};
        ret = sgx_aes_ctr_encrypt(p_key, (uint8_t *)curGroup, Z*sizeof(SortBall<Key>), 
                            groupCtr, 128, (uint8_t *)currArr);
        if(ret != SGX_SUCCESS)
            goto RET;
        currArr+=Z;
    }

    for(uint32_t i=groups;i<B;++i) 
    {
        for(uint32_t j=0;j<Z;++j)
        {
            curGroup[j].key = B*2-1;
            // memset(&curGroup[i].val, -1, sizeof(Key));
        }
        uint8_t groupCtr[16]={0};
        ret = sgx_aes_ctr_encrypt(p_key, (uint8_t *)curGroup, Z*sizeof(SortBall<Key>), 
                            groupCtr, 128, (uint8_t *)currArr);
        if(ret != SGX_SUCCESS)
            goto RET;
        currArr+=Z;
    }
RET:
    delete[] plainText;
    delete[] curGroup;
    return ret;
}

template<class T>
sgx_status_t mergeSplit(SortBall<T> *nextLeft, SortBall<T> *nextRight, 
                SortBall<T> *curLeft, SortBall<T> *curRight, 
                SortBall<T> *secureBuf,
                uint32_t Z, uint32_t logB, uint32_t I)
{
    const uint32_t binSize = sizeof(SortBall<T>)*Z;
    uint8_t ctr[16]={0};
    memset(ctr, I, sizeof(ctr));
    sgx_aes_ctr_decrypt(p_key, (uint8_t *)curLeft, binSize, 
                        ctr, 128, (uint8_t *)secureBuf);

    memset(ctr, I, sizeof(ctr));
    sgx_aes_ctr_decrypt(p_key, (uint8_t *)curRight, binSize, 
                        ctr, 128, (uint8_t *)(secureBuf+Z));

    Z<<=1; 
    const uint32_t dummy = (1<<(logB+1))-1;
    const uint32_t MSB=logB-I-1;
    for(uint32_t k=2;k<=Z;k<<=1)
        for(uint32_t j=k>>1;j>0;j>>=1) 
            for(uint32_t i=0;i<Z;i++)
            {
                const uint32_t l = i^j; 
                if(l>i){
                    bool arri=(secureBuf[i].key>>MSB)&1;
                    bool arrl=(secureBuf[l].key>>MSB)&1;
                    if(secureBuf[i].key == dummy)   
                    {
                        arri = 1;
                        arrl = 0;
                    }
                    else if(secureBuf[l].key == dummy)
                    {
                        arrl = 1;
                        arri = 0;
                    }
                    if((i&k)==0 && arri>arrl ||
                       (i&k)!=0 && arri<arrl)
                        std::swap(secureBuf[i], secureBuf[l]);
                }
            }
    for(uint32_t i=0;i<Z;++i)
        if(((secureBuf[i].key>>MSB)&1)!=0) 
        {
            if(i>Z/2)
                return SGX_ERROR_INVALID_MISC;
            else if(i==Z/2) break;
            const uint32_t offset = Z/2 - i;
            if(secureBuf[Z-offset].key!=dummy)
                return SGX_ERROR_INVALID_MISC;
            for(uint32_t j=Z-offset;j<Z;++j)
                std::swap(secureBuf[j], secureBuf[i+j-Z+offset]);
            break;
        }
    Z>>=1;

    memset(ctr, I+1, sizeof(ctr));
    sgx_aes_ctr_encrypt(p_key, (uint8_t *)secureBuf, binSize, 
                        ctr, 128, (uint8_t *)nextLeft);

    memset(ctr, I+1, sizeof(ctr));
    sgx_aes_ctr_encrypt(p_key, (uint8_t *)(secureBuf+Z), binSize, 
                        ctr, 128, (uint8_t *)nextRight);
    return SGX_SUCCESS;
}

template<class Key>
void kMergeSort(Key *cArr, Key *buffer, uint32_t cnt) 
{
    if(cnt*sizeof(Key)<(80<<20))
    {
        Key *sortBuf=new Key[cnt];

        uint8_t ctr[16]={0};
        sgx_aes_ctr_decrypt(p_key, (uint8_t *)cArr, cnt*sizeof(Key), ctr, 128, (uint8_t *)sortBuf);

        std::sort(sortBuf, sortBuf+cnt);

        memset(ctr,0,sizeof(ctr));
        sgx_aes_ctr_encrypt(p_key, (uint8_t *)sortBuf, cnt*sizeof(Key), ctr, 128, (uint8_t *)cArr);

        delete[] sortBuf;
        return;   
    }
// External sort part has bugs
    const uint32_t enclaveSize = (76<<20);
    uint32_t batchSize = enclaveSize/sizeof(Key);
    Key *sortBuf = new Key[batchSize];
    uint8_t deCtr[16]={0};
    std::vector<std::vector<uint8_t> > deKCtr;
    uint8_t enCtr[16]={0};
    Key *cArr_ = cArr;
    Key *buffer_ = buffer;
    uint32_t k = 0;
    std::vector<Key *> kP;
    std::vector<uint32_t> nums;
    for(uint32_t st = 0; st<cnt; st+=batchSize)
    {
        k++;
        uint32_t num = std::min(batchSize, cnt-st);
        nums.push_back(num);
        deKCtr.push_back(std::vector<uint8_t>(deCtr, deCtr+16));
        sgx_aes_ctr_decrypt(p_key, (uint8_t *)cArr, num*sizeof(Key), deCtr, 128, (uint8_t *)sortBuf);
        cArr+=num;

        std::sort(sortBuf, sortBuf+num);

        kP.push_back(buffer);
        sgx_aes_ctr_encrypt(p_key, (uint8_t *)sortBuf, num*sizeof(Key), enCtr, 128, (uint8_t *)buffer);
        buffer+=num;
    }
    delete[] sortBuf;
#ifdef __cpp_lib_gcd_lcm
    const uint32_t pBufferSize = std::lcm(16, sizeof(Key));
#else 
    const uint32_t pBufferSize = 16*sizeof(Key);
#endif 
    const uint32_t deNum = pBufferSize / sizeof(Key);
    // batchSize = (enclaveSize/sizeof(Key))/(k+1);
    // sortBuf = new Key[k*batchSize];
    // uint32_t heapSize = batchSize + (enclaveSize/sizeof(Key))%(k+1);
    uint32_t heapSize = batchSize;
    std::priority_queue<Key, std::vector<Key>, std::greater<Key>> que;
    Key* pBuffer = new Key[deNum];
    Key* deBuffer = new Key[k * deNum];
    uint32_t idx = 0;
    memset(enCtr, 0, sizeof(enCtr));
    while(k)
    {
        for(uint32_t i = 0; i<nums.size(); i++)
            if(nums[i]>0)
            {
                uint32_t num = std::min(nums[i], uint32_t(nums.size()*deNum));
                nums[i] -= num;
                if(nums[i]==0) --k;
                sgx_aes_ctr_decrypt(p_key, (uint8_t *)(kP[i]), num*sizeof(Key), (uint8_t *)deKCtr[i].data(), 128, (uint8_t *)deBuffer);
                kP[i] += num;
                for(uint32_t j = 0; j<num;j++)
                    que.push(deBuffer[j]);
            }
        for(uint32_t i=0;i<deNum;i++)
        {
            if(que.empty())break;
            pBuffer[idx++] = que.top(); que.pop();
            if(idx == deNum)
            {
                sgx_aes_ctr_encrypt(p_key, (uint8_t *)pBuffer, idx*sizeof(Key), enCtr, 128, (uint8_t *)cArr_);
                cArr_+=idx;
                idx = 0;
            }
        }
    }
    while(!que.empty()) 
    {
        pBuffer[idx++] = que.top(); que.pop();
        if(idx == deNum)
        {
            sgx_aes_ctr_encrypt(p_key, (uint8_t *)pBuffer, idx*sizeof(Key), enCtr, 128, (uint8_t *)cArr_);
            cArr_+=idx;
            idx = 0;
        }
    }
    sgx_aes_ctr_encrypt(p_key, (uint8_t *)pBuffer, idx*sizeof(Key), enCtr, 128, (uint8_t *)cArr_);
    cArr_+=idx;
    delete[] pBuffer;
    delete[] deBuffer;
}

template<class Key>
sgx_status_t bucketFinalSort(SortBall<Key> *secureBuf, SortBall<Key> *arr, Key *cArr, uint8_t *buffer, uint32_t cnt, 
                            uint32_t B, uint32_t Z, uint32_t logB, 
                            const uint32_t maxThreadNum)
{
    // Retrive actual keys
    const uint32_t binSize = sizeof(SortBall<Key>)*Z;
    Key *plaintext = new Key[Z];
    uint32_t idx = 0;

    uint8_t deCtr[16]={0};
    uint8_t enCtr[16]={0};
    Key *cArr_ = cArr;
    for(uint32_t i=0;i<B;++i) 
    {
        memset(deCtr, logB, sizeof(deCtr));
        sgx_status_t ret = sgx_aes_ctr_decrypt(p_key, (uint8_t *)arr, binSize, deCtr, 128, (uint8_t *)secureBuf);
        if(ret != SGX_SUCCESS)
            return ret;
        for(uint32_t j=0;j<Z;++j) 
            if(secureBuf[j].key!=(2*B-1))
            {
                plaintext[idx++] = secureBuf[j].val;
                if(idx==Z)
                {
                    sgx_aes_ctr_encrypt(p_key, (uint8_t *)plaintext, idx*sizeof(Key), enCtr, 128, (uint8_t *)cArr);
                    cArr+=Z;
                    idx = 0;
                }
            }
        arr+=Z;
    }
    sgx_aes_ctr_encrypt(p_key, (uint8_t *)plaintext, idx*sizeof(Key), enCtr, 128, (uint8_t *)cArr);
    delete[] plaintext; 

    kMergeSort<Key>(cArr_, (Key *)buffer, cnt);

    return SGX_SUCCESS;
}

template<class Key>
void bucketObliviousSort(uint8_t *buffer, Key *arr, uint32_t cnt, 
                        const uint32_t maxThreadNum = THREAD_NUM)
{
    static const uint32_t Z = 512;
    uint32_t B = 1;
    uint32_t logB = 0;
    while(B<2*cnt/Z) 
    {
        B<<=1;
        ++logB;
    }
    assert((1<<logB)==B);
    SortBall<Key> *currArr = (SortBall<Key> *)buffer; 
    SortBall<Key> *nextArr = currArr+B*Z;

    SortBall<Key> *secureBuf = new SortBall<Key>[2*Z];

    // Oblivious Random Permutation
    sgx_status_t ret = bucketObliviousSortInit<Key>(currArr, arr, cnt, Z, B, maxThreadNum);
    if(ret!=SGX_SUCCESS)
        return;
    for(uint32_t i = 0;i<logB;++i) 
    {
        for(uint32_t j = 0;j<B/2;++j)
        {
            uint32_t j_ = ((j>>i)<<(i+1))+(j%(1<<i));
            SortBall<Key> *nextLeft = nextArr+(j<<1)*Z;
            SortBall<Key> *nextRight = nextLeft + Z;
            SortBall<Key> *curLeft = currArr+(j_)*Z;
            SortBall<Key> *curRight = curLeft + (1<<i)*Z;
            ret = mergeSplit<Key>(nextLeft, nextRight, curLeft, curRight, secureBuf, Z, logB, i);
            if(ret!=SGX_SUCCESS)
                return;
        }
        std::swap(currArr, nextArr);
    }
    
    bucketFinalSort<Key>(secureBuf, currArr, arr, buffer, cnt, B, Z, logB, maxThreadNum);
    delete[] secureBuf;
}

void ecall_BucketObliviousSort(uint8_t *buffer, int cArr[], uint32_t cnt) 
{
    bucketObliviousSort<int>(buffer, cArr, cnt);
}

void ecall_ObliviousSort(int cArr[], uint32_t cnt) 
{
    int *buf = new int[cnt];
    ecallDecryptArr((uint8_t *)cArr, (uint8_t *)buf, cnt*sizeof(int));
    bitonicSortParallel<int>(buf, cnt);
    ecallEncryptArr((uint8_t*)buf, (uint8_t*)cArr, cnt*sizeof(int));
    delete[] buf;
}
