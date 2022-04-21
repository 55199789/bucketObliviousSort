# bucketObliviousSort
Intel SGX based bucket oblivious sort

This is my own implementation of bucket oblivious sort where the enclave is the client and runs a small bitonic sort. However, it is much slower than the bitonic sort with O(1) client size, since the enclave is not oblivious. 

In addition, the bitonic sort does not support sorting the array larger than 80MB.