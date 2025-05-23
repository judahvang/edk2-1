/*************************************************************************
* Copyright (C) 2023 Intel Corporation
*
* Licensed under the Apache License,  Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* 	http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law  or agreed  to  in  writing,  software
* distributed under  the License  is  distributed  on  an  "AS IS"  BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the  specific  language  governing  permissions  and
* limitations under the License.
*************************************************************************/

#ifndef IPPCP_FIPS_CERT_COMMON_H
#define IPPCP_FIPS_CERT_COMMON_H

#include "ippcpdefs.h"
#include "pcpbnuimpl.h"

#define IPPCP_AES_MSG_BYTE_LEN       (64)
#define IPPCP_AES_KEY128_BYTE_LEN    (16)
#define IPPCP_AES_KEY256_BYTE_LEN    (32)

#define IPPCP_IV128_BYTE_LEN         (16)

#define IPPCP_AES_ALIGNMENT  ((int)sizeof(void *))
#define IPPCP_HASH_ALIGNMENT ((int)sizeof(void *))
#define IPPCP_HMAC_ALIGNMENT ((int)sizeof(void *))
#define IPPCP_GFP_ALIGNMENT  ((int)sizeof(void *))
#define IPPCP_BN_ALIGNMENT   ((int)sizeof(void*))
#define IPPCP_RSA_ALIGNMENT  ((int)sizeof(BNU_CHUNK_T))

// convert bitsize into 32-bit wordsize
#define IPPCP_BITSIZE_2_WORDSIZE(N_BITS)   (((N_BITS) + 31) >> 5)
#define IPPCP_BYTESIZE_2_BITSIZE(N_BYTES)  ((N_BYTES) * 8)
#define IPPCP_BYTESIZE_2_WORDSIZE(N_BYTES) (((N_BYTES) + 3) >> 2)

// Feature of internal memory management
#ifdef IPPCP_SELFTEST_USE_MALLOC
    #include <stdlib.h>

    // Internal memory management - free resource
    #define MEMORY_FREE(pBuffer, memMgmFlag)  if(1 == internalMemMgm) {  \
                                                free((void*)pBuffer);    \
                                                pBuffer = NULL;          \
                                              }
    // If buffer is NULL, allocate memory
    #define BUF_CHECK_NULL_AND_ALLOC(pBuffer, memMgmFlag, size, ret_sts)         \
                                        if(NULL == pBuffer) {                    \
                                            IPP_BADARG_RET((0 == size), ret_sts) \
                                            memMgmFlag = 1;                      \
                                            pBuffer = malloc((size_t)size);      \
                                        }                  
#else
    // No memory management inside the test
    #define MEMORY_FREE(pBuffer, memMgmFlag)    (void)internalMemMgm;
    // Return bad sts if buffer is NULL - we cannot allocate memory
    // IPPCP_SELFTEST_USE_MALLOC is not defined)
    #define BUF_CHECK_NULL_AND_ALLOC(pBuffer, memMgmFlag, size, ret_sts)           \
                                        (void)internalMemMgm;                      \
                                        IPP_BADARG_RET((NULL == pBuffer), ret_sts);

#endif

#define MEMORY_FREE_2(pBuffer1, pBuffer2, memMgmFlag)       \
                        { MEMORY_FREE(pBuffer1, memMgmFlag) \
                          MEMORY_FREE(pBuffer2, memMgmFlag) }            
#define MEMORY_FREE_3(pBuffer1, pBuffer2, pBuffer3, memMgmFlag) \
                         { MEMORY_FREE(pBuffer1, memMgmFlag)    \
                           MEMORY_FREE(pBuffer2, memMgmFlag)    \
                           MEMORY_FREE(pBuffer3, memMgmFlag) }   

/**
 * \brief
 *
 *  Comparison of two byte arrays.
 *
 *  Compares byte arrays, returns 1 if arrays are equal, 0 otherwise.
 *
 *  NOTE: This function should not be used for a secure memory comparison (i.e. constant time).
 *
 * \param[in] p1 pointer to first byte array
 * \param[in] p1_byte_len length of first array in bytes
 * \param[in] p2 pointer to second byte array
 * \param[in] p2_byte_len length of second array in bytes
 *
 */
#define ippcp_is_mem_eq OWNAPI(ippcp_is_mem_eq)
    IPP_OWN_DECL (int, ippcp_is_mem_eq, (const Ipp8u *p1, Ipp32u p1_byte_len, const Ipp8u *p2, Ipp32u p2_byte_len))

#endif // IPPCP_FIPS_CERT_COMMON_H
