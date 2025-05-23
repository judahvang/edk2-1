/*
 * // INTEL CONFIDENTIAL
 * // Copyright 2014 2015 Intel Corporation All Rights Reserved.
 * //
 * // The source code contained or described herein and all documents related to
 * // the source code ("Material") are owned by Intel Corporation or its suppliers
 * // or licensors. Title to the Material remains with Intel Corporation or its
 * // suppliers and licensors. The Material contains trade secrets and proprietary and
 * // confidential information of Intel or its suppliers and licensors. The Material is
 * // protected by worldwide copyright and trade secret laws and treaty provisions. No
 * // part of the Material may be used, copied, reproduced, modified, published, uploaded,
 * // posted, transmitted, distributed, or disclosed in any way without Intel's prior
 * // express written permission.
 * //
 * // No license under any patent, copyright, trade secret or other intellectual property
 * // right is granted to or conferred upon you by disclosure or delivery of the Materials,
 * // either expressly, by implication, inducement, estoppel or otherwise. Any license under
 * // such intellectual property rights must be express and approved by Intel in writing.
 * //
 */

/*
 * //               Intel(R) Integrated Performance Primitives
 * //                   Cryptographic Primitives (ippcp)
 * //
 * //   Purpose:
 * //     Define ippCP variant
 * //
 * //
 */

#if !defined(_CP_VARIANT_TXT_ACM_H)
#define _CP_VARIANT_TXT_ACM_H

#ifndef __BYTESWAP__
unsigned short _byteswap_ushort(unsigned short val);
unsigned long _byteswap_ulong(unsigned long val);
#define __BYTESWAP__
#endif

// Open Source Customization Start
// Moved from stdlib.h to remove dependancy on standard library

#define _SHA_NI_ENABLING_ _FEATURE_ON_

unsigned long lrotr(unsigned long val, int shift);
unsigned long lrotl(unsigned long val, int shift);

#if defined(_MSC_VER)
unsigned __int64 _byteswap_uint64(unsigned __int64 val);

#define _CRT_ALIGN(x) __declspec(align(x))

typedef union __declspec(intrin_type) _CRT_ALIGN(16) __m128i {
  __int8 m128i_i8[16];
  __int16 m128i_i16[8];
  __int32 m128i_i32[4];
  __int64 m128i_i64[2];
  unsigned __int8 m128i_u8[16];
  unsigned __int16 m128i_u16[8];
  unsigned __int32 m128i_u32[4];
  unsigned __int64 m128i_u64[2];
} __m128i;
#else
unsigned long long _byteswap_uint64(unsigned long long val);

#define _CRT_ALIGN(x) __attribute__ ((aligned(x)))

typedef long long __m128i __attribute__((__vector_size__(16), __aligned__(16)));
#endif
// Open Source Customization End

#endif /* _CP_VARIANT_TXT_ACM_H */
