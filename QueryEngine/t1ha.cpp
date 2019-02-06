/*
 *  Copyright (c) 2016-2017 Positive Technologies, https://www.ptsecurity.com,
 *  Fast Positive Hash.
 *
 *  Portions Copyright (c) 2010-2017 Leonid Yuriev <leo@yuriev.ru>,
 *  The 1Hippeus project (t1h).
 *
 *  This software is provided 'as-is', without any express or implied
 *  warranty. In no event will the authors be held liable for any damages
 *  arising from the use of this software.
 *
 *  Permission is granted to anyone to use this software for any purpose,
 *  including commercial applications, and to alter it and redistribute it
 *  freely, subject to the following restrictions:
 *
 *  1. The origin of this software must not be misrepresented; you must not
 *     claim that you wrote the original software. If you use this software
 *     in a product, an acknowledgement in the product documentation would be
 *     appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be
 *     misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */

/*
 * t1ha = { Fast Positive Hash, aka "Позитивный Хэш" }
 * by [Positive Technologies](https://www.ptsecurity.ru)
 *
 * Briefly, it is a 64-bit Hash Function:
 *  1. Created for 64-bit little-endian platforms, in predominantly for x86_64,
 *     but without penalties could runs on any 64-bit CPU.
 *  2. In most cases up to 15% faster than City64, xxHash, mum-hash, metro-hash
 *     and all others which are not use specific hardware tricks.
 *  3. Not suitable for cryptography.
 *
 * The Future will Positive. Всё будет хорошо.
 *
 * ACKNOWLEDGEMENT:
 * The t1ha was originally developed by Leonid Yuriev (Леонид Юрьев)
 * for The 1Hippeus project - zerocopy messaging in the spirit of Sparta!
 */

/*
 * dpayne
 *  - Small modifications were done to the original t1ha. All changes revolve around simplifying the code under the assumption of an x86-64 intel processor with aes and avx support.
 */

#include <stdlib.h>
#include <string.h>
#include <emmintrin.h>
#include <wmmintrin.h>
#include <x86intrin.h>
#include <cstdint>
#include "t1ha.h"

#define t1ha_unreachable() __builtin_unreachable()

/* 'magic' primes */
static const uint64_t t1ha_p0 = 17048867929148541611ull;
static const uint64_t t1ha_p1 = 9386433910765580089ull;
static const uint64_t t1ha_p2 = 15343884574428479051ull;
static const uint64_t t1ha_p3 = 13662985319504319857ull;
static const uint64_t t1ha_p4 = 11242949449147999147ull;

/* rotations */
static const unsigned t1ha_s0 = 41;
static const unsigned t1ha_s1 = 17;

static __inline uint32_t t1ha_fetch32_le(const void *v) {
  return *(const uint32_t *)v;
}

static __inline uint16_t t1ha_fetch16_le(const void *v) {
  return *(const uint16_t *)v;
}

static __inline uint64_t t1ha_fetch64_le(const void *v) {
  return *(const uint64_t *)v;
}

static __inline uint64_t t1ha_tail64_le(const void *v, size_t tail) {
  const uint8_t *p = (const uint8_t *)v;
  uint64_t r = 0;
  switch (tail & 7) {
  /* For most CPUs this code is better when not needed
   * copying for alignment or byte reordering. */
  case 0:
    return t1ha_fetch64_le(p);
  case 7:
    r = (uint64_t)p[6] << 8;
  case 6:
    r += p[5];
    r <<= 8;
  case 5:
    r += p[4];
    r <<= 32;
  case 4:
    return r + t1ha_fetch32_le(p);
  case 3:
    r = (uint64_t)p[2] << 16;
  case 2:
    return r + t1ha_fetch16_le(p);
  case 1:
    return p[0];
  }
  t1ha_unreachable();
}

static __inline uint64_t t1ha_rot64(uint64_t v, unsigned s) {
  return (v >> s) | (v << (64 - s));
}

static __inline uint64_t t1ha_mix(uint64_t v, uint64_t p) {
  v *= p;
  return v ^ t1ha_rot64(v, t1ha_s0);
}


/* xor high and low parts of full 128-bit product */
static __inline uint64_t t1ha_mux64(uint64_t v, uint64_t p) {
  __uint128_t r = (__uint128_t)v * (__uint128_t)p;
  /* modern GCC could nicely optimize this */
  return r ^ (r >> 64);
}

uint64_t
t1ha(const void *data, size_t len, uint64_t seed) {
  uint64_t a = seed;
  uint64_t b = len;

  const uint64_t *v;
  if (len > 32) {
    __m128i x = _mm_set_epi64x(a, b);
    __m128i y = _mm_aesenc_si128(x, _mm_set_epi64x(t1ha_p0, t1ha_p1));

    const __m128i *v1 = (const __m128i *)data;
    const __m128i *const detent =
        (const __m128i *)((const uint8_t *)data + (len & ~15ul));
    data = detent;

    if (len & 16) {
      x = _mm_add_epi64(x, _mm_loadu_si128(v1++));
      y = _mm_aesenc_si128(x, y);
    }
    len &= 15;

    if (v1 + 7 < detent) {
      __m128i salt = y;
      do {
        __m128i t = _mm_aesenc_si128(_mm_loadu_si128(v1++), salt);
        t = _mm_aesdec_si128(t, _mm_loadu_si128(v1++));
        t = _mm_aesdec_si128(t, _mm_loadu_si128(v1++));
        t = _mm_aesdec_si128(t, _mm_loadu_si128(v1++));

        t = _mm_aesdec_si128(t, _mm_loadu_si128(v1++));
        t = _mm_aesdec_si128(t, _mm_loadu_si128(v1++));
        t = _mm_aesdec_si128(t, _mm_loadu_si128(v1++));
        t = _mm_aesdec_si128(t, _mm_loadu_si128(v1++));

        salt = _mm_add_epi64(salt, _mm_set_epi64x(t1ha_p2, t1ha_p3));
        t = _mm_aesenc_si128(x, t);
        x = _mm_add_epi64(y, x);
        y = t;
      } while (v1 + 7 < detent);
    }

    while (v1 < detent) {
      __m128i v0y = _mm_add_epi64(y, _mm_loadu_si128(v1++));
      __m128i v1x = _mm_sub_epi64(x, _mm_loadu_si128(v1++));
      x = _mm_aesdec_si128(x, v0y);
      y = _mm_aesdec_si128(y, v1x);
    }

    x = _mm_add_epi64(_mm_aesdec_si128(x, _mm_aesenc_si128(y, x)), y);
    a = _mm_cvtsi128_si64(x);
    b = _mm_extract_epi64(x, 1);
  }

  v = (const uint64_t *)data;

  switch (len) {
  default:
    b += t1ha_mux64(t1ha_fetch64_le(v++), t1ha_p4);
  case 24:
  case 23:
  case 22:
  case 21:
  case 20:
  case 19:
  case 18:
  case 17:
    a += t1ha_mux64(t1ha_fetch64_le(v++), t1ha_p3);
  case 16:
  case 15:
  case 14:
  case 13:
  case 12:
  case 11:
  case 10:
  case 9:
    b += t1ha_mux64(t1ha_fetch64_le(v++), t1ha_p2);
  case 8:
  case 7:
  case 6:
  case 5:
  case 4:
  case 3:
  case 2:
  case 1:
    a += t1ha_mux64(t1ha_tail64_le(v, len), t1ha_p1);
  case 0:
    return t1ha_mux64(t1ha_rot64(a + b, t1ha_s1), t1ha_p4) + t1ha_mix(a ^ b, t1ha_p0);
  }
}

