#ifndef QUERYENGINE_MAPDHASH1INL_H
#define QUERYENGINE_MAPDHASH1INL_H

#include "../Shared/funcannotations.h"

//#define USE_XXH

#ifdef USE_XXH


/* Force direct memory access. Only works on CPU which support unaligned memory access in hardware */
static uint32_t XXH_read32(const void* memPtr) { return *(const uint32_t*) memPtr; }

#define XXH_rotl32(x,r) (((x) << (r)) | ((x) >> (32 - (r))))
#define XXH_rotl64(x,r) (((x) << (r)) | ((x) >> (64 - (r))))
#define XXH_swap32 __builtin_bswap32

/* *************************************
*  Architecture Macros
***************************************/
typedef enum { XXH_bigEndian=0, XXH_littleEndian=1 } XXH_endianess;

/* XXH_CPU_LITTLE_ENDIAN can be defined externally, for example on the compiler command line */
#ifndef XXH_CPU_LITTLE_ENDIAN
static int XXH_isLittleEndian(void)
{
    const union { uint32_t u; uint8_t c[4]; } one = { 1 };   /* don't use static : performance detrimental  */
    return one.c[0];
}
# define XXH_CPU_LITTLE_ENDIAN   XXH_isLittleEndian()
#endif


/* ***************************
*  Memory reads
*****************************/
typedef enum { XXH_aligned, XXH_unaligned } XXH_alignment;

FORCE_INLINE DEVICE uint32_t
XXH_readLE32_align(const void* ptr, XXH_endianess endian, XXH_alignment align)
{
    if (align==XXH_unaligned)
        return endian==XXH_littleEndian ? XXH_read32(ptr) : XXH_swap32(XXH_read32(ptr));
    else
        return endian==XXH_littleEndian ? *(const uint32_t*)ptr : XXH_swap32(*(const uint32_t*)ptr);
}


static const uint64_t PRIME64_1 = 11400714785074694791ULL;   /* 0b1001111000110111011110011011000110000101111010111100101010000111 */
static const uint64_t PRIME64_2 = 14029467366897019727ULL;   /* 0b1100001010110010101011100011110100100111110101001110101101001111 */
static const uint64_t PRIME64_3 =  1609587929392839161ULL;   /* 0b0001011001010110011001111011000110011110001101110111100111111001 */
static const uint64_t PRIME64_4 =  9650029242287828579ULL;   /* 0b1000010111101011110010100111011111000010101100101010111001100011 */
static const uint64_t PRIME64_5 =  2870177450012600261ULL;   /* 0b0010011111010100111010110010111100010110010101100110011111000101 */

static uint64_t XXH64_round(uint64_t acc, uint64_t input)
{
    acc += input * PRIME64_2;
    acc  = XXH_rotl64(acc, 31);
    acc *= PRIME64_1;
    return acc;
}

static uint64_t XXH64_mergeRound(uint64_t acc, uint64_t val)
{
    val  = XXH64_round(0, val);
    acc ^= val;
    acc  = acc * PRIME64_1 + PRIME64_4;
    return acc;
}

static uint64_t XXH64_avalanche(uint64_t h64)
{
    h64 ^= h64 >> 33;
    h64 *= PRIME64_2;
    h64 ^= h64 >> 29;
    h64 *= PRIME64_3;
    h64 ^= h64 >> 32;
    return h64;
}

/* Force direct memory access. Only works on CPU which support unaligned memory access in hardware */
static uint64_t XXH_read64(const void* memPtr) { return *(const uint64_t*) memPtr; }

#define XXH_swap64 __builtin_bswap64

FORCE_INLINE DEVICE uint64_t XXH_readLE64_align(const void* ptr, XXH_endianess endian, XXH_alignment align)
{
    if (align==XXH_unaligned)
        return endian==XXH_littleEndian ? XXH_read64(ptr) : XXH_swap64(XXH_read64(ptr));
    else
        return endian==XXH_littleEndian ? *(const uint64_t*)ptr : XXH_swap64(*(const uint64_t*)ptr);
}

#define XXH_get64bits(p) XXH_readLE64_align(p, endian, align)
#define XXH_get32bits(p) XXH_readLE32_align(p, endian, align)

static uint64_t
XXH64_finalize(uint64_t h64, const void* ptr, int len,
               XXH_endianess endian, XXH_alignment align)
{
    const uint8_t* p = (const uint8_t*)ptr;

#define PROCESS1_64            \
    h64 ^= (*p++) * PRIME64_5; \
    h64 = XXH_rotl64(h64, 11) * PRIME64_1;

#define PROCESS4_64          \
    h64 ^= (uint64_t)(XXH_get32bits(p)) * PRIME64_1; \
    p+=4;                    \
    h64 = XXH_rotl64(h64, 23) * PRIME64_2 + PRIME64_3;

#define PROCESS8_64 {        \
    uint64_t const k1 = XXH64_round(0, XXH_get64bits(p)); \
    p+=8;                    \
    h64 ^= k1;               \
    h64  = XXH_rotl64(h64,27) * PRIME64_1 + PRIME64_4; \
}

    switch(len&31) {
      case 24: PROCESS8_64;
                    /* fallthrough */
      case 16: PROCESS8_64;
                    /* fallthrough */
      case  8: PROCESS8_64;
               return XXH64_avalanche(h64);

      case 28: PROCESS8_64;
                    /* fallthrough */
      case 20: PROCESS8_64;
                    /* fallthrough */
      case 12: PROCESS8_64;
                    /* fallthrough */
      case  4: PROCESS4_64;
               return XXH64_avalanche(h64);

      case 25: PROCESS8_64;
                    /* fallthrough */
      case 17: PROCESS8_64;
                    /* fallthrough */
      case  9: PROCESS8_64;
               PROCESS1_64;
               return XXH64_avalanche(h64);

      case 29: PROCESS8_64;
                    /* fallthrough */
      case 21: PROCESS8_64;
                    /* fallthrough */
      case 13: PROCESS8_64;
                    /* fallthrough */
      case  5: PROCESS4_64;
               PROCESS1_64;
               return XXH64_avalanche(h64);

      case 26: PROCESS8_64;
                    /* fallthrough */
      case 18: PROCESS8_64;
                    /* fallthrough */
      case 10: PROCESS8_64;
               PROCESS1_64;
               PROCESS1_64;
               return XXH64_avalanche(h64);

      case 30: PROCESS8_64;
                    /* fallthrough */
      case 22: PROCESS8_64;
                    /* fallthrough */
      case 14: PROCESS8_64;
                    /* fallthrough */
      case  6: PROCESS4_64;
               PROCESS1_64;
               PROCESS1_64;
               return XXH64_avalanche(h64);

      case 27: PROCESS8_64;
                    /* fallthrough */
      case 19: PROCESS8_64;
                    /* fallthrough */
      case 11: PROCESS8_64;
               PROCESS1_64;
               PROCESS1_64;
               PROCESS1_64;
               return XXH64_avalanche(h64);

      case 31: PROCESS8_64;
                    /* fallthrough */
      case 23: PROCESS8_64;
                    /* fallthrough */
      case 15: PROCESS8_64;
                    /* fallthrough */
      case  7: PROCESS4_64;
                    /* fallthrough */
      case  3: PROCESS1_64;
                    /* fallthrough */
      case  2: PROCESS1_64;
                    /* fallthrough */
      case  1: PROCESS1_64;
                    /* fallthrough */
      case  0: return XXH64_avalanche(h64);
    }

    /* impossible to reach */
    return 0;  /* unreachable, but some compilers complain without it */
}

FORCE_INLINE DEVICE uint64_t XXH64_endian_align(const void* input, int len, uint64_t seed,
                XXH_endianess endian, XXH_alignment align)
{
    const uint8_t* p = (const uint8_t*)input;
    const uint8_t* bEnd = p + len;
    uint64_t h64;

    if (len>=32) {
        const uint8_t* const limit = bEnd - 32;
        uint64_t v1 = seed + PRIME64_1 + PRIME64_2;
        uint64_t v2 = seed + PRIME64_2;
        uint64_t v3 = seed + 0;
        uint64_t v4 = seed - PRIME64_1;

        do {
            v1 = XXH64_round(v1, XXH_get64bits(p)); p+=8;
            v2 = XXH64_round(v2, XXH_get64bits(p)); p+=8;
            v3 = XXH64_round(v3, XXH_get64bits(p)); p+=8;
            v4 = XXH64_round(v4, XXH_get64bits(p)); p+=8;
        } while (p<=limit);

        h64 = XXH_rotl64(v1, 1) + XXH_rotl64(v2, 7) + XXH_rotl64(v3, 12) + XXH_rotl64(v4, 18);
        h64 = XXH64_mergeRound(h64, v1);
        h64 = XXH64_mergeRound(h64, v2);
        h64 = XXH64_mergeRound(h64, v3);
        h64 = XXH64_mergeRound(h64, v4);

    } else {
        h64  = seed + PRIME64_5;
    }

    h64 += (uint64_t) len;

    return XXH64_finalize(h64, p, len, endian, align);
}

FORCE_INLINE DEVICE uint32_t MapdHash1Impl(const void* key,
                                             int len,
                                             const uint32_t seed) {
    XXH_endianess endian_detected = (XXH_endianess)XXH_CPU_LITTLE_ENDIAN;

    if ((((uint64_t)key) & 7)==0) {  /* Input is aligned, let's leverage the speed advantage */
        if ((endian_detected==XXH_littleEndian))
            return XXH64_endian_align(key, len, seed, XXH_littleEndian, XXH_aligned);
        else
            return XXH64_endian_align(key, len, seed, XXH_bigEndian, XXH_aligned);
    }

    if ((endian_detected==XXH_littleEndian))
        return XXH64_endian_align(key, len, seed, XXH_littleEndian, XXH_unaligned);
    else
        return XXH64_endian_align(key, len, seed, XXH_bigEndian, XXH_unaligned);
}

FORCE_INLINE DEVICE uint64_t MapdHash64AImpl(const void* key,
                                             int len,
                                             const uint64_t seed) {
    XXH_endianess endian_detected = (XXH_endianess)XXH_CPU_LITTLE_ENDIAN;

    if ((((uint64_t)key) & 7)==0) {  /* Input is aligned, let's leverage the speed advantage */
        if ((endian_detected==XXH_littleEndian))
            return XXH64_endian_align(key, len, seed, XXH_littleEndian, XXH_aligned);
        else
            return XXH64_endian_align(key, len, seed, XXH_bigEndian, XXH_aligned);
    }

    if ((endian_detected==XXH_littleEndian))
        return XXH64_endian_align(key, len, seed, XXH_littleEndian, XXH_unaligned);
    else
        return XXH64_endian_align(key, len, seed, XXH_bigEndian, XXH_unaligned);
}

#else

FORCE_INLINE DEVICE uint32_t MapdHash1Impl(const void* key,
                                             int len,
                                             const uint32_t seed) {
  const unsigned int m = 0xc6a4a793;

  const int r = 16;

  unsigned int h = seed ^ (len * m);

  //----------

  const unsigned char* data = (const unsigned char*)key;

  while (len >= 4) {
    unsigned int k = *(unsigned int*)data;

    h += k;
    h *= m;
    h ^= h >> 16;

    data += 4;
    len -= 4;
  }

  //----------

  switch (len) {
    case 3:
      h += data[2] << 16;
    case 2:
      h += data[1] << 8;
    case 1:
      h += data[0];
      h *= m;
      h ^= h >> r;
  };

  //----------

  h *= m;
  h ^= h >> 10;
  h *= m;
  h ^= h >> 17;

  return h;
}

FORCE_INLINE DEVICE uint64_t MapdHash64AImpl(const void* key, int len, uint64_t seed) {
  const uint64_t m = 0xc6a4a7935bd1e995LLU;
  const int r = 47;

  uint64_t h = seed ^ (len * m);

  const uint64_t* data = (const uint64_t*)key;
  const uint64_t* end = data + (len / 8);

  while (data != end) {
    uint64_t k = *data++;

    k *= m;
    k ^= k >> r;
    k *= m;

    h ^= k;
    h *= m;
  }

  const unsigned char* data2 = (const unsigned char*)data;

  switch (len & 7) {
    case 7:
      h ^= ((uint64_t)data2[6]) << 48;
    case 6:
      h ^= ((uint64_t)data2[5]) << 40;
    case 5:
      h ^= ((uint64_t)data2[4]) << 32;
    case 4:
      h ^= ((uint64_t)data2[3]) << 24;
    case 3:
      h ^= ((uint64_t)data2[2]) << 16;
    case 2:
      h ^= ((uint64_t)data2[1]) << 8;
    case 1:
      h ^= ((uint64_t)data2[0]);
      h *= m;
  };

  h ^= h >> r;
  h *= m;
  h ^= h >> r;

  return h;
}

#endif // USE_XXH

#endif  // QUERYENGINE_MAPDHASH1INL_H
