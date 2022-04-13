#pragma once

#ifdef CITY_HASH
#include "smhasher/City.h"
#include "smhasher/CityCrc.h"
#endif

#ifdef METRO_HASH
#include "smhasher/metrohash/metrohash.h"
#endif

#ifdef MURMUR_HASH
#include "smhasher/MurmurHash1.h"
#include "smhasher/MurmurHash2.h"
#include "smhasher/MurmurHash3.h"
#endif

#ifdef XX_HASH
#include "xxHash/xxhash.h"
#endif

#ifdef LOOKUP3

uint32_t lookup3(const char *key, int length, uint32_t initval);

#endif

#ifdef FARM_HASH

#include "smhasher/farmhash-c.h"

uint64_t farmhash_fingerprint_uint128(uint128_c_t x);

uint64_t farmhash_fingerprint_uint64(uint64_t x);

#endif

#ifdef KOMI_HASH

uint64_t komihash64(const void *const Msg0, size_t MsgLen, const uint64_t UseSeed);

uint64_t komirand64(uint64_t *const Seed1, uint64_t *const Seed2);

#endif

#ifdef MEOW_HASH

#include "smhasher/meow_hash_x64_aesni.h"

void MeowHash128(const void *key, int len, void *seed, void *out);

void MeowHashBegin(meow_state *State, void *Seed128);

void MeowHashUpdate(meow_state *State, size_t Len, void *SourceInit);

void MeowHashEnd(meow_state *State, void *out);

void MeowHashExpandSeed(meow_umm InputLen, void *Input, meow_u8 *SeedResult);

#endif

#ifdef MUM_HASH

#include "smhasher/mum.h"

uint64_t mum_hash_(const void *key, size_t len, uint64_t seed);

#endif

#ifdef SPOOKY_HASH

#include "smhasher/Spooky.h"

void SpookyHasherHash(
    const void *message, // message to hash
    size_t length,       // length of message in bytes
    uint64 *hash1,       // in/out: in seed 1, out hash value 1
    uint64 *hash2);      // in/out: in seed 2, out hash value 2

void *SpookyHasherNew();

void SpookyHasherFree(void *h);

void SpookyHasherInit(
    void *h,
    uint64 seed1,  // any 64-bit value will do, including 0
    uint64 seed2); // different seeds produce independent hashes

void SpookyHasherUpdate(
    void *h,
    const void *message, // message fragment
    size_t length);      // length of message fragment in bytes

void SpookyHasherFinal(
    void *h,
    uint64 *hash1,  // out only: first 64 bits of hash value.
    uint64 *hash2); // out only: second 64 bits of hash value.

#endif // SPOOKY_HASH

#ifdef T1_HASH

#include "t1ha/t1ha.h"

uint64_t t1ha0_64(const void *data, size_t length, uint64_t seed);

#endif

#ifdef HIGHWAY_HASH

#include "highwayhash/highwayhash/c_bindings.h"

void HighwayHash128(const HHKey key, const char *bytes, const uint64_t size, HHResult128 &hash);

void HighwayHash256(const HHKey key, const char *bytes, const uint64_t size, HHResult256 &hash);

#endif

#ifdef WY_HASH

#include "wyhash/wyhash.h"

uint64_t wyhash64(const void *key, uint64_t len, uint64_t seed);

#endif
