#pragma once

#include "highwayhash/highwayhash/c_bindings.h"
#include "smhasher/City.h"
#include "smhasher/CityCrc.h"
#include "smhasher/farmhash-c.h"
#include "smhasher/meow_hash_x64_aesni.h"
#include "smhasher/metrohash/metrohash.h"
#include "smhasher/mum.h"
#include "smhasher/MurmurHash1.h"
#include "smhasher/MurmurHash2.h"
#include "smhasher/MurmurHash3.h"
#include "smhasher/Spooky.h"
#include "t1ha/t1ha.h"
#include "wyhash/wyhash.h"
#include "xxHash/xxhash.h"

uint32_t lookup3(const char *key, int length, uint32_t initval);

uint64_t farmhash_fingerprint_uint128(uint128_c_t x);

uint64_t farmhash_fingerprint_uint64(uint64_t x);

uint64_t mum_hash_(const void *key, size_t len, uint64_t seed);

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

uint64_t t1ha0_64(const void *data, size_t length, uint64_t seed);

void HighwayHash128(const HHKey key, const char *bytes, const uint64_t size, HHResult128 &hash);

void HighwayHash256(const HHKey key, const char *bytes, const uint64_t size, HHResult256 &hash);

uint64_t wyhash64(const void *key, uint64_t len, uint64_t seed);

void MeowHash128(const void *key, int len, void *seed, void *out);

typedef struct meow_state;

void MeowHashBegin(meow_state *State, void *Seed128);

void MeowHashUpdate(meow_state *State, size_t Len, void *SourceInit);

void MeowHashEnd(meow_state *State, void *out);

void MeowHashExpandSeed(meow_umm InputLen, void *Input, meow_u8 *SeedResult);
