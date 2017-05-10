#include "smhasher/City.h"
#include "smhasher/farmhash-c.h"
#include "smhasher/metrohash.h"
#include "smhasher/mum.h"
#include "smhasher/MurmurHash1.h"
#include "smhasher/MurmurHash2.h"
#include "smhasher/MurmurHash3.h"
#include "smhasher/Spooky.h"
#include "smhasher/t1ha.h"
#include "smhasher/xxhash.h"

uint64_t farmhash_fingerprint_uint128(uint128_c_t x);

uint64_t farmhash_fingerprint_uint64(uint64_t x);

uint32_t lookup3(const void *key, int length, uint32_t initval);

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
