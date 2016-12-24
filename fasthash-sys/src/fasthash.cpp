#include "fasthash.hpp"

uint64_t mum_hash_(const void *key, size_t len, uint64_t seed) {
    return mum_hash(key, len, seed);
}

void SpookyHasherHash(
    const void *message,  // message to hash
    size_t length,        // length of message in bytes
    uint64 *hash1,        // in/out: in seed 1, out hash value 1
    uint64 *hash2)        // in/out: in seed 2, out hash value 2
{
    SpookyHash::Hash128(message, length, hash1, hash2);
}

void *SpookyHasherNew() { return new SpookyHash(); }

void SpookyHasherFree(void *h) { delete ((SpookyHash *) h); }

void SpookyHasherInit(
    void *h,
    uint64 seed1,       // any 64-bit value will do, including 0
    uint64 seed2)       // different seeds produce independent hashes
{
    ((SpookyHash *) h)->Init(seed1, seed2);
}

void SpookyHasherUpdate(
    void *h,
    const void *message,  // message fragment
    size_t length)        // length of message fragment in bytes
{
    ((SpookyHash *) h)->Update(message, length);
}

void SpookyHasherFinal(
    void *h,
    uint64 *hash1,    // out only: first 64 bits of hash value.
    uint64 *hash2)    // out only: second 64 bits of hash value.
{
    ((SpookyHash *) h)->Final(hash1, hash2);
}