#include "fasthash.hpp"

#include "highwayhash/highwayhash/instruction_sets.h"
#include "highwayhash/highwayhash/highwayhash_target.h"

uint64_t farmhash_fingerprint_uint128(uint128_c_t x)
{
    return farmhash_fingerprint_uint128_c_t(x);
}

uint64_t farmhash_fingerprint_uint64(uint64_t x)
{
    return farmhash_fingerprint_uint64_t(x);
}

uint64_t mum_hash_(const void *key, size_t len, uint64_t seed)
{
    return mum_hash(key, len, seed);
}

void SpookyHasherHash(
    const void *message, // message to hash
    size_t length,       // length of message in bytes
    uint64 *hash1,       // in/out: in seed 1, out hash value 1
    uint64 *hash2)       // in/out: in seed 2, out hash value 2
{
    SpookyHash::Hash128(message, length, hash1, hash2);
}

void *SpookyHasherNew() { return new SpookyHash(); }

void SpookyHasherFree(void *h) { delete ((SpookyHash *)h); }

void SpookyHasherInit(
    void *h,
    uint64 seed1, // any 64-bit value will do, including 0
    uint64 seed2) // different seeds produce independent hashes
{
    ((SpookyHash *)h)->Init(seed1, seed2);
}

void SpookyHasherUpdate(
    void *h,
    const void *message, // message fragment
    size_t length)       // length of message fragment in bytes
{
    ((SpookyHash *)h)->Update(message, length);
}

void SpookyHasherFinal(
    void *h,
    uint64 *hash1, // out only: first 64 bits of hash value.
    uint64 *hash2) // out only: second 64 bits of hash value.
{
    ((SpookyHash *)h)->Final(hash1, hash2);
}

uint64_t t1ha0_64(const void *data, size_t length, uint64_t seed)
{
    return t1ha0(data, length, seed);
}

void HighwayHash128(const HHKey key, const char *bytes, const uint64_t size, HHResult128 &hash)
{
    highwayhash::InstructionSets::Run<highwayhash::HighwayHash>(
        *reinterpret_cast<const HHKey *>(key), bytes, size, reinterpret_cast<HHResult128 *>(hash));
}

void HighwayHash256(const HHKey key, const char *bytes, const uint64_t size, HHResult256 &hash)
{
    highwayhash::InstructionSets::Run<highwayhash::HighwayHash>(
        *reinterpret_cast<const HHKey *>(key), bytes, size, reinterpret_cast<HHResult256 *>(hash));
}

uint64_t wyhash64(const void *key, uint64_t len, uint64_t seed)
{
    return wyhash(key, len, seed, _wyp);
}

void MeowHash128(const void *key, int len, void *seed, void *out)
{
    meow_u128 h = MeowHash(seed, (meow_umm)len, (void *)key);
    ((uint64_t *)out)[0] = MeowU64From(h, 0);
    ((uint64_t *)out)[1] = MeowU64From(h, 1);
}

void MeowHashBegin(meow_state *State, void *Seed128)
{
    MeowBegin(State, Seed128);
}

void MeowHashUpdate(meow_state *State, size_t Len, void *SourceInit)
{
    MeowAbsorb(State, Len, SourceInit);
}

void MeowHashEnd(meow_state *State, void *out)
{
    meow_u128 h = MeowEnd(State, NULL);
    ((uint64_t *)out)[0] = MeowU64From(h, 0);
    ((uint64_t *)out)[1] = MeowU64From(h, 1);
}

void MeowHashExpandSeed(meow_umm InputLen, void *Input, meow_u8 *SeedResult)
{
    MeowExpandSeed(InputLen, Input, SeedResult);
}
