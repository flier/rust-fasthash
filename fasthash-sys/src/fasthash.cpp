#include "fasthash.hpp"

#ifdef FARM_HASH

uint64_t farmhash_fingerprint_uint128(uint128_c_t x)
{
    return farmhash_fingerprint_uint128_c_t(x);
}

uint64_t farmhash_fingerprint_uint64(uint64_t x)
{
    return farmhash_fingerprint_uint64_t(x);
}

#endif

#ifdef KOMI_HASH

#include "komihash/komihash.h"

uint64_t komihash64(const void *const Msg0, size_t MsgLen, const uint64_t UseSeed)
{
    return komihash(Msg0, MsgLen, UseSeed);
}

uint64_t komirand64(uint64_t *const Seed1, uint64_t *const Seed2)
{
    return komirand(Seed1, Seed2);
}

#endif

#ifdef MUM_HASH

#include "smhasher/mum.h"

uint64_t mum_hash_(const void *key, size_t len, uint64_t seed)
{
    return mum_hash(key, len, seed);
}

#endif

#ifdef MX3_HASH

#include "mx3/mx3.h"

uint64_t mx3hash(const uint8_t *buf, size_t len, uint64_t seed)
{
    return mx3::hash(buf, len, seed);
}

#endif

#ifdef NM_HASH
uint32_t
NMHASH32_(const void *const NMH_RESTRICT input, size_t const len, uint32_t seed)
{
    return NMHASH32(input, len, seed);
}

uint32_t
NMHASH32X_(const void *const NMH_RESTRICT input, size_t const len, uint32_t seed)
{
    return NMHASH32X(input, len, seed);
}

#endif

#ifdef SPOOKY_HASH

void SpookyHasherHash(
    const void *message, // message to hash
    size_t length,       // length of message in bytes
    uint64 *hash1,       // in/out: in seed 1, out hash value 1
    uint64 *hash2)       // in/out: in seed 2, out hash value 2
{
    SpookyHashV1::Hash128(message, length, hash1, hash2);
}

void *SpookyHasherNew() { return new SpookyHashV1(); }

void SpookyHasherFree(void *h) { delete static_cast<SpookyHashV1 *>(h); }

void SpookyHasherInit(
    void *h,
    uint64 seed1, // any 64-bit value will do, including 0
    uint64 seed2) // different seeds produce independent hashes
{
    static_cast<SpookyHashV1 *>(h)->Init(seed1, seed2);
}

void SpookyHasherUpdate(
    void *h,
    const void *message, // message fragment
    size_t length)       // length of message fragment in bytes
{
    static_cast<SpookyHashV1 *>(h)->Update(message, length);
}

void SpookyHasherFinal(
    void *h,
    uint64 *hash1, // out only: first 64 bits of hash value.
    uint64 *hash2) // out only: second 64 bits of hash value.
{
    static_cast<SpookyHashV1 *>(h)->Final(hash1, hash2);
}

#endif

#ifdef T1_HASH

uint64_t t1ha0_64(const void *data, size_t length, uint64_t seed)
{
    return t1ha0(data, length, seed);
}

#endif

#ifdef HIGHWAY_HASH

#include "highwayhash/highwayhash/instruction_sets.h"
#include "highwayhash/highwayhash/highwayhash_target.h"

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

#endif

#ifdef WY_HASH

uint64_t wyhash64(const void *key, uint64_t len, uint64_t seed)
{
    return wyhash(key, len, seed, _wyp);
}

#endif

#ifdef MEOW_HASH

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

#endif

#ifdef PRV_HASH

void prvhash16_(const void *const Msg0, const size_t MsgLen,
                void *const Hash0, const size_t HashLen, const uint32_t UseSeed)
{
    return prvhash16(Msg0, MsgLen, Hash0, HashLen, UseSeed);
}

void prvhash64_(const void *const Msg0, const size_t MsgLen,
                void *const Hash0, const size_t HashLen, const PRH64_T UseSeed,
                const void *const InitVec0)
{
    return prvhash64(Msg0, MsgLen, Hash0, HashLen, UseSeed, InitVec0);
}

uint64_t prvhash64_64m_(const void *const Msg0,
                        const size_t MsgLen, const PRH64_T UseSeed)
{
    return prvhash64_64m(Msg0, MsgLen, UseSeed);
}

void prvhash64s_init_(PRVHASH64S_CTX *const ctx,
                      void *const Hash0, const size_t HashLen,
                      const PRH64S_T UseSeeds[PRH64S_PAR], const void *const InitVec0)
{
    return prvhash64s_init(ctx, Hash0, HashLen, UseSeeds, InitVec0);
}

void prvhash64s_update_(PRVHASH64S_CTX *const ctx, const void *const Msg0, size_t MsgLen)
{
    return prvhash64s_update(ctx, Msg0, MsgLen);
}

void prvhash64s_final_(PRVHASH64S_CTX *const ctx)
{
    return prvhash64s_final(ctx);
}

void prvhash64s_oneshot_(const void *const Msg, const size_t MsgLen, void *const Hash, const size_t HashLen)
{
    return prvhash64s_oneshot(Msg, MsgLen, Hash, HashLen);
}

#endif
