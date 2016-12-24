#include "smhasher/City.h"
#include "smhasher/farmhash-c.h"
#include "smhasher/metrohash.h"
#include "smhasher/MurmurHash1.h"
#include "smhasher/MurmurHash2.h"
#include "smhasher/MurmurHash3.h"
#include "smhasher/Spooky.h"
#include "smhasher/t1ha.h"

void SpookyHasherHash(
    const void *message,  // message to hash
    size_t length,        // length of message in bytes
    uint64 *hash1,        // in/out: in seed 1, out hash value 1
    uint64 *hash2);       // in/out: in seed 2, out hash value 2

void *SpookyHasherNew();

void SpookyHasherFree(void *h);

void SpookyHasherInit(
    void *h,
    uint64 seed1,       // any 64-bit value will do, including 0
    uint64 seed2);      // different seeds produce independent hashes

void SpookyHasherUpdate(
    void *h,
    const void *message,  // message fragment
    size_t length);       // length of message fragment in bytes

void SpookyHasherFinal(
    void *h,
    uint64 *hash1,    // out only: first 64 bits of hash value.
    uint64 *hash2);   // out only: second 64 bits of hash value.
