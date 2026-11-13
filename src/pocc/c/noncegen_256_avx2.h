#pragma once

#include <stdint.h>
#include <stdlib.h>

void init_noncegen_avx2();
void noncegen_avx2(char *cache,
                   const uint64_t numeric_id, const uint64_t local_startnonce,
                   const uint64_t local_nonces,
                   char poc_version);

// One scoop per (account id, nonce, scoop), see noncegen_scoops_impl.h. count must be a multiple of
// MSHABAL256_VECTOR_SIZE. Returns 0 on success.
int noncegen_scoops_avx2(const uint64_t *account_ids, const uint64_t *nonces, const uint32_t *scoops,
                   uint64_t count, char poc_version, uint8_t *out);
