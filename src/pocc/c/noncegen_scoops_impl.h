// Template for the noncegen_scoops_<simd> functions.
//
// Unlike noncegen_<simd>, which generates consecutive nonces of one account, every SIMD lane gets
// its own account id and nonce, and only one scoop per nonce is written. This is what block
// verification needs: a batch of blocks has unrelated generators and nonces.
//
// Included at the end of a noncegen_*.c file, after these macros are defined:
//   NG_LANES        number of SIMD lanes (MSHABAL*_VECTOR_SIZE)
//   NG_VEC          SIMD vector type, used to align the termination strings
//   NG_CTX_FAST     mshabal fast context type
//   NG_GLOBAL_FAST  initialized global fast context of that file
//   NG_HASH_FAST    mshabal_hash_fast_<simd> function
//   NG_SCOOPS_FUNC  name of the generated function

#include <stdlib.h>
#include <string.h>

// account_ids, nonces, scoops: count entries each, every scoop < NUM_SCOOPS
// count:                       must be a multiple of NG_LANES
// out:                         count * SCOOP_SIZE bytes, scoop i is written to out[i * SCOOP_SIZE]
// returns 0 on success, -1 if count is not a multiple of NG_LANES or memory allocation failed
int NG_SCOOPS_FUNC(const uint64_t *account_ids, const uint64_t *nonces, const uint32_t *scoops,
                   uint64_t count, char poc_version, uint8_t *out) {
    if (count % NG_LANES != 0) {
        return -1;
    }

    // Layout of the vectored buffers: 4 byte word at byte offset b (b % 4 == 0) of lane k is at
    // index b * NG_LANES + k * 4.
    uint8_t *buffer = (uint8_t *)malloc((size_t)NG_LANES * NONCE_SIZE);
    uint8_t *final = (uint8_t *)malloc((size_t)NG_LANES * HASH_SIZE);
    if (buffer == NULL || final == NULL) {
        free(buffer);
        free(final);
        return -1;
    }

    NG_CTX_FAST local_fast;
    union {
        mshabal_u32 words[16 * NG_LANES];
        NG_VEC data[16];
    } t1, t2, t3;

    char term[32];  // 1bit 1, 255bit of zeros
    char zero[32];  // 256bit of zeros
    write_term(term);
    memset(zero, 0, sizeof(zero));

    // parts of the termination strings that are the same for all lanes
    for (int w = 0; w < 8; w++) {
        for (int k = 0; k < NG_LANES; k++) {
            memcpy(&t1.words[(w + 8) * NG_LANES + k], zero + 4 * w, 4);
            memcpy(&t3.words[w * NG_LANES + k], term + 4 * w, 4);
            memcpy(&t3.words[(w + 8) * NG_LANES + k], zero + 4 * w, 4);
        }
    }

    for (uint64_t n = 0; n < count; n += NG_LANES) {
        // seed per lane: 64bit account id, 64bit nonce, 1bit termination, 127 bits zero
        // t1: seed + zeros, t2: (first hash, filled in below) + seed
        for (int k = 0; k < NG_LANES; k++) {
            char seed[32];
            uint64_t nonce = bswap_64(nonces[n + k]);
            write_seed(seed, account_ids[n + k]);
            memcpy(&seed[8], &nonce, 8);
            for (int w = 0; w < 8; w++) {
                memcpy(&t1.words[w * NG_LANES + k], seed + 4 * w, 4);
                memcpy(&t2.words[(w + 8) * NG_LANES + k], seed + 4 * w, 4);
            }
        }

        // 3 cases: first 128 rounds uses case 1 or 2, after that case 3
        // case 1: first 128 rounds, hashes are even: use termination string 1
        // case 2: first 128 rounds, hashes are odd: use termination string 2
        // case 3: round > 128: use termination string 3

        // round 1
        memcpy(&local_fast, &NG_GLOBAL_FAST, sizeof(local_fast));  // fast initialize shabal
        NG_HASH_FAST(&local_fast, NULL, &t1, &buffer[NG_LANES * (NONCE_SIZE - HASH_SIZE)], 16 >> 6);

        // store first hash into termination string 2 (data is vectored and SIMD aligned)
        memcpy(&t2, &buffer[NG_LANES * (NONCE_SIZE - HASH_SIZE)], NG_LANES * HASH_SIZE);

        // round 2 - 128
        for (size_t i = NONCE_SIZE - HASH_SIZE; i > (NONCE_SIZE - HASH_CAP); i -= HASH_SIZE) {
            // last msg = seed + termination if it divides into 512bit packages without a
            // remainder, otherwise 256 bit data + seed + termination
            NG_HASH_FAST(&local_fast, &buffer[i * NG_LANES], (i % 64 == 0) ? (void *)&t1 : (void *)&t2,
                         &buffer[(i - HASH_SIZE) * NG_LANES], (NONCE_SIZE + 16 - i) >> 6);
        }

        // round 128 - 8192
        for (size_t i = NONCE_SIZE - HASH_CAP; i > 0; i -= HASH_SIZE) {
            NG_HASH_FAST(&local_fast, &buffer[i * NG_LANES], &t3, &buffer[(i - HASH_SIZE) * NG_LANES],
                         HASH_CAP >> 6);
        }

        // final hash
        NG_HASH_FAST(&local_fast, &buffer[0], &t1, &final[0], (NONCE_SIZE + 16) >> 6);

        // Extract the requested scoop per lane and XOR it with the final hash. Hash h of a nonce
        // is the first half of scoop h / 2 if h is even, otherwise the second half. PoC2 takes the
        // second half from the mirrored scoop.
        for (int k = 0; k < NG_LANES; k++) {
            size_t scoop = scoops[n + k] % NUM_SCOOPS;
            size_t first = 2 * scoop;
            size_t second = poc_version == 2 ? 2 * (NUM_SCOOPS - 1 - scoop) + 1 : first + 1;
            uint8_t *dst = &out[(n + k) * SCOOP_SIZE];
            for (size_t b = 0; b < HASH_SIZE; b++) {
                size_t lane_byte = (b & ~(size_t)3) * NG_LANES + k * 4 + (b & 3);
                uint8_t f = final[lane_byte];
                dst[b] = buffer[first * HASH_SIZE * NG_LANES + lane_byte] ^ f;
                dst[HASH_SIZE + b] = buffer[second * HASH_SIZE * NG_LANES + lane_byte] ^ f;
            }
        }
    }

    free(buffer);
    free(final);
    return 0;
}
