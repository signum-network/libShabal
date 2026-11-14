// Batched scoop creation for ARM NEON. The SSE2 Shabal code runs on NEON through SSE2NEON.h, as in
// shabal_neon.c; only the scoops function is provided, plotting stays on x86.
#include "noncegen_128_neon.h"
#include "SSE2NEON.h"
#include <string.h>
#include "common.h"
#include "mshabal_128_neon.h"
#include "sph_shabal.h"

static mshabal128_context global_128;
static mshabal128_context_fast global_128_fast;

void init_noncegen_neon() {
    mshabal_init_neon(&global_128, 256);
    global_128_fast.out_size = global_128.out_size;
    for (int i = 0; i < 176; i++) global_128_fast.state[i] = global_128.state[i];
    global_128_fast.Whigh = global_128.Whigh;
    global_128_fast.Wlow = global_128.Wlow;
}

#define NG_LANES MSHABAL128_VECTOR_SIZE
#define NG_VEC __m128i
#define NG_CTX_FAST mshabal128_context_fast
#define NG_GLOBAL_FAST global_128_fast
#define NG_HASH_FAST mshabal_hash_fast_neon
#define NG_SCOOPS_FUNC noncegen_scoops_neon
#include "noncegen_scoops_impl.h"
