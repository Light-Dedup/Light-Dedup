#ifndef FINGERPRINT_H_
#define FINGERPRINT_H_

#include <linux/types.h>
#include <linux/xxhash.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include "stats.h"

#define NOVA_FP_STRONG_CTX_BUF_SIZE 256

struct nova_fp_strong_ctx {
	struct crypto_shash *alg;
};

struct nova_fp_partial {
	u32 index;
	uint64_t value;
};
struct nova_fp {
	union {
		struct nova_fp_partial partial;
		uint64_t u64s[4];
	};
};

_Static_assert(sizeof(struct nova_fp) == 32, "Fingerprint not 32B!");

static inline int nova_fp_strong_ctx_init(struct nova_fp_strong_ctx *ctx) {
	struct crypto_shash *alg = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(alg))
		return PTR_ERR(alg);
	if (crypto_shash_descsize(alg) > NOVA_FP_STRONG_CTX_BUF_SIZE) {
		crypto_free_shash(alg);
		return -EINVAL;
	}
	ctx->alg = alg;
	return 0;
}
static inline void nova_fp_strong_ctx_free(struct nova_fp_strong_ctx *ctx) {
	crypto_free_shash(ctx->alg);
}

static inline int nova_fp_calc(struct nova_fp_strong_ctx *fp_ctx, const void *addr, struct nova_fp *fp)
{
	struct shash_desc *shash_desc;
	int ret;
	INIT_TIMING(fp_calc_time);

	shash_desc = kmalloc(sizeof(struct shash_desc) +
		crypto_shash_descsize(fp_ctx->alg), GFP_KERNEL);
	if (shash_desc == NULL)
		return -ENOMEM;
	shash_desc->tfm = fp_ctx->alg;
	NOVA_START_TIMING(fp_calc_t, fp_calc_time);
	ret = crypto_shash_digest(shash_desc, (const void*)addr, 4096, (void*)fp->u64s);
	NOVA_END_TIMING(fp_calc_t, fp_calc_time);
	kfree(shash_desc);

	return ret;
}

#endif // FINGERPRINT_H_