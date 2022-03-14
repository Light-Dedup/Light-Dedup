#ifndef FINGERPRINT_H_
#define FINGERPRINT_H_

#include <linux/types.h>
#include <linux/xxhash.h>
#include "stats.h"

struct nova_fp_strong_ctx {};

#define WHICH_TABLET_BIT_NUM 11
#define INDICATOR_BIT_NUM 5
#define TAG_BIT_NUM 8
#define INDEX_BIT_NUM 45
_Static_assert(WHICH_TABLET_BIT_NUM + TAG_BIT_NUM + INDEX_BIT_NUM == 64, "Fingerprint not 8 bytes!");
struct nova_fp {
	union {
		struct {
			uint64_t which_tablet: WHICH_TABLET_BIT_NUM;
			uint64_t index: INDEX_BIT_NUM;
			// (tag % 255 + 1) % 32 serves as indicator
			uint64_t tag: TAG_BIT_NUM;
		};
		uint64_t value;
	};
};
_Static_assert(INDICATOR_BIT_NUM <= TAG_BIT_NUM, "INDICATOR_BIT_NUM > TAG_BIT_NUM!");
_Static_assert(sizeof(struct nova_fp) == 8, "Fingerprint not 8B!");

static inline int nova_fp_strong_ctx_init(struct nova_fp_strong_ctx *ctx) {
	return 0;
}
static inline void nova_fp_strong_ctx_free(struct nova_fp_strong_ctx *ctx) {
}

static inline int nova_fp_calc(struct nova_fp_strong_ctx *fp_ctx, const void *addr, struct nova_fp *fp)
{
	INIT_TIMING(fp_calc_time);
	NOVA_START_TIMING(fp_calc_t, fp_calc_time);
	fp->value = xxh64((const char *)addr, 4096, 0);
	NOVA_END_TIMING(fp_calc_t, fp_calc_time);
	return 0;
}

#endif // FINGERPRINT_H_