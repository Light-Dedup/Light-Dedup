#include <linux/types.h>
#include <asm/asm.h>
#include <linux/kernel.h>

#define BLOCK_SIZE 4096

// Assume that block_a and block_b is 8 byte aligned
uint64_t cmp64(const uint64_t *block_a, const uint64_t *block_b) {
	const uint64_t *b_end = block_b + BLOCK_SIZE / sizeof(block_b[0]);
	for (; block_b < b_end; ++block_b, ++block_a) {
		if (*block_a != *block_b) {
			printk("cmp64: %ld, %llx, %llx\n", 4096 - (b_end - block_b) * 8, *block_a, *block_b);
			return *block_a - *block_b;
		}
	}
	return 0;
}

// Assume that block_a and block_b is 8 byte aligned
uint64_t cmp64_8(const uint64_t *block_a, const uint64_t *block_b) {
	const uint64_t *b_end = block_b + BLOCK_SIZE / sizeof(block_b[0]);
	for (; block_b < b_end; block_b += 8, block_a += 8) {
		if (block_a[0] != block_b[0])
			return block_a[0] - block_b[0];
		if (block_a[1] != block_b[1])
			return block_a[1] - block_b[1];
		if (block_a[2] != block_b[2])
			return block_a[2] - block_b[2];
		if (block_a[3] != block_b[3])
			return block_a[3] - block_b[3];
		if (block_a[4] != block_b[4])
			return block_a[4] - block_b[4];
		if (block_a[5] != block_b[5])
			return block_a[5] - block_b[5];
		if (block_a[6] != block_b[6])
			return block_a[6] - block_b[6];
		if (block_a[7] != block_b[7])
			return block_a[7] - block_b[7];
	}
	return 0;
}

// Assume that block_a and block_b is 8 byte aligned
uint64_t cmp64_4(const uint64_t *block_a, const uint64_t *block_b) {
	const uint64_t *b_end = block_b + BLOCK_SIZE / sizeof(block_b[0]);
	for (; block_b < b_end; block_b += 4, block_a += 4) {
		if (block_a[0] != block_b[0])
			return block_a[0] - block_b[0];
		if (block_a[1] != block_b[1])
			return block_a[1] - block_b[1];
		if (block_a[2] != block_b[2])
			return block_a[2] - block_b[2];
		if (block_a[3] != block_b[3])
			return block_a[3] - block_b[3];
	}
	return 0;
}

// Assume that block_a and block_b is 8 byte aligned
uint64_t cmp64_8_or(const uint64_t *block_a, const uint64_t *block_b) {
	const uint64_t *b_end = block_b + BLOCK_SIZE / sizeof(block_b[0]);
	for (; block_b < b_end; block_b += 8, block_a += 8) {
		if (block_a[0] != block_b[0] || block_a[1] != block_b[1] || block_a[2] != block_b[2] || block_a[3] != block_b[3] || block_a[4] != block_b[4] || block_a[5] != block_b[5] || block_a[6] != block_b[6] || block_a[7] != block_b[7]) {
			if (block_a[0] != block_b[0])
				return block_a[0] - block_b[0];
			if (block_a[1] != block_b[1])
				return block_a[1] - block_b[1];
			if (block_a[2] != block_b[2])
				return block_a[2] - block_b[2];
			if (block_a[3] != block_b[3])
				return block_a[3] - block_b[3];
			if (block_a[4] != block_b[4])
				return block_a[4] - block_b[4];
			if (block_a[5] != block_b[5])
				return block_a[5] - block_b[5];
			if (block_a[6] != block_b[6])
				return block_a[6] - block_b[6];
			if (block_a[7] != block_b[7])
				return block_a[7] - block_b[7];
		}
	}
	return 0;
}

// Assume that block_a and block_b is 8 byte aligned
uint64_t cmp64_8_bitwise_or(const uint64_t *block_a, const uint64_t *block_b) {
	const uint64_t *b_end = block_b + BLOCK_SIZE / sizeof(block_b[0]);
	for (; block_b < b_end; block_b += 8, block_a += 8) {
		if ((block_a[0] - block_b[0]) | (block_a[1] - block_b[1]) | (block_a[2] - block_b[2]) | (block_a[3] - block_b[3]) | (block_a[4] - block_b[4]) | (block_a[5] - block_b[5]) | (block_a[6] - block_b[6]) | (block_a[7] - block_b[7])) {
			if (block_a[0] != block_b[0])
				return block_a[0] - block_b[0];
			if (block_a[1] != block_b[1])
				return block_a[1] - block_b[1];
			if (block_a[2] != block_b[2])
				return block_a[2] - block_b[2];
			if (block_a[3] != block_b[3])
				return block_a[3] - block_b[3];
			if (block_a[4] != block_b[4])
				return block_a[4] - block_b[4];
			if (block_a[5] != block_b[5])
				return block_a[5] - block_b[5];
			if (block_a[6] != block_b[6])
				return block_a[6] - block_b[6];
			if (block_a[7] != block_b[7])
				return block_a[7] - block_b[7];
		}
	}
	return 0;
}

// Assume that block_a and block_b is 8 byte aligned
uint64_t cmp64_4_bitwise_or(const uint64_t *block_a, const uint64_t *block_b) {
	const uint64_t *b_end = block_b + BLOCK_SIZE / sizeof(block_b[0]);
	for (; block_b < b_end; block_b += 4, block_a += 4) {
		if ((block_a[0] - block_b[0]) | (block_a[1] - block_b[1]) | (block_a[2] - block_b[2]) | (block_a[3] - block_b[3])) {
			if (block_a[0] != block_b[0])
				return block_a[0] - block_b[0];
			if (block_a[1] != block_b[1])
				return block_a[1] - block_b[1];
			if (block_a[2] != block_b[2])
				return block_a[2] - block_b[2];
			if (block_a[3] != block_b[3])
				return block_a[3] - block_b[3];
		}
	}
	return 0;
}

// Assume that block_a and block_b is 8 byte aligned
uint64_t cmp64_rep(const uint64_t *block_a, const uint64_t *block_b) {
	uint64_t diff;
	uint16_t cnt = 512;
	asm("repe; cmpsq" CC_SET(nz)
		: CC_OUT(nz) (diff), "+D" (block_a), "+S" (block_b), "+c" (cnt));
	return diff;
}

/*int fastcmp(const char *block_a, const char *block_b) {
	int ret;
#ifdef __AVX512BW__
	kernel_fpu_begin();
	const __m512i *a = (const __m512i *)block_a;
	const __m512i *b = (const __m512i *)block_b;
	const __m512i *b_end = (const __m512i *)(block_b + BLOCK_SIZE);
	__mmask64 res;
	for (; b < b_end; ++b, ++a) {
		res = _mm512_cmpeq_epi8_mask(_mm512_loadu_si512(a), _mm512_loadu_si512(b));
		if (res != ~(__mmask64)(0)) {
			break;
		}
	}
	kernel_fpu_end();
	if (b == b_end) {
		ret = 0;
	} else {
		int index = __builtin_ctzll(~res);
		ret = *((char *)a + index) - *((char *)b + index);
	}
#elif defined(__AVX2__)
	#ifdef __AVX__
		kernel_fpu_begin();
		const __m256i *a = (const __m256i *)block_a;
		const __m256i *b = (const __m256i *)block_b;
		const __m256i *b_end = (const __m256i *)(block_b + BLOCK_SIZE);
		int res;
		for (; b < b_end; ++b, ++a) {
			__m256i tmp;
			tmp = _mm256_cmpeq_epi8(_mm256_loadu_si256(a), _mm256_loadu_si256(b));
			res = _mm256_movemask_epi8(tmp);
			if (res != ~(int)(0)) {
				break;
			}
		}
		kernel_fpu_end();
		if (b == b_end) {
			ret = 0;
		} else {
			int index = __builtin_ctzll(~res);
			ret = *((char *)a + index) - *((char *)b + index);
		}
	#else
		#define RUN_TRIVIAL
	#endif
#else
	#define RUN_TRIVIAL
#endif

#ifdef RUN_TRIVIAL
	#pragma message "Warning: fastcmp uses trivial compare method."
	size_t i;
	for (i = 0; i < BLOCK_SIZE; ++i) {
		if (block_a[i] != block_b[i]) {
			break;
		}
	}
	ret = block_a[i] - block_b[i];
#endif
	return ret;
}
*/