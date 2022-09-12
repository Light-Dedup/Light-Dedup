#ifndef __ARITHMETIC_H
#define __ARITHMETIC_H

#include <linux/types.h>

static inline uint32_t lowbit_u32(uint32_t x) {
	return x & -x;
}

static inline bool is_pow_of_2_u32(uint32_t x) {
	return lowbit_u32(x) == x;
}

static inline unsigned long ceil_log_2(unsigned long x)
{
	unsigned long i = 0;
	while ((1UL << i) < x)
		++i;
	return i;
}

static inline uint32_t ceil_div_u32(uint32_t a, uint32_t b)
{
	return (a + b - 1) / b;
}
static inline unsigned long ceil_div_ul(unsigned long a, unsigned long b)
{
	return (a + b - 1) / b;
}

static inline unsigned long min_ul(unsigned long a, unsigned long b)
{
	return a < b ? a : b;
}
static inline size_t min_usize(size_t a, size_t b)
{
	return a < b ? a : b;
}
static inline uint16_t min_u16(uint16_t a, uint16_t b)
{
	return a < b ? a : b;
}
static inline uint32_t min_u32(uint32_t a, uint32_t b)
{
	return a < b ? a : b;
}

static inline unsigned long max_ul(unsigned long a, unsigned long b)
{
	return a < b ? b : a;
}

#endif // __ARITHMETIC_H