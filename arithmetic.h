#ifndef __ARITHMETIC_H
#define __ARITHMETIC_H

static inline unsigned long ceil_log_2(unsigned long x)
{
	unsigned long i = 0;
	while ((1UL << i) < x)
		++i;
	return i;
}
static inline unsigned long min_ul(unsigned long a, unsigned long b)
{
	return a < b ? a : b;
}
static inline unsigned long max_ul(unsigned long a, unsigned long b)
{
	return a < b ? b : a;
}

#endif // __ARITHMETIC_H