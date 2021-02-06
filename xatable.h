#ifndef __XATABLE_H
#define __XATABLE_H

#include <linux/xarray.h>

struct xatable {
	struct xarray *xa;
	unsigned long num_bit;
};

struct xatable_state {
	unsigned long which;
	struct xa_state xa_state;
};

// Multithread traverse is preferred.
#if 0
#define xatable_for_each(xat, which, inner_index, entry)	\
	for (which = 0; which < xat->num; ++which)		\
		xa_for_each(xat->xa + which, inner_index, entry)
#endif

int xatable_init(struct xatable *xat, unsigned long num_bit);
void xatable_destroy(struct xatable *xat);
void *xatable_store(struct xatable *xat, unsigned long index, void *entry, gfp_t gfp);
void *xatable_load(struct xatable *xat, unsigned long index);

#endif // __XATABLE_H