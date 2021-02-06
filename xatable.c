#include "xatable.h"
#include <linux/slab.h>

int xatable_init(struct xatable *xat, unsigned long num_bit)
{
	unsigned long i, num = 1UL << num_bit;
	xat->xa = kmalloc(sizeof(struct xarray) * num, GFP_KERNEL);
	if (xat->xa == NULL)
		return -ENOMEM;
	for (i = 0; i < num; ++i)
		xa_init(xat->xa + i);
	xat->num_bit = num_bit;
	return 0;
}
void xatable_destroy(struct xatable *xat)
{
	unsigned long i, num;
	if (xat->xa == NULL)
		return;
	num = 1UL << xat->num_bit;
	for (i = 0; i < num; ++i)
		xa_destroy(xat->xa + i);
}

void *xatable_store(struct xatable *xat, unsigned long index, void *entry, gfp_t gfp)
{
	unsigned long which = index & ((1UL << xat->num_bit) - 1);
	index >>= xat->num_bit;
	return xa_store(xat->xa + which, index, entry, gfp);
}

void *xatable_load(struct xatable *xat, unsigned long index)
{
	unsigned long which = index & ((1UL << xat->num_bit) - 1);
	index >>= xat->num_bit;
	return xa_load(xat->xa + which, index);
}
