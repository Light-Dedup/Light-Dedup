#include "xatable.h"
#include <linux/slab.h>

#include "stats.h"

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
	INIT_TIMING(xatable_store_time);
	void *ret;

	NOVA_START_TIMING(xatable_store_t, xatable_store_time);
	index >>= xat->num_bit;
	ret = xa_store(xat->xa + which, index, entry, gfp);
	NOVA_END_TIMING(xatable_store_t, xatable_store_time);
	return ret;
}

void *xatable_load(struct xatable *xat, unsigned long index)
{
	unsigned long which = index & ((1UL << xat->num_bit) - 1);
	INIT_TIMING(xatable_load_time);
	void *ret;

	NOVA_START_TIMING(xatable_load_t, xatable_load_time);
	index >>= xat->num_bit;
	ret = xa_load(xat->xa + which, index);
	NOVA_END_TIMING(xatable_load_t, xatable_load_time);
	return ret;
}
