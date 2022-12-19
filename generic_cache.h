#ifndef GENERIC_CACHE_H_
#define GENERIC_CACHE_H_

#include <linux/spinlock.h>

struct generic_cache_node {
	void *obj;
	struct generic_cache_node *next;
};

struct generic_cache {
	spinlock_t lock;
	struct generic_cache_node *head;
	void *(*allocate)(gfp_t);
	void (*free)(void *);
	size_t allocated;
};

void generic_cache_init(struct generic_cache *cache, void *(*allocate)(gfp_t),
	void (*free)(void *));
void **generic_cache_alloc(struct generic_cache *cache, gfp_t flags);
void generic_cache_free(struct generic_cache *cache, void **obj_p);
void generic_cache_destroy(struct generic_cache *cache);

#endif // GENERIC_CACHE_H_
