#include "generic_cache.h"

#include <linux/slab.h>

void generic_cache_init(struct generic_cache *cache,
	struct llist_node *(*allocate)(gfp_t),
	void (*free)(struct llist_node *))
{
	spin_lock_init(&cache->lock);
	init_llist_head(&cache->head);
	cache->allocate = allocate;
	cache->free = free;
	cache->allocated = 0;
}

struct llist_node *generic_cache_alloc(struct generic_cache *cache, gfp_t flags)
{
	struct llist_node *ret;
	spin_lock(&cache->lock);
	if (cache->head.first == NULL) {
		cache->allocated += 1;
		spin_unlock(&cache->lock);
		return cache->allocate(flags);
	}
	ret = cache->head.first;
	cache->head.first = ret->next;
	spin_unlock(&cache->lock);
	return ret;
}

void generic_cache_free(struct generic_cache *cache, struct llist_node *node)
{
	spin_lock(&cache->lock);
	node->next = cache->head.first;
	cache->head.first = node;
	spin_unlock(&cache->lock);
}

// Make sure that there is no other threads accessing it
void generic_cache_destroy(struct generic_cache *cache)
{
	struct llist_node *cur = cache->head.first, *next;
	printk("Generic cache allocated %lu\n", cache->allocated);
	while (cur != NULL) {
		next = cur->next;
		cache->free(cur);
		cur = next;
	}
}
