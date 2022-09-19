#include "generic_cache.h"

#include <linux/slab.h>

void generic_cache_init(struct generic_cache *cache, void *(*allocate)(gfp_t),
	void (*free)(void *))
{
	spin_lock_init(&cache->lock);
	cache->head = NULL;
	cache->allocate = allocate;
	cache->free = free;
}

static void **new_obj(struct generic_cache *cache, gfp_t flags)
{
	struct generic_cache_node *node =
		kmalloc(sizeof(struct generic_cache_node), flags);
	if (node == NULL)
		return NULL;
	node->obj = cache->allocate(flags);
	if (node->obj == NULL) {
		kfree(node);
		return NULL;
	}
	return &node->obj;
}

void **generic_cache_alloc(struct generic_cache *cache, gfp_t flags)
{
	void **ret;
	spin_lock(&cache->lock);
	if (cache->head == NULL) {
		spin_unlock(&cache->lock);
		return new_obj(cache, flags);
	}
	ret = &cache->head->obj;
	cache->head = cache->head->next;
	spin_unlock(&cache->lock);
	return ret;
}

void generic_cache_free(struct generic_cache *cache, void **obj_p)
{
	struct generic_cache_node *node;
	if (obj_p == NULL)
		return;
	node = container_of(obj_p, struct generic_cache_node, obj);
	spin_lock(&cache->lock);
	node->next = cache->head;
	cache->head = node;
	spin_unlock(&cache->lock);
}

// Make sure that there is no other threads accessing it
void generic_cache_destroy(struct generic_cache *cache)
{
	struct generic_cache_node *cur = cache->head, *next;
	while (cur != NULL) {
		cache->free(cur->obj);
		next = cur->next;
		kfree(cur);
		cur = next;
	}
}
