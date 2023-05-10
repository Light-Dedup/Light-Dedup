/*
 * Generic cache.
 *
 * Copyright (c) 2020-2023 Jiansheng Qiu <jianshengqiu.cs@gmail.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef GENERIC_CACHE_H_
#define GENERIC_CACHE_H_

#include <linux/spinlock.h>
#include <linux/llist.h>

struct generic_cache {
	spinlock_t lock;
	struct llist_head head;
	struct llist_node *(*allocate)(gfp_t);
	void (*free)(struct llist_node *);
	size_t allocated;
};

void generic_cache_init(struct generic_cache *cache,
	struct llist_node *(*allocate)(gfp_t),
	void (*free)(struct llist_node *));
struct llist_node *
generic_cache_alloc(struct generic_cache *cache, gfp_t flags);
void generic_cache_free(struct generic_cache *cache, struct llist_node *node);
void generic_cache_destroy(struct generic_cache *cache);

#endif // GENERIC_CACHE_H_
