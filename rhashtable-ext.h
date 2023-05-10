/*
 * Extensions for rhashtable.
 *
 * Copyright (c) 2022 Jiansheng Qiu <jianshengqiu.cs@gmail.com>
 * Copyright (c) 2015 Herbert Xu <herbert@gondor.apana.org.au>
 * Copyright (c) 2014-2015 Thomas Graf <tgraf@suug.ch>
 * Copyright (c) 2008-2014 Patrick McHardy <kaber@trash.net>
 *
 * Code partially derived from nft_hash
 * Rewritten with rehash code from br_multicast plus single list
 * pointer as suggested by Josh Triplett
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __RHASHTABLE_EXT_H
#define __RHASHTABLE_EXT_H

#include <linux/rhashtable.h>

int rhashtable_traverse_multithread(struct rhashtable *ht, int thread_num,
        void (*fn)(void *ptr, void *arg),
        void (*fn_worker_init)(void *arg),
	void (*fn_worker_finish)(void *arg),
        void *(*thread_local_arg_factory)(void *),
        void (*thread_local_arg_recycler)(void *),
        void *arg);

int rhashtable_init_large(struct rhashtable *ht, size_t nelem_hint,
		    const struct rhashtable_params *params);

void rhashtable_free_and_destroy_multithread(struct rhashtable *ht,
	void (*free_fn)(void *ptr, void *arg), void *arg, int thread_num);

#endif // __RHASHTABLE_EXT_H
