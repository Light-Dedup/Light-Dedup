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
