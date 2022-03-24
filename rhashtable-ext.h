#ifndef __RHASHTABLE_EXT_H
#define __RHASHTABLE_EXT_H

#include <linux/rhashtable.h>

int rhashtable_traverse_multithread(struct rhashtable *ht, int thread_num,
        void (*fn)(void *ptr, void *arg),
        void *(*thread_local_arg_factory)(void *),
        void (*thread_local_arg_recycler)(void *),
        void *arg);

#endif // __RHASHTABLE_EXT_H
