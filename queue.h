#ifndef __NOVA_QUEUE_H
#define __NOVA_QUEUE_H

#include <linux/kfifo.h>

// TODO: Implement it with block list.
struct nova_queue {
	struct kfifo q;
};

int nova_queue_init(struct nova_queue *_q, size_t init_sz);
static inline void nova_queue_destroy(struct nova_queue *_q)
{
	struct kfifo *q = &_q->q;
	vfree(q->kfifo.data);
}
int nova_queue_push(struct nova_queue *_q, void *data, size_t len);
size_t nova_queue_pop(struct nova_queue *_q, void *data, size_t len);

#endif // __NOVA_QUEUE_H