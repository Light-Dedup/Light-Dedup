#ifndef __NOVA_QUEUE_H
#define __NOVA_QUEUE_H

#include <linux/gfp.h>

#define NOVA_QUEUE_BLOCK_ORDER 0
#define NOVA_QUEUE_BLOCK_CAP (((1 << NOVA_QUEUE_BLOCK_ORDER) * PAGE_SIZE - \
	sizeof(struct nova_queue_block *)) / sizeof(unsigned long))

struct nova_queue_block {
	unsigned long buf[NOVA_QUEUE_BLOCK_CAP];
	struct nova_queue_block *next;
};
_Static_assert(sizeof(unsigned long) == sizeof(struct nova_queue_block *),
	"sizeof unsigned long != sizeof pointer!");

struct nova_queue {
	struct nova_queue_block *head, *tail;
	size_t front, back;
};

int nova_queue_init(struct nova_queue *q, gfp_t gfp);
static inline bool nova_queue_is_empty(struct nova_queue *q)
{
	return q->head == q->tail && q->front == q->back;
}
void nova_queue_destroy(struct nova_queue *_q);
int nova_queue_push_ul(struct nova_queue *q, unsigned long data, gfp_t gfp);
unsigned long nova_queue_pop_ul(struct nova_queue *q);

#endif // __NOVA_QUEUE_H