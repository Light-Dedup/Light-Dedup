#include "queue.h"

static inline struct nova_queue_block *
new_block(gfp_t gfp)
{
	return (struct nova_queue_block *)
		__get_free_pages(gfp, NOVA_QUEUE_BLOCK_ORDER);
}
static inline void
free_block(struct nova_queue_block *block)
{
	free_pages((unsigned long)block, NOVA_QUEUE_BLOCK_ORDER);
}
int nova_queue_init(struct nova_queue *q, gfp_t gfp)
{
	q->head = q->tail = new_block(gfp);
	if (q->head == NULL)
		return -ENOMEM;
	q->front = q->back = 0;
	return 0;
}
void nova_queue_destroy(struct nova_queue *q)
{
	struct nova_queue_block *cur, *next = q->head;
	do {
		cur = next;
		next = cur->next;
		free_block(cur);
	} while (cur != q->tail);
}
int nova_queue_push_ul(struct nova_queue *q, unsigned long data, gfp_t gfp)
{
	if (unlikely(q->back == NOVA_QUEUE_BLOCK_CAP)) {
		q->tail->next = new_block(gfp);
		if (q->tail->next == NULL)
			return -ENOMEM;
		q->tail = q->tail->next;
		q->back = 0;
	}
	q->tail->buf[q->back++] = data;
	return 0;
}
// A push after a pop has to succeed.
unsigned long nova_queue_pop_ul(struct nova_queue *q)
{
	if (unlikely(q->front == NOVA_QUEUE_BLOCK_CAP)) {
		struct nova_queue_block *next = q->head->next;
		free_block(q->head);
		q->head = next;
		q->front = 0;
	}
	return q->head->buf[q->front++];
}
