#include "queue.h"

int nova_queue_init(struct nova_queue *_q, size_t init_sz)
{
	struct kfifo *q = &_q->q;
	char *buf = vmalloc(init_sz);
	int ret;
	if (buf == NULL)
		return -ENOMEM;
	ret = kfifo_init(q, buf, init_sz);
	if (ret) {
		vfree(buf);
		return ret;
	}
	return 0;
}
static int
nova_queue_expand(struct kfifo *q)
{
	struct kfifo tmp;
	size_t size = kfifo_size(q);
	size_t left = kfifo_len(q);
	char *buf = vmalloc(size << 1);
	unsigned long buf2;
	size_t copied;
	int ret;
	if (buf == NULL) {
		ret = -ENOMEM;
		goto err_out0;
	}
	ret = kfifo_init(&tmp, buf, size << 1);
	if (ret)
		goto err_out1;
	while (left) {
		copied = kfifo_out(q, &buf2, sizeof(buf2));
		BUG_ON(kfifo_in(&tmp, &buf2, sizeof(buf2)) != copied);
		left -= copied;
	}
	vfree(q->kfifo.data);
	*q = tmp;
	return 0;
err_out1:
	vfree(buf);
err_out0:
	return ret;
}
int nova_queue_push(struct nova_queue *_q, void *data, size_t len)
{
	struct kfifo *q = &_q->q;
	size_t copied = kfifo_in(q, data, len);
	int ret;
	// printk("%s: %lu\n", __func__, *(unsigned long *)data);
	if (copied == len) {
		return 0;
	}
	BUG_ON(copied != 0);
	ret = nova_queue_expand(q);
	if (ret)
		return ret;
	BUG_ON(kfifo_in(q, data, len) != len);
	return 0;
}
// A push after a pop has to succeed.
size_t nova_queue_pop(struct nova_queue *_q, void *data, size_t len)
{
	struct kfifo *q = &_q->q;
	return kfifo_out(q, data, len);
}
