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
	size_t len = kfifo_len(q);
	size_t left = kfifo_size(q);
	char *buf = vmalloc(len << 1);
	char *buf2;
	size_t copied;
	int ret;
	if (buf == NULL) {
		ret = -ENOMEM;
		goto err_out0;
	}
	buf2 = vmalloc(len);
	if (buf2 == NULL) {
		ret = -ENOMEM;
		goto err_out1;
	}
	ret = kfifo_init(&tmp, buf, len << 1);
	if (ret)
		goto err_out2;
	while (left) {
		copied = kfifo_out(q, buf2, left);
		BUG_ON(kfifo_in(&tmp, buf, copied) != copied);
		left -= copied;
	}
	vfree(buf2);
	vfree(q->kfifo.data);
	*q = tmp;
	return 0;
err_out2:
	vfree(buf2);
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
