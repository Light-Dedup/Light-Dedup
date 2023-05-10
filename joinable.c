#include "joinable.h"

int __joinable_kthreadfn(void *data)
{
	struct joinable_kthread *t = (struct joinable_kthread *)data;
	int ret;
	complete(&t->entered);
	ret = t->threadfn(t->data);
	/* Wait for kthread_stop */
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	return ret;
}

static void joinable_kthreads_abort(struct joinable_kthread *ts, int num)
{
	int i;
	for (i = 0; i < num; ++i)
		joinable_kthread_abort(ts + i);
}

int joinable_kthreads_create(struct joinable_kthread *ts, int num,
	const char *basename)
{
	int i, ret;
	for (i = 0; i < num; ++i) {
		ret = joinable_kthread_create(ts + i, "%s%d", basename, num);
		if (ret < 0) {
			joinable_kthreads_abort(ts, num);
			return ret;
		}
	}
	return 0;
}

static void joinable_kthreads_wake_up(struct joinable_kthread *ts, int num)
{
	int i;
	for (i = 0; i < num; ++i)
		joinable_kthread_wake_up(ts + i);
}

int joinable_kthreads_run(struct joinable_kthread *ts, int num,
	const char *basename)
{
	int ret = joinable_kthreads_create(ts, num, basename);
	if (ret < 0)
		return ret;
	joinable_kthreads_wake_up(ts, num);
	return 0;
}

int __joinable_kthreads_join_check_lt_zero(struct joinable_kthread *ts, int num,
	const char *basename)
{
	int i, ret = 0, ret2;
	for (i = 0; i < num; ++i) {
		ret2 = __joinable_kthread_join(ts + i);
		if (ret2 < 0) {
			printk("%s%d returns %d\n", basename, i, ret2);
			ret = ret2;
		}
	}
	return ret;
}
