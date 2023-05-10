/*
 * Joinable wrapper for kthread.
 *
 * Copyright (c) 2020-2023 Jiansheng Qiu <jianshengqiu.cs@gmail.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef __JOINABLE_H
#define __JOINABLE_H

#include <linux/fs.h>
#include <linux/kthread.h>

struct joinable_kthread {
	// The caller should set these
	int (*threadfn)(void *data);
	void *data;
	// The user should not touch these
	struct task_struct *task;
	struct completion entered;
};

int __joinable_kthreadfn(void *data);

// The caller should set t->threadfn and t->data
// TODO: Make this an ordinary function if kthread_create has a version that
// accepts va_list to hide __joinable_kthreadfn
#define joinable_kthread_create(t, namefmt, ...) ({			\
	int ret;							\
	typecheck(struct joinable_kthread *, (t));			\
	init_completion(&(t)->entered);					\
	(t)->task = kthread_create(__joinable_kthreadfn, (t), (namefmt),	\
		__VA_ARGS__);						\
	if (IS_ERR((t)->task))						\
		ret = PTR_ERR((t)->task);					\
	else								\
		ret = 0;						\
	ret;								\
})

static inline void joinable_kthread_bind(struct joinable_kthread *t,
	unsigned int cpu)
{
	kthread_bind(t->task, cpu);
}

static inline int joinable_kthread_stop(struct joinable_kthread *t)
{
	return kthread_stop(t->task);
}

static inline void joinable_kthread_abort(struct joinable_kthread *t)
{
	BUG_ON(joinable_kthread_stop(t) != -EINTR);
}

static inline void joinable_kthread_wake_up(struct joinable_kthread *t)
{
	wake_up_process(t->task);
}

// The caller should make sure that the thread has been waken up.
static inline int __joinable_kthread_join(struct joinable_kthread *t)
{
	wait_for_completion(&t->entered);
	return kthread_stop(t->task);
}

int joinable_kthreads_create(struct joinable_kthread *ts, int num,
	const char *basename);

// The caller should set threadfn and data of ts[0..num]
int joinable_kthreads_run(struct joinable_kthread *ts, int num,
	const char *basename);

// The caller should make sure that the threads has been waken up.
int __joinable_kthreads_join_check_lt_zero(struct joinable_kthread *ts, int num,
	const char *basename);

static inline int joinable_kthreads_run_join_check_lt_zero(
	struct joinable_kthread *ts, int num, const char *basename)
{
	int ret = joinable_kthreads_run(ts, num, basename);
	if (ret < 0)
		return ret;
	return __joinable_kthreads_join_check_lt_zero(ts, num, basename);
}

#endif // __JOINABLE_H
