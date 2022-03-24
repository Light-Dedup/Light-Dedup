#ifndef __MULTITHREAD_H
#define __MULTITHREAD_H

#include <linux/fs.h>
#include <linux/kthread.h>

int __run_and_stop_kthreads(
	struct task_struct **tasks, void *__para, size_t para_len,
	size_t entered_offset,
	unsigned long thread_num, unsigned long created);

#define run_and_stop_kthreads(tasks, para, thread_num, created)	\
	__run_and_stop_kthreads(tasks, para, sizeof(para[0]),	\
		offsetof(typeof(para[0]), entered),			\
		thread_num, created)

#endif // __MULTITHREAD_H