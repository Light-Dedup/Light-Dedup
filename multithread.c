#include "multithread.h"

// static inline struct completion *
// get_completion(void *para, size_t para_len, unsigned long i)
// {
//     return (struct completion *)((char *)para + para_len * i);
// }
int __run_and_stop_kthreads(
	struct task_struct **tasks, void *__para, size_t para_len,
	size_t entered_offset,
	unsigned long thread_num, unsigned long created)
{
	unsigned long i;
	char *para;
	int ret = 0, ret2;

	if (created == thread_num) {
		for (i = 0; i < thread_num; ++i)
			wake_up_process(tasks[i]);
		for (i = 0, para = (char *)__para + entered_offset;
			i < thread_num;
			++i, para += para_len
		) {
			wait_for_completion((struct completion *)para);
			ret2 = kthread_stop(tasks[i]);
			if (ret2 < 0) {
				printk("kthread_stop %lu return %d\n", i, ret2);
				ret = ret2;
			}
		}
	} else {
		thread_num = created;
		for (i = 0; i < thread_num; ++i) {
			ret2 = kthread_stop(tasks[i]);
			if (ret2 < 0 && ret2 != -EINTR) {
				printk("kthread_stop %lu return %d\n", i, ret2);
				ret = ret2;
			}
		}
	}
	return ret;
}
