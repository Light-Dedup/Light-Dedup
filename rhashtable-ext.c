#include "rhashtable-ext.h"
#include "multithread.h"

#include <linux/slab.h>

// #define static _Static_assert(1, "2333");

static void rhashtable_operate_one(struct rhashtable *ht, struct rhash_head *obj,
	void (*fn)(void *ptr, void *arg), void *arg)
{
	struct rhlist_head *list;

	if (!ht->rhlist) {
		fn(rht_obj(ht, obj), arg);
		return;
	}

	list = container_of(obj, struct rhlist_head, rhead);
	do {
		obj = &list->rhead;
		list = rht_dereference(list->next, ht);
		fn(rht_obj(ht, obj), arg);
	} while (list);
}

static void __rhashtable_traverse_func(struct rhashtable *ht,
        struct bucket_table *tbl, unsigned int start, unsigned int end,
        void (*fn)(void *ptr, void *arg), void *arg)
{
	unsigned int i;
	for (i = start; i < end; i++) {
		struct rhash_head *pos, *next;

		cond_resched();
		pos = rht_dereference(*rht_bucket(tbl, i), ht);
		next = !rht_is_a_nulls(pos) ?
			rht_dereference(pos->next, ht) : NULL;
		while (!rht_is_a_nulls(pos)) {
			rhashtable_operate_one(ht, pos, fn, arg);
			pos = next,
			next = !rht_is_a_nulls(pos) ?
				rht_dereference(pos->next, ht) : NULL;
		}
	}
}

struct __rhashtable_traverse_para {
	struct completion entered;
        struct rhashtable *ht;
        struct bucket_table *tbl;
	unsigned int start, end;
        void (*fn)(void *ptr, void *arg);
        void *arg;
};
static int rhashtable_traverse_func(void *__para)
{
	struct __rhashtable_traverse_para *para =
                (struct __rhashtable_traverse_para *)__para;
	complete(&para->entered);
	__rhashtable_traverse_func(para->ht, para->tbl, para->start, para->end,
		para->fn, para->arg);
	// printk("%s waiting for kthread_stop\n", __func__);
	/* Wait for kthread_stop */
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	return 0;
}
static int __rhashtable_traverse_multithread(struct rhashtable *ht,
        struct bucket_table *tbl, int thread_num,
        void (*fn)(void *ptr, void *arg),
        void *(*thread_local_arg_factory)(void *factory_arg),
        void (*thread_local_arg_recycler)(void *),
        void *arg)
{
	unsigned int per_thread;
	struct __rhashtable_traverse_para *para = NULL;
	struct task_struct **tasks = NULL;
	unsigned int i = 0, base;
	int ret = 0, ret2;

	per_thread = (tbl->size + thread_num - 1) / thread_num;
	thread_num = (tbl->size + per_thread - 1) / per_thread;
	printk("Traversing rhashtable using %d threads\n", thread_num);
	para = kmalloc(thread_num * sizeof(struct __rhashtable_traverse_para),
                GFP_KERNEL);
	if (para == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	tasks = kmalloc(thread_num * sizeof(struct task_struct *), GFP_KERNEL);
	if (tasks == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	base = 0;
	for (i = 0; i < thread_num; ++i) {
		init_completion(&para[i].entered);
		para[i].ht = ht;
		para[i].tbl = tbl;
		para[i].start = base;
		base += per_thread;
		para[i].end = base < tbl->size ? base : tbl->size;
                para[i].fn = fn;
                if (thread_local_arg_factory) {
                        para[i].arg = thread_local_arg_factory(arg);
                } else {
                        para[i].arg = arg;
                }
		tasks[i] = kthread_create(rhashtable_traverse_func, para + i,
			"rhashtable_traverse_func_%u", i);
		if (IS_ERR(tasks[i])) {
			ret = PTR_ERR(tasks[i]);
			printk("%s: kthread_create %u return %d\n",
				__func__, i, ret);
			break;
		}
	}
	ret2 = run_and_stop_kthreads(tasks, para, thread_num, i);
	if (ret2 < 0)
		ret = ret2;
out:
	if (para) {
                if (thread_local_arg_recycler) {
                        while (i) {
                                i--;
                                thread_local_arg_recycler(para[i].arg);
                        }
                }
		kfree(para);
        }
	if (tasks)
		kfree(tasks);
	return ret;
}
int rhashtable_traverse_multithread(struct rhashtable *ht, int thread_num,
        void (*fn)(void *ptr, void *arg),
        void *(*thread_local_arg_factory)(void *),
        void (*thread_local_arg_recycler)(void *),
        void *arg)
{
	struct bucket_table *tbl;
        int ret;

	cancel_work_sync(&ht->run_work);
	mutex_lock(&ht->mutex);
	tbl = rht_dereference(ht->tbl, ht);
        do {
                ret = __rhashtable_traverse_multithread(ht, tbl, thread_num, fn,
                        thread_local_arg_factory, thread_local_arg_recycler,
                        arg);
                if (ret < 0) {
                        break;
                }
                tbl = rht_dereference(tbl->future_tbl, ht);
        } while (tbl);
	mutex_unlock(&ht->mutex);
        return ret;
}
