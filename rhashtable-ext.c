#include "rhashtable-ext.h"
#include "multithread.h"

#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/random.h>

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



#define HASH_DEFAULT_SIZE	64UL
#define HASH_MIN_SIZE		4U
#define BUCKET_LOCKS_PER_CPU	32UL

union nested_table {
	union nested_table __rcu *table;
	struct rhash_head __rcu *bucket;
};

static u32 head_hashfn(struct rhashtable *ht,
		       const struct bucket_table *tbl,
		       const struct rhash_head *he)
{
	return rht_head_hashfn(ht, tbl, he, ht->p);
}

#ifdef CONFIG_PROVE_LOCKING
#define ASSERT_RHT_MUTEX(HT) BUG_ON(!lockdep_rht_mutex_is_held(HT))

int lockdep_rht_mutex_is_held(struct rhashtable *ht)
{
	return (debug_locks) ? lockdep_is_held(&ht->mutex) : 1;
}
EXPORT_SYMBOL_GPL(lockdep_rht_mutex_is_held);

int lockdep_rht_bucket_is_held(const struct bucket_table *tbl, u32 hash)
{
	spinlock_t *lock = rht_bucket_lock(tbl, hash);

	return (debug_locks) ? lockdep_is_held(lock) : 1;
}
EXPORT_SYMBOL_GPL(lockdep_rht_bucket_is_held);
#else
#define ASSERT_RHT_MUTEX(HT)
#endif

static void nested_table_free(union nested_table *ntbl, unsigned int size)
{
	const unsigned int shift = PAGE_SHIFT - ilog2(sizeof(void *));
	const unsigned int len = 1 << shift;
	unsigned int i;

	ntbl = rcu_dereference_raw(ntbl->table);
	if (!ntbl)
		return;

	if (size > len) {
		size >>= shift;
		for (i = 0; i < len; i++)
			nested_table_free(ntbl + i, size);
	}

	kfree(ntbl);
}

static void nested_bucket_table_free(const struct bucket_table *tbl)
{
	unsigned int size = tbl->size >> tbl->nest;
	unsigned int len = 1 << tbl->nest;
	union nested_table *ntbl;
	unsigned int i;

	ntbl = (union nested_table *)rcu_dereference_raw(tbl->buckets[0]);

	for (i = 0; i < len; i++)
		nested_table_free(ntbl + i, size);

	kfree(ntbl);
}

static void bucket_table_free(const struct bucket_table *tbl)
{
	if (tbl->nest)
		nested_bucket_table_free(tbl);

	free_bucket_spinlocks(tbl->locks);
	kvfree(tbl);
}

static void bucket_table_free_rcu(struct rcu_head *head)
{
	bucket_table_free(container_of(head, struct bucket_table, rcu));
}

static union nested_table *nested_table_alloc(struct rhashtable *ht,
					      union nested_table __rcu **prev,
					      bool leaf)
{
	union nested_table *ntbl;
	int i;

	ntbl = rcu_dereference(*prev);
	if (ntbl)
		return ntbl;

	ntbl = kzalloc(PAGE_SIZE, GFP_ATOMIC);

	if (ntbl && leaf) {
		for (i = 0; i < PAGE_SIZE / sizeof(ntbl[0]); i++)
			INIT_RHT_NULLS_HEAD(ntbl[i].bucket);
	}

	rcu_assign_pointer(*prev, ntbl);

	return ntbl;
}

static struct bucket_table *nested_bucket_table_alloc(struct rhashtable *ht,
						      size_t nbuckets,
						      gfp_t gfp)
{
	const unsigned int shift = PAGE_SHIFT - ilog2(sizeof(void *));
	struct bucket_table *tbl;
	size_t size;

	if (nbuckets < (1 << (shift + 1)))
		return NULL;

	size = sizeof(*tbl) + sizeof(tbl->buckets[0]);

	tbl = kzalloc(size, gfp);
	if (!tbl)
		return NULL;

	if (!nested_table_alloc(ht, (union nested_table __rcu **)tbl->buckets,
				false)) {
		kfree(tbl);
		return NULL;
	}

	tbl->nest = (ilog2(nbuckets) - 1) % shift + 1;

	return tbl;
}

static struct bucket_table *bucket_table_alloc(struct rhashtable *ht,
					       size_t nbuckets,
					       gfp_t gfp)
{
	struct bucket_table *tbl = NULL;
	size_t size, max_locks;
	int i;

	size = sizeof(*tbl) + nbuckets * sizeof(tbl->buckets[0]);
	tbl = kvzalloc(size, gfp);

	size = nbuckets;

	if (tbl == NULL && (gfp & ~__GFP_NOFAIL) != GFP_KERNEL) {
		tbl = nested_bucket_table_alloc(ht, nbuckets, gfp);
		nbuckets = 0;
	}

	if (tbl == NULL)
		return NULL;

	tbl->size = size;

	max_locks = size >> 1;
	if (tbl->nest)
		max_locks = min_t(size_t, max_locks, 1U << tbl->nest);

	if (alloc_bucket_spinlocks(&tbl->locks, &tbl->locks_mask, max_locks,
				   ht->p.locks_mul, gfp) < 0) {
		bucket_table_free(tbl);
		return NULL;
	}

	INIT_LIST_HEAD(&tbl->walkers);

	tbl->hash_rnd = get_random_u32();

	for (i = 0; i < nbuckets; i++)
		INIT_RHT_NULLS_HEAD(tbl->buckets[i]);

	return tbl;
}

static struct bucket_table *rhashtable_last_table(struct rhashtable *ht,
						  struct bucket_table *tbl)
{
	struct bucket_table *new_tbl;

	do {
		new_tbl = tbl;
		tbl = rht_dereference_rcu(tbl->future_tbl, ht);
	} while (tbl);

	return new_tbl;
}

static int rhashtable_rehash_one(struct rhashtable *ht, unsigned int old_hash)
{
	struct bucket_table *old_tbl = rht_dereference(ht->tbl, ht);
	struct bucket_table *new_tbl = rhashtable_last_table(ht, old_tbl);
	struct rhash_head __rcu **pprev = rht_bucket_var(old_tbl, old_hash);
	int err = -EAGAIN;
	struct rhash_head *head, *next, *entry;
	spinlock_t *new_bucket_lock;
	unsigned int new_hash;

	if (new_tbl->nest)
		goto out;

	err = -ENOENT;

	rht_for_each(entry, old_tbl, old_hash) {
		err = 0;
		next = rht_dereference_bucket(entry->next, old_tbl, old_hash);

		if (rht_is_a_nulls(next))
			break;

		pprev = &entry->next;
	}

	if (err)
		goto out;

	new_hash = head_hashfn(ht, new_tbl, entry);

	new_bucket_lock = rht_bucket_lock(new_tbl, new_hash);

	spin_lock_nested(new_bucket_lock, SINGLE_DEPTH_NESTING);
	head = rht_dereference_bucket(new_tbl->buckets[new_hash],
				      new_tbl, new_hash);

	RCU_INIT_POINTER(entry->next, head);

	rcu_assign_pointer(new_tbl->buckets[new_hash], entry);
	spin_unlock(new_bucket_lock);

	rcu_assign_pointer(*pprev, next);

out:
	return err;
}

static int rhashtable_rehash_chain(struct rhashtable *ht,
				    unsigned int old_hash)
{
	struct bucket_table *old_tbl = rht_dereference(ht->tbl, ht);
	spinlock_t *old_bucket_lock;
	int err;

	old_bucket_lock = rht_bucket_lock(old_tbl, old_hash);

	spin_lock_bh(old_bucket_lock);
	while (!(err = rhashtable_rehash_one(ht, old_hash)))
		;

	if (err == -ENOENT) {
		old_tbl->rehash++;
		err = 0;
	}
	spin_unlock_bh(old_bucket_lock);

	return err;
}

static int rhashtable_rehash_attach(struct rhashtable *ht,
				    struct bucket_table *old_tbl,
				    struct bucket_table *new_tbl)
{
	/* Make insertions go into the new, empty table right away. Deletions
	 * and lookups will be attempted in both tables until we synchronize.
	 * As cmpxchg() provides strong barriers, we do not need
	 * rcu_assign_pointer().
	 */

	if (cmpxchg(&old_tbl->future_tbl, NULL, new_tbl) != NULL)
		return -EEXIST;

	return 0;
}

static int rhashtable_rehash_table(struct rhashtable *ht)
{
	struct bucket_table *old_tbl = rht_dereference(ht->tbl, ht);
	struct bucket_table *new_tbl;
	struct rhashtable_walker *walker;
	unsigned int old_hash;
	int err;

	new_tbl = rht_dereference(old_tbl->future_tbl, ht);
	if (!new_tbl)
		return 0;

	for (old_hash = 0; old_hash < old_tbl->size; old_hash++) {
		err = rhashtable_rehash_chain(ht, old_hash);
		if (err)
			return err;
		cond_resched();
	}

	/* Publish the new table pointer. */
	rcu_assign_pointer(ht->tbl, new_tbl);

	spin_lock(&ht->lock);
	list_for_each_entry(walker, &old_tbl->walkers, list)
		walker->tbl = NULL;
	spin_unlock(&ht->lock);

	/* Wait for readers. All new readers will see the new
	 * table, and thus no references to the old table will
	 * remain.
	 */
	call_rcu(&old_tbl->rcu, bucket_table_free_rcu);

	return rht_dereference(new_tbl->future_tbl, ht) ? -EAGAIN : 0;
}

static int rhashtable_rehash_alloc(struct rhashtable *ht,
				   struct bucket_table *old_tbl,
				   unsigned int size)
{
	struct bucket_table *new_tbl;
	int err;

	ASSERT_RHT_MUTEX(ht);

	new_tbl = bucket_table_alloc(ht, size, GFP_KERNEL);
	if (new_tbl == NULL)
		return -ENOMEM;

	err = rhashtable_rehash_attach(ht, old_tbl, new_tbl);
	if (err)
		bucket_table_free(new_tbl);

	return err;
}

/**
 * rhashtable_shrink - Shrink hash table while allowing concurrent lookups
 * @ht:		the hash table to shrink
 *
 * This function shrinks the hash table to fit, i.e., the smallest
 * size would not cause it to expand right away automatically.
 *
 * The caller must ensure that no concurrent resizing occurs by holding
 * ht->mutex.
 *
 * The caller must ensure that no concurrent table mutations take place.
 * It is however valid to have concurrent lookups if they are RCU protected.
 *
 * It is valid to have concurrent insertions and deletions protected by per
 * bucket locks or concurrent RCU protected lookups and traversals.
 */
static int rhashtable_shrink(struct rhashtable *ht)
{
	struct bucket_table *old_tbl = rht_dereference(ht->tbl, ht);
	unsigned int nelems = atomic_read(&ht->nelems);
	unsigned int size = 0;

	if (nelems)
		size = roundup_pow_of_two(nelems * 3 / 2);
	if (size < ht->p.min_size)
		size = ht->p.min_size;

	if (old_tbl->size <= size)
		return 0;

	if (rht_dereference(old_tbl->future_tbl, ht))
		return -EEXIST;

	return rhashtable_rehash_alloc(ht, old_tbl, size);
}

static void rht_deferred_worker(struct work_struct *work)
{
	struct rhashtable *ht;
	struct bucket_table *tbl;
	int err = 0;

	ht = container_of(work, struct rhashtable, run_work);
	mutex_lock(&ht->mutex);

	tbl = rht_dereference(ht->tbl, ht);
	tbl = rhashtable_last_table(ht, tbl);

	if (rht_grow_above_75(ht, tbl))
		err = rhashtable_rehash_alloc(ht, tbl, tbl->size * 2);
	else if (ht->p.automatic_shrinking && rht_shrink_below_30(ht, tbl))
		err = rhashtable_shrink(ht);
	else if (tbl->nest)
		err = rhashtable_rehash_alloc(ht, tbl, tbl->size);

	if (!err || err == -EEXIST) {
		int nerr;

		nerr = rhashtable_rehash_table(ht);
		err = err ?: nerr;
	}

	mutex_unlock(&ht->mutex);

	if (err)
		schedule_work(&ht->run_work);
}

static size_t rounded_hashtable_size_large_nelem_hint(
	const struct rhashtable_params *params, size_t nelem_hint)
{
	size_t retsize;

	if (nelem_hint)
		retsize = max(roundup_pow_of_two(nelem_hint * 4 / 3),
			      (unsigned long)params->min_size);
	else
		retsize = max(HASH_DEFAULT_SIZE,
			      (unsigned long)params->min_size);

	return retsize;
}

static u32 rhashtable_jhash2(const void *key, u32 length, u32 seed)
{
	return jhash2(key, length, seed);
}

int rhashtable_init_large(struct rhashtable *ht, size_t nelem_hint,
		    const struct rhashtable_params *params)
{
	struct bucket_table *tbl;
	size_t size;

	if ((!params->key_len && !params->obj_hashfn) ||
	    (params->obj_hashfn && !params->obj_cmpfn))
		return -EINVAL;

	memset(ht, 0, sizeof(*ht));
	mutex_init(&ht->mutex);
	spin_lock_init(&ht->lock);
	memcpy(&ht->p, params, sizeof(*params));

	if (params->min_size)
		ht->p.min_size = roundup_pow_of_two(params->min_size);

	/* Cap total entries at 2^31 to avoid nelems overflow. */
	ht->max_elems = 1u << 31;

	if (params->max_size) {
		ht->p.max_size = rounddown_pow_of_two(params->max_size);
		if (ht->p.max_size < ht->max_elems / 2)
			ht->max_elems = ht->p.max_size * 2;
	}

	ht->p.min_size = max_t(u16, ht->p.min_size, HASH_MIN_SIZE);

	// Modified
	size = rounded_hashtable_size_large_nelem_hint(&ht->p, nelem_hint);

	if (params->locks_mul)
		ht->p.locks_mul = roundup_pow_of_two(params->locks_mul);
	else
		ht->p.locks_mul = BUCKET_LOCKS_PER_CPU;

	ht->key_len = ht->p.key_len;
	if (!params->hashfn) {
		ht->p.hashfn = jhash;

		if (!(ht->key_len & (sizeof(u32) - 1))) {
			ht->key_len /= sizeof(u32);
			ht->p.hashfn = rhashtable_jhash2;
		}
	}

	/*
	 * This is api initialization and thus we need to guarantee the
	 * initial rhashtable allocation. Upon failure, retry with the
	 * smallest possible size with __GFP_NOFAIL semantics.
	 */
	tbl = bucket_table_alloc(ht, size, GFP_KERNEL);
	if (unlikely(tbl == NULL)) {
		size = max_t(u16, ht->p.min_size, HASH_MIN_SIZE);
		tbl = bucket_table_alloc(ht, size, GFP_KERNEL | __GFP_NOFAIL);
	}

	atomic_set(&ht->nelems, 0);

	RCU_INIT_POINTER(ht->tbl, tbl);

	INIT_WORK(&ht->run_work, rht_deferred_worker);

	return 0;
}
