#include "dedup.h"
#include "inode.h"
#include "nova.h"

/******************** FACT DRAM data structure *****************/
struct DeNOVA_bm *FACT_free_list; // For allocating new  indirect access area

/******** EMULATE **************/
void nova_dedup_read_emulate(unsigned long size)
{
    // int i;
    // volatile int emul=0;
    // unsigned int emulator_value=size/4096;
    // for(i=0;i<emulator_value*EMULATION_READ_CYCLE;i++){
    // 	emul=emul+i;
    // }
}

/******************** DEDUP QUEUE ********************/
struct nova_dedup_queue dqueue;

// Initialize Dedup Queue
int nova_dedup_queue_init(void)
{
    INIT_LIST_HEAD(&dqueue.head.list);
    mutex_init(&dqueue.lock);
    dqueue.head.write_entry_address = 0;
    return 0;
}

// Insert Write Entries to Dedup Queue
int nova_dedup_queue_push(u64 new_address, u64 target_inode_number)
{
    struct nova_dedup_queue_entry *new_data;
    // INIT_TIMING(start_time);
    // getrawmonotonic(&start_time);

    mutex_lock(&dqueue.lock);
    new_data = kmalloc(sizeof(struct nova_dedup_queue_entry), GFP_KERNEL);
    list_add_tail(&new_data->list, &dqueue.head.list);
    new_data->write_entry_address = new_address;
    new_data->target_inode_number = target_inode_number;
    // new_data->start_sec = start_time.tv_sec;
    // new_data->start_nsec = start_time.tv_nsec;
    // printk("Insert time well inserted: %lu sec %lu nsec\n",new_data->start_time.tv_sec,new_data->start_time.tv_nsec);
    mutex_unlock(&dqueue.lock);

    // printk("dqueue-PUSH(Write Entry Address: %llu, Inode Number: %llu)\n",new_address,target_inode_number);
    return 0;
}

// Get next write entry to dedup
u64 nova_dedup_queue_get_next_entry(u64 *target_inode_number)
{
    struct nova_dedup_queue_entry *ptr;
    // INIT_TIMING(end_time);
    u64 ret = 0;
    // u64 start_time_sec;
    // u64 start_time_nsec;
    u64 result = 0;
    // getrawmonotonic(&end_time);
    // result = end_time.tv_nsec + end_time.tv_sec*1000000000;

    mutex_lock(&dqueue.lock);

    if (!list_empty(&dqueue.head.list)) {
        ptr = list_entry(dqueue.head.list.next, struct nova_dedup_queue_entry, list);

        ret = ptr->write_entry_address;
        *target_inode_number = ptr->target_inode_number;
        // start_time_sec = ptr->start_sec;
        // start_time_nsec = ptr->start_nsec;
        list_del(dqueue.head.list.next);
        kfree(ptr);

        // result = result - start_time_nsec - start_time_sec*1000000000;
        // printk("%lu sec %ld nsec\n",result/1000000000,result%1000000000);
        // printk("dqueue-POP(Write Entry Address: %llu, Inode Number: %llu)\n",ret,*target_inode_number);
    }
    mutex_unlock(&dqueue.lock);

    return ret;
}

/******************** SHA1 ********************/
static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
    struct sdesc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    sdesc->shash.flags = 0x0;
    return sdesc;
}
static int calc_hash(struct crypto_shash *alg,
                     const unsigned char *data, unsigned int datalen,
                     unsigned char *digest)
{
    struct sdesc *sdesc;
    int ret;
    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc)) {
        pr_info("can't alloc sdesc\n");
        return PTR_ERR(sdesc);
    }
    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    kfree(sdesc);
    return ret;
}
int nova_dedup_fingerprint(int interval, unsigned char *datapage, unsigned char *ret_fingerprint)
{
    struct crypto_shash *alg;
    char *hash_alg_name = "sha1";
    int ret;
    INIT_TIMING(t0);
    INIT_TIMING(t1);

    getrawmonotonic(&t0);
    alg = crypto_alloc_shash(hash_alg_name, 0, 0);
    if (IS_ERR(alg)) {
        pr_info("can't alloc alg %s\n", hash_alg_name);
        return PTR_ERR(alg);
    }
    ret = calc_hash(alg, datapage, DATABLOCK_SIZE, ret_fingerprint);
    crypto_free_shash(alg);

    getrawmonotonic(&t1);
    printk("%d: %lu sec %lu nsec\n", interval, t1.tv_sec - t0.tv_sec, t1.tv_nsec - t0.tv_nsec);
    return ret;
}

int nova_dedup_compare_fingerprint(unsigned char *a, unsigned char *b)
{
    int ret = 0;
    int i;
    for (i = 0; i < FINGERPRINT_SIZE; i++) {
        if (a[i] != b[i])
            ret = 1;
    }
    return ret;
}

int nova_dedup_copy_fingerprint(unsigned char *src, unsigned char *dst)
{
    int i;
    for (i = 0; i < FINGERPRINT_SIZE; i++)
        dst[i] = src[i];
    return 0;
}

/******************** Check Integrity of Inode, Write Entry, Data page ********************/
// Cross check if 'Inode', 'WriteEntry', 'Datapage' was invalidated
// Return 1 if Inode-writeentry-datapage is all valid
int nova_dedup_crosscheck(struct nova_file_write_entry *entry, struct nova_inode_info_header *sih, unsigned long pgoff)
{
    struct nova_file_write_entry *referenced_entry;
    void **pentry;
    pentry = radix_tree_lookup_slot(&sih->tree, pgoff);
    if (!pentry) // Entry has been deleted
        return 0;
    referenced_entry = radix_tree_deref_slot(pentry);

    if (referenced_entry == entry) // Entry has been modified
        return 1;
    else {
        // printk("NOVA ERROR: Invalid DataPage Detected\n");
        return 0;
    }
}

/******************** FACT ********************/

// Clear FACT, set FACT_free_table, FACT locks
int nova_dedup_FACT_init(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    unsigned long i;
    unsigned long start = 0;
    unsigned long end = FACT_TABLE_INDEX_MAX(sbi);
    unsigned long irq_flags = 0;
    unsigned long target_index;
    struct fact_entry *target_entry;

    unsigned char fill[64];
    memset(fill, 0, 64);

    FACT_free_list = kzalloc(sizeof(struct DeNOVA_bm), GFP_KERNEL);
    FACT_free_list->bitmap_size = FACT_TABLE_INDEX_MAX(sbi);
    FACT_free_list->bitmap = kvzalloc(FACT_TABLE_INDEX_MAX(sbi), GFP_KERNEL);

    for (i = start; i <= end; i++) {
        target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + i * NOVA_FACT_ENTRY_SIZE;
        target_entry = (struct fact_entry *)nova_get_block(sb, target_index);

        nova_memunlock_range(sb, target_entry, 64, &irq_flags);
        memcpy_to_pmem_nocache(target_entry, &fill, 64);
        nova_memlock_range(sb, target_entry, 64, &irq_flags);
    }
    return 1;
}

// For debugging, show how much FACT is utilized
int nova_dedup_FACT_utilize(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    unsigned long i;
    unsigned long start = 0;
    unsigned long end = FACT_TABLE_INDEX_MAX(sbi);
    unsigned long target_index;
    struct fact_entry *target_entry;
    int total = 0;
    int used = 0;

    for (i = start; i <= end; i++) {
        target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + i * NOVA_FACT_ENTRY_SIZE;
        target_entry = (struct fact_entry *)nova_get_block(sb, target_index);

        if (target_entry->count != 0) {
            // nova_dedup_FACT_read(sb,i);
            used++;
        }
        total++;
    }

    printk("Utilization total: %d, used %d\n", total, used);

    return 1;
}

// Recover FACT
int nova_dedup_FACT_reorder_undo(struct super_block *sb, u64 head_index)
{
    // Scan through 'next' to fix the prev of each node
    unsigned long prev_index = head_index;
    unsigned long target_index = 0;
    unsigned long curr_index = head_index;
    struct fact_entry *target_entry;

    target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + curr_index * NOVA_FACT_ENTRY_SIZE;
    target_entry = (struct fact_entry *)nova_get_block(sb, target_index);
    curr_index = target_entry->next;

    do {
        target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + curr_index * NOVA_FACT_ENTRY_SIZE;
        target_entry = (struct fact_entry *)nova_get_block(sb, target_index);
        target_entry->prev = prev_index;
        prev_index = curr_index;
        curr_index = target_entry->next;
    } while (target_entry->next != head_index);

    return 0;
}

int nova_dedup_FACT_reorder_recover(struct super_block *sb, u64 head_index, u64 end_index)
{
    // Scan through 'prev' to fix the next of each node
    unsigned long target_index = 0;
    unsigned long next_index = head_index;
    unsigned long curr_index = head_index;
    struct fact_entry *target_entry;

    target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + curr_index * NOVA_FACT_ENTRY_SIZE;
    target_entry = (struct fact_entry *)nova_get_block(sb, target_index);
    curr_index = target_entry->prev;

    do {
        target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + curr_index * NOVA_FACT_ENTRY_SIZE;
        target_entry = (struct fact_entry *)nova_get_block(sb, target_index);
        target_entry->next = next_index;
        next_index = curr_index;
        curr_index = target_entry->prev;
    } while (target_entry->prev != head_index);

    return 0;
}

int nova_dedup_FACT_recovery(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    unsigned long i, start = 0;
    unsigned long end = FACT_TABLE_INDEX_MAX(sbi);
    unsigned long target_index;
    unsigned long irq_flags = 0;
    unsigned long u_count, r_count;

    struct fact_entry *target_entry;

    FACT_free_list = kzalloc(sizeof(struct DeNOVA_bm), GFP_KERNEL);
    FACT_free_list->bitmap_size = FACT_TABLE_INDEX_MAX(sbi);
    FACT_free_list->bitmap = kvzalloc(FACT_TABLE_INDEX_MAX(sbi), GFP_KERNEL);

    for (i = start; i <= end; i++) {
        target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + i * NOVA_FACT_ENTRY_SIZE;
        target_entry = (struct fact_entry *)nova_get_block(sb, target_index);

        r_count = target_entry->count >> 32;
        u_count = target_entry->count & (((long)1 << 32) - 1);

        // Rebuild FACT_free_list
        if (r_count > 0) {
            // TODO Check if block is in free list
            set_bit(target_index, FACT_free_list->bitmap); // set the bit of index
        }

        // Set Update Count to 0
        if (r_count != 0) {
            nova_memunlock_range(sb, target_entry, NOVA_FACT_ENTRY_SIZE, &irq_flags);
            PERSISTENT_BARRIER();
            target_entry->count -= r_count;
            nova_flush_buffer(&target_entry->count, CACHELINE_SIZE, 1);
            nova_memlock_range(sb, target_entry, NOVA_FACT_ENTRY_SIZE, &irq_flags);
        }

        // Check reordering process
        if (target_index < FACT_TABLE_INDIRECT_AREA_START_INDEX(sbi) && target_entry->prev != 0) {
            if (target_entry->prev == target_index) {
                // Undo reorder process
                nova_dedup_FACT_reorder_undo(sb, target_index);
            } else {
                // continue reorder
                nova_dedup_FACT_reorder_recover(sb, target_index, target_entry->prev);
            }
        }
    }

    return 1;
}

int nova_dedup_FACT_reorder(struct super_block *sb, u64 head_index)
{
    struct fact_entry *target_entry;
    u64 curr_index = head_index;
    u64 target_index;
    u64 last_index = 0;
    unsigned long *weight;
    unsigned long *reorder;
    unsigned long irq_flags = 0;
    unsigned long tmp1;
    int tmp2;
    int i, j, hops = 0;

    printk("Reorder Start\n");

    // Count hops & save nodes of a linked list to reorder
    do {
        target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + curr_index * NOVA_FACT_ENTRY_SIZE;
        target_entry = (struct fact_entry *)nova_get_block(sb, target_index);
        hops++;
        curr_index = target_entry->next;
    } while (target_entry->next != head_index);

    weight = kmalloc(hops * sizeof(unsigned long), GFP_KERNEL);
    reorder = kmalloc(hops * sizeof(unsigned long), GFP_KERNEL);

    curr_index = head_index;
    for (i = 0; i < hops; i++) {
        target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + curr_index * NOVA_FACT_ENTRY_SIZE;
        target_entry = (struct fact_entry *)nova_get_block(sb, target_index);

        weight[i] = target_entry->count >> 32;
        reorder[i] = target_index;

        curr_index = target_entry->next;
    }

    // Sort the linked list
    for (i = 0; i < hops - 1; i++) {
        for (j = 0; j < hops - i - 1; j++) {
            if (weight[j] > weight[j + 1]) {
                tmp1 = weight[j];
                tmp2 = reorder[j];

                weight[j] = weight[j + 1];
                reorder[j] = weight[j + 1];

                weight[j + 1] = tmp1;
                reorder[j + 1] = tmp2;
            }
        }
    }

    // head 'prev' to head_index
    target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + head_index * NOVA_FACT_ENTRY_SIZE;
    target_entry = (struct fact_entry *)nova_get_block(sb, target_index);

    nova_memunlock_range(sb, target_entry, NOVA_FACT_ENTRY_SIZE, &irq_flags);
    PERSISTENT_BARRIER();
    target_entry->prev = head_index;
    nova_flush_buffer(&target_entry->prev, CACHELINE_SIZE, 1);
    nova_memlock_range(sb, target_entry, NOVA_FACT_ENTRY_SIZE, &irq_flags);

    // Modify the prev of all nodes

    for (i = 0; i < hops; i++) {
        target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + reorder[i] * NOVA_FACT_ENTRY_SIZE;
        target_entry = (struct fact_entry *)nova_get_block(sb, target_index);

        if (i == 0)
            target_entry->prev = head_index;
        else
            target_entry->prev = reorder[i - 1];
    }

    // head 'prev' to last node
    target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + head_index * NOVA_FACT_ENTRY_SIZE;
    target_entry = (struct fact_entry *)nova_get_block(sb, target_index);

    nova_memunlock_range(sb, target_entry, NOVA_FACT_ENTRY_SIZE, &irq_flags);
    PERSISTENT_BARRIER();
    target_entry->prev = last_index;
    nova_flush_buffer(&target_entry->prev, CACHELINE_SIZE, 1);
    nova_memlock_range(sb, target_entry, NOVA_FACT_ENTRY_SIZE, &irq_flags);

    // Modify the next of all nodes
    target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + head_index * NOVA_FACT_ENTRY_SIZE;
    target_entry = (struct fact_entry *)nova_get_block(sb, target_index);
    target_entry->next = reorder[0];

    for (i = 0; i < hops; i++) {
        target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + reorder[i] * NOVA_FACT_ENTRY_SIZE;
        target_entry = (struct fact_entry *)nova_get_block(sb, target_index);

        if (i == hops - 1)
            target_entry->next = head_index;
        else
            target_entry->next = reorder[i + 1];
    }

    // head 'prev' to 0
    target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + head_index * NOVA_FACT_ENTRY_SIZE;
    target_entry = (struct fact_entry *)nova_get_block(sb, target_index);

    nova_memunlock_range(sb, target_entry, NOVA_FACT_ENTRY_SIZE, &irq_flags);
    PERSISTENT_BARRIER();
    target_entry->prev = 0;
    nova_flush_buffer(&target_entry->prev, CACHELINE_SIZE, 1);
    nova_memlock_range(sb, target_entry, NOVA_FACT_ENTRY_SIZE, &irq_flags);

    kfree(weight);
    kfree(reorder);

    printk("Reorder End\n");

    return 1;
}

// Check FACT index range(of FACT)
int nova_dedup_FACT_index_check(struct nova_sb_info *sbi, u64 index)
{
    if (index > FACT_TABLE_INDEX_MAX(sbi)) {
        printk("FACT Index Out of Range: %llu(maximum %llu)\n", index, (unsigned long long int)FACT_TABLE_INDEX_MAX(sbi));
        return 1;
    }
    return 0;
}

// Check FACT index head
int nova_dedup_FACT_index_head(struct nova_sb_info *sbi, u64 index)
{
    if (nova_dedup_FACT_index_check(sbi, index))
        return 0;
    if (index < FACT_TABLE_INDIRECT_AREA_START_INDEX(sbi))
        return 0;
    else
        return 1;
}

// Update Count after tail has been updated.
int nova_dedup_FACT_update_count(struct super_block *sb, u64 index)
{
    u64 count = 0;
    u64 compare = ((unsigned long)1 << 32) - 1;
    struct fact_entry *target_entry;
    unsigned long irq_flags = 0;
    u64 target_index;
    u64 temp_index;
    struct nova_sb_info *sbi = NOVA_SB(sb);

    // Check index is in range
    if (nova_dedup_FACT_index_check(sbi, index))
        return 1;

    // Read Actual Index
    // If this place has something, meaning that the entry has something
    target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + index * NOVA_FACT_ENTRY_SIZE;
    target_entry = (struct fact_entry *)nova_get_block(sb, target_index);
    target_index = target_entry->delete_entry;

    // Check index is in range
    if (nova_dedup_FACT_index_check(sbi, target_index))
        return 1;

    // Read Count of Actual Index
    temp_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + target_index * NOVA_FACT_ENTRY_SIZE;
    target_entry = (struct fact_entry *)nova_get_block(sb, temp_index);
    count = target_entry->count;

    // IF update Count > 0
    if (compare & count) {
        count += compare; // Ucount--, Rcount++
        // Reference count, update count Atomic Update
        nova_memunlock_range(sb, target_entry, NOVA_FACT_ENTRY_SIZE, &irq_flags);
        PERSISTENT_BARRIER();
        target_entry->count = count;
        nova_flush_buffer(&target_entry->count, CACHELINE_SIZE, 1);
        nova_memlock_range(sb, target_entry, NOVA_FACT_ENTRY_SIZE, &irq_flags);
    }
    return 0;
}

// Reading a specific FACT entry by index, mainly for debugging
int nova_dedup_FACT_read(struct super_block *sb, u64 index)
{
    int r_count, u_count;
    u64 block_address;
    u64 next, prev;
    struct fact_entry *target;
    u64 target_index;
    struct nova_sb_info *sbi = NOVA_SB(sb);

    if (nova_dedup_FACT_index_check(sbi, index))
        return 1;

    target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + index * NOVA_FACT_ENTRY_SIZE;
    target = (struct fact_entry *)nova_get_block(sb, target_index);

    r_count = target->count >> 32;
    u_count = target->count & (((long)1 << 32) - 1);
    block_address = target->block_address;
    next = target->next;
    prev = target->prev;

    printk("index:%lld, ref_count:%d, up_count:%d, prev:%lld, next:%lld, block_address: %lld\n",
           index, r_count, u_count, prev, next, block_address);
    return 0;
}

u64 __calc_FACT_index(struct nova_sb_info *sbi, struct fingerprint_lookup_data *lookup)
{
    u64 index = 0;
    int complete = 0;
    int remain = 0;
    int i;

    /* shift fingerprint with fact_entry_prefix */
    complete = sbi->fact_entry_prefix / 8;
    remain = sbi->fact_entry_prefix & 0x7;

    for (i = 0; i < complete; i++) {
        index = index << 8 | lookup->fingerprint[i];
    }

    if (remain) {
        index = index << remain | lookup->fingerprint[i] >> (8 - remain);
    }

    return index;
}

int nova_dedup_FACT_insert(struct super_block *sb, struct fingerprint_lookup_data *lookup)
{
    unsigned long irq_flags = 0;
    struct fact_entry te;       // target entry
    struct fact_entry *pmem_te; // pmem target entry
    u64 index = 0;
    u64 prev_index = 0;
    u64 head_index = 0;
    u64 target_index;
    int ret = 0;
    int hop = 0;
    struct nova_sb_info *sbi = NOVA_SB(sb);

    index = __calc_FACT_index(sbi, lookup);

    // Index out of range
    if (nova_dedup_FACT_index_check(sbi, index))
        return 2;

    head_index = index;
    // Read Entries until it finds a match, or finds a empty slot
    do {
        // if (hop > 500) {
        //     printk("IAA Infinite loop, bug exists\n");
        //     return 2;
        // }

        target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + index * NOVA_FACT_ENTRY_SIZE;
        pmem_te = (struct fact_entry *)nova_get_block(sb, target_index);

        __copy_to_user(&te, pmem_te, sizeof(struct fact_entry));
        nova_dedup_read_emulate(sizeof(struct fact_entry));
        // printk("head index:%llu prev-index:%llu index:%llu next-index:%llu\n",head_index,te.prev,index,te.next);

        if (nova_dedup_compare_fingerprint(te.fingerprint, lookup->fingerprint) == 0 && (te.count != 0)) { // duplicate found
            ret = 1;
            break;
        } else if (te.next != 0 && te.next != head_index) { // next exists
            index = te.next;
            if (hop != 0) {
				nova_dbg("head index: %llu, next index: %llu, hop: %d\n", head_index, index, hop);
			}
        } else { // need new entry
            ret = 0;
            break;
        }
        hop++;
    } while (1);

    if (ret) { // duplicate data page detected
        nova_memunlock_range(sb, pmem_te, NOVA_FACT_ENTRY_SIZE, &irq_flags);
        PERSISTENT_BARRIER();
        pmem_te->count += 1; // increase update count
        nova_flush_buffer(&pmem_te->count, CACHELINE_SIZE, 1);
        nova_memlock_range(sb, pmem_te, NOVA_FACT_ENTRY_SIZE, &irq_flags);
    } else { // new entry should be written
        if (index == head_index && te.count == 0) {
            prev_index = 0;
        } else { // write in IAA
            prev_index = index;
            index = find_next_zero_bit(FACT_free_list->bitmap, FACT_free_list->bitmap_size, FACT_TABLE_INDIRECT_AREA_START_INDEX(sbi));
            set_bit(index, FACT_free_list->bitmap);
        }

        target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + index * NOVA_FACT_ENTRY_SIZE;
        pmem_te = (struct fact_entry *)nova_get_block(sb, target_index);

        __copy_to_user(&te, pmem_te, sizeof(struct fact_entry));
        nova_dedup_read_emulate(sizeof(struct fact_entry));

        nova_dedup_copy_fingerprint(lookup->fingerprint, te.fingerprint);
        te.block_address = lookup->block_address;
        te.count = 1;
        te.prev = prev_index;
        te.next = head_index;

        // copy target_entry to pmem
        nova_memunlock_range(sb, pmem_te, NOVA_FACT_ENTRY_SIZE, &irq_flags);
        memcpy_to_pmem_nocache(pmem_te, &te, NOVA_FACT_ENTRY_SIZE - 12); // don't write delete, pdding
        nova_memlock_range(sb, pmem_te, NOVA_FACT_ENTRY_SIZE, &irq_flags);

        if (index != head_index) {
            target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + prev_index * NOVA_FACT_ENTRY_SIZE;
            pmem_te = (struct fact_entry *)nova_get_block(sb, target_index);

            // set previous index's next field to 'index'
            nova_memunlock_range(sb, pmem_te, NOVA_FACT_ENTRY_SIZE, &irq_flags);
            PERSISTENT_BARRIER();
            pmem_te->next = index;
            nova_flush_buffer(&pmem_te->next, CACHELINE_SIZE, 1);
            nova_memlock_range(sb, pmem_te, NOVA_FACT_ENTRY_SIZE, &irq_flags);
        }
    }

    // update lookup data(used in deduplication process)
    lookup->index = index;
    lookup->block_address = te.block_address;

    // Add 'delete entry'
    if (ret == 0) {
        // Check range
        if (nova_dedup_FACT_index_check(sbi, te.block_address))
            return 2;

        target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + te.block_address * NOVA_FACT_ENTRY_SIZE;
        pmem_te = (struct fact_entry *)nova_get_block(sb, target_index);

        nova_memunlock_range(sb, pmem_te, NOVA_FACT_ENTRY_SIZE, &irq_flags);
        PERSISTENT_BARRIER();
        pmem_te->delete_entry = index;
        nova_flush_buffer(&pmem_te->delete_entry, CACHELINE_SIZE, 1);
        nova_memlock_range(sb, pmem_te, NOVA_FACT_ENTRY_SIZE, &irq_flags);
    }

	if (hop > REORDER_THRESHOLD) {
    	nova_dedup_FACT_reorder(sb,head_index);
	}

    return ret;
}

// Update FACT table + dedup_flags in write entry, of Target Write Entry
int nova_dedup_TWE_update(struct super_block *sb, struct nova_inode_info_header *sih, u64 curr_p, short *duplicate_check)
{
    int i;
    unsigned long irq_flags = 0;
    unsigned int num = 0;
    unsigned long start_index;
    unsigned long curr_index;

    void *addr;
    struct nova_file_write_entry *entry;

    addr = (void *)nova_get_block(sb, curr_p);
    entry = (struct nova_file_write_entry *)addr;
    // Update dedup flag to 'in_process'
    nova_memunlock_range(sb, entry, CACHELINE_SIZE, &irq_flags);
    PERSISTENT_BARRIER();
    entry->dedup_flag = IN_PROCESS;
    nova_flush_buffer(&entry->dedup_flag, CACHELINE_SIZE, 1);
    nova_memlock_range(sb, entry, CACHELINE_SIZE, &irq_flags);

    // Update unique FACT entry counts
    num = entry->num_pages;
    start_index = entry->block >> PAGE_SHIFT;
    for (i = 0; i < num; i++) {
        if (duplicate_check[i] != 0)
            continue;
        curr_index = start_index + i;
        nova_dedup_FACT_update_count(sb, curr_index);
    }
    // Update dedup flag to 'dedup finished'
    nova_memunlock_range(sb, entry, CACHELINE_SIZE, &irq_flags);
    PERSISTENT_BARRIER();
    entry->dedup_flag = DEDUP_DONE;
    nova_flush_buffer(&entry->dedup_flag, CACHELINE_SIZE, 1);
    nova_memlock_range(sb, entry, CACHELINE_SIZE, &irq_flags);

    return 0;
}

// Update FACT table + dedup_flags in write entry, of new write entry
int nova_dedup_entry_update(struct super_block *sb, struct nova_inode_info_header *sih, u64 begin_tail)
{
    void *addr;
    struct nova_file_write_entry *entry;
    u64 curr_p = begin_tail;
    size_t entry_size = sizeof(struct nova_file_write_entry);
    unsigned long irq_flags = 0;
    unsigned long curr_index;
    unsigned long start_index;
    unsigned int num = 0;
    int i;

    while (curr_p && curr_p != sih->log_tail) {
        if (is_last_entry(curr_p, entry_size))
            curr_p = next_log_page(sb, curr_p);
        if (curr_p == 0)
            break;
        addr = (void *)nova_get_block(sb, curr_p);
        entry = (struct nova_file_write_entry *)addr;

        num = entry->num_pages;
        start_index = entry->block >> PAGE_SHIFT;
        for (i = 0; i < num; i++) {
            curr_index = start_index + i;
            nova_dedup_FACT_update_count(sb, curr_index); // Update FACT 'update, reference count'
        }
        // Update Write New Write Entry 'dedup_flag'
        nova_memunlock_range(sb, entry, CACHELINE_SIZE, &irq_flags);
        PERSISTENT_BARRIER();
        entry->dedup_flag = DEDUP_DONE; // Dedup finish
        nova_flush_buffer(&entry->dedup_flag, CACHELINE_SIZE, 1);

        nova_update_entry_csum(entry);
        nova_update_alter_entry(sb, entry);
        nova_memlock_range(sb, entry, CACHELINE_SIZE, &irq_flags);
        curr_p += entry_size;
    }
    return 0;
}

// Check if target block has multiple Reference Count & Delete FACT entry
// Return 1 if it's okay to delete - reference count = 0
// Return 0 if it's not okay to delete - reference count > 0
// Return 2 if it's not in FACT table - reference count < 0
int nova_dedup_is_duplicate(struct super_block *sb, unsigned long blocknr, bool check)
{
    unsigned long irq_flags = 0;
    struct fact_entry *pmem_te; // pmem target entry
    struct fact_entry *delete_te;
    u64 index = 0;
    u64 target_index;
    u64 delete_index;
    u64 temp_next;
    u64 temp_prev;
    struct nova_sb_info *sbi = NOVA_SB(sb);

    // Check Index Range of delete entry
    if (nova_dedup_FACT_index_check(sbi, blocknr))
        return 3;
    delete_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + blocknr * NOVA_FACT_ENTRY_SIZE;
    delete_te = (struct fact_entry *)nova_get_block(sb, delete_index);

    index = delete_te->delete_entry;

    // nova_dedup_FACT_read(sb,index);
    //  Check Index Range of target FACT entry
    if (nova_dedup_FACT_index_check(sbi, index)) {
        printk("Error!\n");
        return 2;
    };

    target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + index * NOVA_FACT_ENTRY_SIZE;
    pmem_te = (struct fact_entry *)nova_get_block(sb, target_index);

    if ((pmem_te->count >> 32) <= 0) { // It's not in dedup table, Deleted before Deduplication
        return 2;
    } else { // It's okay to delete, this entry can also be deleted
        temp_next = pmem_te->next;
        temp_prev = pmem_te->prev;

        if (!check) {
            nova_memunlock_range(sb, pmem_te, NOVA_FACT_ENTRY_SIZE, &irq_flags);
            PERSISTENT_BARRIER();
            pmem_te->count -= ((unsigned long)1 << 32); // Update Reference Count
            nova_flush_buffer(&pmem_te->count, CACHELINE_SIZE, 1);
            nova_memlock_range(sb, pmem_te, NOVA_FACT_ENTRY_SIZE, &irq_flags);
        }

        if ((pmem_te->count >> 32) == 0) { // Free data page
            // Set prev->next to next
            if (temp_prev != 0) { // if it's not the head
                target_index = temp_prev;
                target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + target_index * NOVA_FACT_ENTRY_SIZE;
                pmem_te = (struct fact_entry *)nova_get_block(sb, target_index);

                nova_memunlock_range(sb, pmem_te, NOVA_FACT_ENTRY_SIZE, &irq_flags);
                PERSISTENT_BARRIER();
                pmem_te->next = temp_next;
                nova_flush_buffer(&pmem_te->next, CACHELINE_SIZE, 1);
                nova_memlock_range(sb, pmem_te, NOVA_FACT_ENTRY_SIZE, &irq_flags);
            }
            // Set next->prev to prev
            if (nova_dedup_FACT_index_head(sbi, temp_next)) { // If the next is not head (meaning it's not the last node)
                if (temp_prev == 0)
                    temp_prev = index;
                target_index = temp_next;
                target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + target_index * NOVA_FACT_ENTRY_SIZE;
                pmem_te = (struct fact_entry *)nova_get_block(sb, target_index);

                nova_memunlock_range(sb, pmem_te, NOVA_FACT_ENTRY_SIZE, &irq_flags);
                PERSISTENT_BARRIER();
                pmem_te->prev = temp_prev;
                nova_flush_buffer(&pmem_te->prev, CACHELINE_SIZE, 1);
                nova_memlock_range(sb, pmem_te, NOVA_FACT_ENTRY_SIZE, &irq_flags);
            }
            //
            nova_memunlock_range(sb, delete_te, NOVA_FACT_ENTRY_SIZE, &irq_flags);
            PERSISTENT_BARRIER();
            delete_te->delete_entry = 0;
            nova_flush_buffer(&pmem_te->prev, CACHELINE_SIZE, 1);
            nova_memlock_range(sb, pmem_te, NOVA_FACT_ENTRY_SIZE, &irq_flags);

            // Set bit to 0 in deleted FACT entry
            clear_bit(index, FACT_free_list->bitmap); // clear the bit of index
            return 1;
        } else        // Don't free data page
            return 0; // Can't delete
    }
}

/******************** DEDUPLICATION MAIN FUNCTION ********************/
int nova_dedup_test(struct super_block *sb)
{
    // How many deduplications are going to be done each time?
    int dedup_loop_count = 20000; // this is 'n'

    // SHA1
    struct sdesc *sdesc;
    struct crypto_shash *alg;
    char *hash_alg_name = "sha1";
    alg = crypto_alloc_shash(hash_alg_name, 0, 0);
    if (IS_ERR(alg)) {
        pr_info("can't alloc alg %s\n", hash_alg_name);
        return PTR_ERR(alg);
    }
    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc)) {
        pr_info("can't alloc sdesc\n");
        return PTR_ERR(sdesc);
    }
    INIT_TIMING(t0);
    INIT_TIMING(t1);

    // For read phase
    struct nova_file_write_entry *target_entry; // Target write entry to deduplicate
    struct inode *target_inode;                 // Inode of target write entry
    u64 entry_address;                          // Address of target write entry(TWE)
    u64 target_inode_number = 0;                // Number of target inode (TI)
    struct nova_inode *target_pi, inode_copy;   // nova_inode of TI
    struct nova_inode_info *target_si;
    struct nova_inode_info_header *target_sih;

    unsigned char *buf;         // Read Buffer
    unsigned char *fingerprint; // Fingerprint result

    unsigned long left;
    pgoff_t index;
    int i, j, num_pages = 0;
    int invalid_pages = 0;
    unsigned long nvmm;
    void *dax_mem = NULL;

    // For write phase
    int num_new_entry = 0;
    struct fingerprint_lookup_data *lookup_data;
    struct nova_inode_update update;
    struct nova_file_write_entry entry_data; // new write entry
    short *duplicate_check;
    u64 file_size;
    unsigned long original_start_blk, start_blk;
    unsigned long blocknr = 0;
    unsigned long num_blocks = 0;
    unsigned long irq_flags = 0;
    u64 begin_tail = 0;
    u64 epoch_id;
    u32 time;
    u32 valid_page_num = 0;
    ssize_t ret = 0;

    // kmalloc buf, fingerprint
    buf = kmalloc(DATABLOCK_SIZE, GFP_KERNEL);
    fingerprint = kmalloc(FINGERPRINT_SIZE, GFP_KERNEL);

    do {
		if (kthread_should_stop()) {
			nova_info("Force Break Deduplication Loop\n");
			break;
		}
        // Pop TWE(Target Write Entry)
        entry_address = nova_dedup_queue_get_next_entry(&target_inode_number);
        // target_inode_number should exist
        if (target_inode_number < NOVA_NORMAL_INODE_START && target_inode_number != NOVA_ROOT_INO) {
            // nova_info("%s: invalid inode %llu.", __func__,target_inode_number);
            // printk("No entry\n");
            break;
        }
        // Read TI(Target Inode)
        target_inode = nova_iget(sb, target_inode_number);
        // Inode Could've been deleted
        if (target_inode == ERR_PTR(-ESTALE)) {
            // nova_info("%s: inode %llu does not exist.", __func__,target_inode_number);
            // iput(target_inode);	// Release Inode
            continue;
        }

        if (entry_address != 0) {
            // Initialize variables
            ret = 0;
            num_new_entry = 0;
            valid_page_num = 0;
            original_start_blk = 0;
            begin_tail = 0;
            irq_flags = 0;

            target_si = NOVA_I(target_inode);
            target_sih = &target_si->header;
            target_pi = nova_get_inode(sb, target_inode);

            // ---------------------------Lock Acquire-----------------------------------------
            sb_start_write(target_inode->i_sb);
            inode_lock(target_inode);

            // Read TWE
            target_entry = nova_get_block(sb, entry_address);
            original_start_blk = target_entry->pgoff;

            index = target_entry->pgoff;
            num_pages = target_entry->num_pages;
            invalid_pages = target_entry->invalid_pages;

            if (num_pages > 32 || num_pages <= 0) {
                // printk("Write Entry already claimed\n");
                goto out2;
            }
            if (num_pages == invalid_pages) {
                // printk("Write Entry already claimed\n");
                goto out2;
            }

            // printk("numpages are :%d\n",num_pages);
            lookup_data = kmalloc(num_pages * sizeof(struct fingerprint_lookup_data), GFP_KERNEL);
            duplicate_check = kmalloc(sizeof(short) * num_pages, GFP_KERNEL);
            memset(duplicate_check, false, sizeof(short) * num_pages);

            // Read Each Data Page from TWE
            for (i = 0; i < num_pages; i++) {
                if (nova_dedup_crosscheck(target_entry, target_sih, index) == 0) {
                    duplicate_check[i] = 2; // Data page i in invalid, target write entry does not point to it!
                    index++;
                    continue;
                }
                valid_page_num++;
                memset(buf, 0, DATABLOCK_SIZE);
                memset(fingerprint, 0, FINGERPRINT_SIZE);

                nvmm = get_nvmm(sb, target_sih, target_entry, index);
                dax_mem = nova_get_block(sb, (nvmm << PAGE_SHIFT));

                left = __copy_to_user(buf, dax_mem, DATABLOCK_SIZE); // Read data page
                nova_dedup_read_emulate(DATABLOCK_SIZE);

                if (left) {
                    nova_dbg("%s ERROR!: left %lu\n", __func__, left);
                    goto out;
                }
                crypto_shash_digest(&sdesc->shash, buf, DATABLOCK_SIZE, fingerprint);

                for (j = 0; j < FINGERPRINT_SIZE; j++) {
                    lookup_data[i].fingerprint[j] = fingerprint[j];
                }
                lookup_data[i].block_address = nvmm;
                index++;
            }
            // Lookup & Add to FACT table
            for (i = 0; i < num_pages; i++) {
                if (duplicate_check[i] != 2) {
                    duplicate_check[i] = nova_dedup_FACT_insert(sb, &lookup_data[i]);
                    num_new_entry += duplicate_check[i];
                }
			}
            // Test
            /*
                             for(i=0;i<num_pages;i++)
                             if(duplicate_check[i] != 2){
                             nova_dedup_FACT_read(sb, lookup_data[i].index);
                             }
                    */
            // Get the number of new write entries needed to be appended.
            if (num_new_entry == 0) {
                nova_dedup_TWE_update(sb, target_sih, entry_address, duplicate_check);
                goto out;
            }

            // ------------------- Write Phase -----------------------
            if (nova_check_inode_integrity(sb, target_sih->ino, target_sih->pi_addr,
                                           target_sih->alter_pi_addr, &inode_copy, 0) < 0) {
                ret = -EIO;
                goto out;
            }

            // set time
            target_inode->i_ctime = current_time(target_inode);
            time = current_time(target_inode).tv_sec;

            epoch_id = nova_get_epoch_id(sb);
            update.tail = target_sih->log_tail;
            update.alter_tail = target_sih->alter_log_tail;
            file_size = cpu_to_le64(target_inode->i_size);

            // Only add new write entries for duplicate data pages
            for (i = 0; i < num_pages; i++) {
                if (duplicate_check[i] != 1)
                    continue;

                start_blk = original_start_blk + i;
                num_blocks = 1;
                blocknr = lookup_data[i].block_address;

                nova_init_file_write_entry(sb, target_sih, &entry_data, epoch_id,
                                           start_blk, num_blocks, blocknr, time, file_size);
                entry_data.dedup_flag = IN_PROCESS; // flag is set to 2 - in process
                ret = nova_append_file_write_entry(sb, target_pi, target_inode, &entry_data, &update);

                // printk("NEW WRITE ENTRY(offset: %lu, %lu blocks)\n",start_blk,num_blocks);

                if (ret) {
                    nova_dbg("%s: append inode entry failed\n", __func__);
                    ret = -ENOSPC;
                    // goto out;
                }
                if (begin_tail == 0)
                    begin_tail = update.curr_entry;
                num_new_entry -= 1;
            }
            if (num_new_entry != 0) { // Not appended pages exists
                printk("Datapage assign error! %d duplicate pages left\n", num_new_entry);
                goto out;
            }

            // Update tail
            nova_memunlock_inode(sb, target_pi, &irq_flags);
            nova_update_inode(sb, target_inode, target_pi, &update, 1);
            nova_memlock_inode(sb, target_pi, &irq_flags);

            // Update FACT TABLE + dedup_flag of TWE
            nova_dedup_TWE_update(sb, target_sih, entry_address, duplicate_check);

            // Update FACT TABLE + dedup_flag of new write entries
            nova_dedup_entry_update(sb, target_sih, begin_tail);

            /*
                    for(i=0;i<num_pages;i++)
                     if(duplicate_check[i] != 2){
                     nova_dedup_FACT_read(sb, lookup_data[i].index);
                     }
            */
            // Update Radix Tree
            ret = nova_reassign_file_tree(sb, target_sih, begin_tail);

            // Test
            /*for(i=0;i<num_pages;i++)
                     if(duplicate_check[i] != 2){
                     nova_dedup_FACT_read(sb, lookup_data[i].index);
                     }
            */

            if (ret)
                goto out;

            target_inode->i_blocks = target_sih->i_blocks;
            target_sih->trans_id++;
        out:
            if (ret < 0)
                nova_cleanup_incomplete_write(sb, target_sih, blocknr, num_blocks, begin_tail, update.tail);

            kfree(lookup_data);
            kfree(duplicate_check);
            // Unlock ------------------------------------------------------------
        out2:
            inode_unlock(target_inode);
            sb_end_write(target_inode->i_sb);
        }
        iput(target_inode); // Release Inode
        schedule(); /* be nice */
    } while (dedup_loop_count--);

    // nova_dedup_FACT_utilize(sb);
    kfree(buf);
    kfree(sdesc);
    crypto_free_shash(alg);
    kfree(fingerprint);
    return 0;
}

static int nova_dedup_DD(void *arg)
{
    struct nova_sb_info *sbi = (struct nova_sb_info *)arg;
    struct super_block *sb = sbi->sb;

    allow_signal(SIGABRT);

    while (true) {
        if (sbi->dd_poll_mseconds)
            msleep_interruptible(sbi->dd_poll_mseconds);

        if (kthread_should_stop())
            break;

        nova_dedup_test(sb);
        schedule();
    }

    flush_signals(current);

    nova_info("DeNOVA Deduplication Daemon exited.\n");
    return 0;
}

int nova_dedup_wakeup_DD(struct nova_sb_info *sbi)
{
    int ret = 0;
    sbi->dd = kthread_run(nova_dedup_DD, sbi, "DeNOVA Deduplication Daemon");
    if (IS_ERR(sbi->snapshot_cleaner_thread)) {
        nova_info("Failed to start DeNOVA Deduplication Daemon\n");
        ret = -1;
    }
    nova_info("Start DeNOVA Deduplication Daemon.\n");
    return ret;
}

int nova_dedup_terminate_DD(struct nova_sb_info *sbi)
{
    int ret = 0;
    if (sbi->dd) {
        send_sig_info(SIGABRT, SEND_SIG_NOINFO, sbi->dd);
        kthread_stop(sbi->dd);
        sbi->dd = NULL;
    }
    return ret;
}