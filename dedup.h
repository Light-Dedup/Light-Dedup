#ifndef __DEDUP_H
#define __DEDUP_H

#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/uaccess.h>
#include <linux/falloc.h>
#include <linux/sched/xacct.h>
#include <asm/mman.h>
#include <asm/uaccess.h>
#include <linux/radix-tree.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/ktime.h>
#include <linux/timekeeping.h>

// SHA1
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/crypto.h>

#include "nova.h"
#include "inode.h"

#define DATABLOCK_SIZE 4096
#define FINGERPRINT_SIZE 20
#define MAX_DATAPAGE_PER_WRITEENTRY 32

#define DEDUP_NEEDED 0
#define DEDUP_DONE 1
#define IN_PROCESS 2

#define REORDER_THRESHOLD 150


/* nova_dedup_queue
	 queue of entries that needs to be deduplicated
*/
struct nova_dedup_queue_entry{
  u64 write_entry_address;
  u64 target_inode_number;
  //u64 start_sec;
	//u64 start_nsec;
	struct list_head list;
};

struct nova_dedup_queue{
  struct nova_dedup_queue_entry head;	// head of dqueue
  struct mutex lock;
};

extern struct nova_dedup_queue dqueue;

/* SHA1 */
struct sdesc {
  struct shash_desc shash;
  char ctx[];
};

/* FACT table entry */
struct fact_entry{
  u64 count; // 32bit reference count, 32bit update count
  unsigned char fingerprint[FINGERPRINT_SIZE];
  u64 block_address;
  u64 prev;
	u64 next;
  u64 delete_entry;
  u32 padding;
}__attribute((__packed__));

/* FACT free list */
struct DeNOVA_bm{
	unsigned long bitmap_size;
	unsigned long *bitmap;
};

/* For Fingerprint lookup */
struct fingerprint_lookup_data{
  unsigned char fingerprint[FINGERPRINT_SIZE]; // fingerprint of entry
  u64 index; // index of entry
  u64 block_address; // Actual address of this entry(where the data block is)
};

void nova_dedup_read_emulate(unsigned long size);

int nova_dedup_FACT_init(struct super_block *sb);
int nova_dedup_FACT_read(struct super_block *sb, u64 index);

int nova_dedup_test(struct file *);
int nova_dedup_queue_push(u64,u64);
int nova_dedup_queue_init(void);

int nova_dedup_is_duplicate(struct super_block *sb, unsigned long blocknr, bool check);
int nova_dedup_fingerprint(int interval, unsigned char * datapage, unsigned char *ret_fingerprint);

#endif
