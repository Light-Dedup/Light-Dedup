#ifndef __CONFIG_H
#define __CONFIG_H

extern int measure_timing;
extern int metadata_csum;
extern int unsafe_metadata;
extern int wprotect;
extern int data_csum;
extern int data_parity;
extern int dram_struct_csum;

#ifdef MEASURE_DRAM_USAGE
	#define TABLE_KMEM_CACHE_FLAGS SLAB_POISON
	// #define TABLE_KMEM_CACHE_FLAGS (SLAB_POISON | SLAB_RED_ZONE)
#else
	#define TABLE_KMEM_CACHE_FLAGS 0
#endif

#endif // __CONFIG_H