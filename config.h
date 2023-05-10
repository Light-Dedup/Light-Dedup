/*
 * Definitions for the NOVA filesystem.
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef __CONFIG_H
#define __CONFIG_H

extern int measure_timing;
extern int metadata_csum;
extern int unsafe_metadata;
extern int wprotect;
extern int data_csum;
extern int data_parity;
extern int dram_struct_csum;
extern int transition_threshold;

#ifdef MEASURE_DRAM_USAGE
	#define TABLE_KMEM_CACHE_FLAGS SLAB_POISON
	// #define TABLE_KMEM_CACHE_FLAGS (SLAB_POISON | SLAB_RED_ZONE)
#else
	#define TABLE_KMEM_CACHE_FLAGS 0
#endif

#endif // __CONFIG_H