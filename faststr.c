/*
 * Fast block comparing.
 *
 * Copyright (c) 2020-2022 Jiansheng Qiu <jianshengqiu.cs@gmail.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/types.h>
#include <asm/asm.h>
#include <linux/kernel.h>

#define BLOCK_SIZE 4096

// Assume that block_a and block_b is 8 byte aligned
uint64_t cmp64(const uint64_t *block_a, const uint64_t *block_b) {
	const uint64_t *b_end = block_b + BLOCK_SIZE / sizeof(block_b[0]);
	for (; block_b < b_end; ++block_b, ++block_a) {
		if (*block_a != *block_b) {
			// printk("cmp64: %ld, %llx, %llx\n", 4096 - (b_end - block_b) * 8, *block_a, *block_b);
			return *block_a - *block_b;
		}
	}
	return 0;
}
