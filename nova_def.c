/*
 * Fundamental functions for NOVA.
 *
 * Copyright (c) 2020-2022 Jiansheng Qiu <jianshengqiu.cs@gmail.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/kernel.h>
#include <linux/module.h> // BUG_ON
#include <linux/string.h>

_Static_assert(sizeof(size_t) == 8, "sizeof(size_t) != 8!");
/* assumes the length to be 4-byte aligned */
void memset_nt(void *dest, uint32_t dword, size_t length)
{
	uint64_t qword = ((uint64_t)dword << 32) | dword;
	BUG_ON(length % 4 != 0);
	for (; length >= 64; length -= 64, dest = (char *)dest + 64) {
		memcpy_flushcache((uint64_t *)dest, &qword, sizeof(uint64_t));
		memcpy_flushcache((uint64_t *)dest + 1, &qword, sizeof(uint64_t));
		memcpy_flushcache((uint64_t *)dest + 2, &qword, sizeof(uint64_t));
		memcpy_flushcache((uint64_t *)dest + 3, &qword, sizeof(uint64_t));
		memcpy_flushcache((uint64_t *)dest + 4, &qword, sizeof(uint64_t));
		memcpy_flushcache((uint64_t *)dest + 5, &qword, sizeof(uint64_t));
		memcpy_flushcache((uint64_t *)dest + 6, &qword, sizeof(uint64_t));
		memcpy_flushcache((uint64_t *)dest + 7, &qword, sizeof(uint64_t));
	}
	for (; length >= 8; length -= 8, dest = (char *)dest + 8)
		memcpy_flushcache((uint64_t *)dest, &qword, sizeof(uint64_t));
	if (length == 4)
		memcpy_flushcache((uint32_t *)dest, &dword, sizeof(uint32_t));
}
