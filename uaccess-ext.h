/*
 * Custom uaccess extensions.
 *
 * Copyright (c) 2020-2023 Jiansheng Qiu <jianshengqiu.cs@gmail.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <asm/uaccess.h>

// Fault: Returns the opposite value of the number of bytes not compared
// Success: Returns the number of bytes behind the divergence. 0 means the same.
static inline int64_t
cmp_user_generic_const_8B_aligned(const void __user *usrc, const void *ksrc,
	uint64_t len)
{
	uint64_t tmp;
	BUG_ON(len == 0 || len % 8 != 0);
	might_fault();
	stac();
	asm volatile("\n"
		"1:	movq (%2),%1\n"
		"2:	cmpq %1,(%3)\n"
		"	jnz 3f\n"
		"	leaq 8(%2),%2\n"
		"	leaq 8(%3),%3\n"
		"	subq $8,%0\n"
		"	jnz 1b\n"
		"3:\n"
		".section .fixup,\"ax\"\n"				
		"4:	negq %0\n"
		"	jmp 3b\n"
		".previous\n"
		_ASM_EXTABLE_UA(1b, 4b)
		_ASM_EXTABLE_UA(2b, 4b)
		: "+r" (len), "=r" (tmp), "+r" (usrc), "+r" (ksrc)
		:
		: "cc");
	// TODO: "memory" clobber?
	clac();
	return (int64_t)len;
}
