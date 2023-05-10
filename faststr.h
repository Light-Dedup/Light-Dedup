/*
 * Fast block comparing.
 *
 * Copyright (c) 2020-2022 Jiansheng Qiu <jianshengqiu.cs@gmail.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef FASTSTR_H_
#define FASTSTR_H_

// size_t mismatch_pos(const char *block_a, const char *block_b);
uint64_t cmp64(const uint64_t *block_a, const uint64_t *block_b);

#endif // FASTSTR_H_
