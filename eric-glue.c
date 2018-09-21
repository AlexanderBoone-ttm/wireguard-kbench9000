/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <linux/kernel.h>
#include <linux/string.h>

asmlinkage void chacha_arm(u8 *out, const u8 *in, size_t len, const u32 key[8],
			   const u32 iv[4], int nrounds);

void chacha20_eric_scalar(u8 *dst, const u8 *src, u32 len, const u32 key[8], const u32 counter[4])
{
	chacha_arm(dst, src, len, key, counter, 20);
}
