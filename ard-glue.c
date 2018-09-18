/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <linux/kernel.h>
#include <linux/string.h>

asmlinkage void chacha20_ard_block_xor_neon(u32 *state, u8 *dst, const u8 *src);
asmlinkage void chacha20_ard_4block_xor_neon(u32 *state, u8 *dst, const u8 *src);

enum {
	CHACHA20_IV_SIZE = 16,
	CHACHA20_KEY_SIZE = 32,
	CHACHA20_BLOCK_SIZE = 64,
	CHACHA20_BLOCK_WORDS = CHACHA20_BLOCK_SIZE / sizeof(u32)
};

#define EXPAND_32_BYTE_K 0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U

void chacha20_ard_neon(u8 *dst, const u8 *src, u32 len, const u32 key[8], const u32 counter[4])
{
	u32 state[] = {
		EXPAND_32_BYTE_K,
		key[0], key[1], key[2], key[3],
		key[4], key[5], key[6], key[7],
		counter[0], counter[1], counter[2], counter[3]
	};
	u8 buf[CHACHA20_BLOCK_SIZE];
	unsigned int bytes = len;

	while (bytes >= CHACHA20_BLOCK_SIZE * 4) {
		chacha20_ard_4block_xor_neon(state, dst, src);
		bytes -= CHACHA20_BLOCK_SIZE * 4;
		src += CHACHA20_BLOCK_SIZE * 4;
		dst += CHACHA20_BLOCK_SIZE * 4;
		state[12] += 4;
	}
	while (bytes >= CHACHA20_BLOCK_SIZE) {
		chacha20_ard_block_xor_neon(state, dst, src);
		bytes -= CHACHA20_BLOCK_SIZE;
		src += CHACHA20_BLOCK_SIZE;
		dst += CHACHA20_BLOCK_SIZE;
		state[12]++;
	}
	if (bytes) {
		memcpy(buf, src, bytes);
		chacha20_ard_block_xor_neon(state, buf, buf);
		memcpy(dst, buf, bytes);
	}
}
