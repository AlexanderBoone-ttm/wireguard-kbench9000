/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <linux/kernel.h>
#include <crypto/algapi.h>

enum {
	CHACHA20_IV_SIZE = 16,
	CHACHA20_KEY_SIZE = 32,
	CHACHA20_BLOCK_SIZE = 64,
	CHACHA20_BLOCK_WORDS = CHACHA20_BLOCK_SIZE / sizeof(u32)
};

#define EXPAND_32_BYTE_K 0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U

#define QUARTER_ROUND(x, a, b, c, d) ( \
	x[a] += x[b], \
	x[d] = rol32((x[d] ^ x[a]), 16), \
	x[c] += x[d], \
	x[b] = rol32((x[b] ^ x[c]), 12), \
	x[a] += x[b], \
	x[d] = rol32((x[d] ^ x[a]), 8), \
	x[c] += x[d], \
	x[b] = rol32((x[b] ^ x[c]), 7) \
)

#define C(i, j) (i * 4 + j)

#define DOUBLE_ROUND(x) ( \
	/* Column Round */ \
	QUARTER_ROUND(x, C(0, 0), C(1, 0), C(2, 0), C(3, 0)), \
	QUARTER_ROUND(x, C(0, 1), C(1, 1), C(2, 1), C(3, 1)), \
	QUARTER_ROUND(x, C(0, 2), C(1, 2), C(2, 2), C(3, 2)), \
	QUARTER_ROUND(x, C(0, 3), C(1, 3), C(2, 3), C(3, 3)), \
	/* Diagonal Round */ \
	QUARTER_ROUND(x, C(0, 0), C(1, 1), C(2, 2), C(3, 3)), \
	QUARTER_ROUND(x, C(0, 1), C(1, 2), C(2, 3), C(3, 0)), \
	QUARTER_ROUND(x, C(0, 2), C(1, 3), C(2, 0), C(3, 1)), \
	QUARTER_ROUND(x, C(0, 3), C(1, 0), C(2, 1), C(3, 2)) \
)

#define TWENTY_ROUNDS(x) ( \
	DOUBLE_ROUND(x), \
	DOUBLE_ROUND(x), \
	DOUBLE_ROUND(x), \
	DOUBLE_ROUND(x), \
	DOUBLE_ROUND(x), \
	DOUBLE_ROUND(x), \
	DOUBLE_ROUND(x), \
	DOUBLE_ROUND(x), \
	DOUBLE_ROUND(x), \
	DOUBLE_ROUND(x) \
)

static void chacha20_block_generic(__le32 *stream, u32 *state)
{
	u32 x[CHACHA20_BLOCK_WORDS];
	int i;

	for (i = 0; i < ARRAY_SIZE(x); ++i)
		x[i] = state[i];

	TWENTY_ROUNDS(x);

	for (i = 0; i < ARRAY_SIZE(x); ++i)
		stream[i] = cpu_to_le32(x[i] + state[i]);

	++state[12];
}

void chacha20_generic(u8 *out, const u8 *in, u32 len, const u32 key[8], const u32 counter[4])
{
	__le32 buf[CHACHA20_BLOCK_WORDS];
	u32 x[] = {
		EXPAND_32_BYTE_K,
		key[0], key[1], key[2], key[3],
		key[4], key[5], key[6], key[7],
		counter[0], counter[1], counter[2], counter[3]
	};

	if (out != in)
		memmove(out, in, len);

	while (len >= CHACHA20_BLOCK_SIZE) {
		chacha20_block_generic(buf, x);
		crypto_xor(out, (u8 *)buf, CHACHA20_BLOCK_SIZE);
		len -= CHACHA20_BLOCK_SIZE;
		out += CHACHA20_BLOCK_SIZE;
	}
	if (len) {
		chacha20_block_generic(buf, x);
		crypto_xor(out, (u8 *)buf, len);
	}
}
