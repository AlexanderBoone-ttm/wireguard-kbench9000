/* SPDX-License-Identifier: OpenSSL OR (BSD-3-Clause OR GPL-2.0)
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/intel-family.h>

asmlinkage void poly1305_init_x86_64(void *ctx, const u8 key[16]);
asmlinkage void poly1305_blocks_x86_64(void *ctx, const u8 *inp, size_t len, u32 padbit);
asmlinkage void poly1305_emit_x86_64(void *ctx, u8 mac[16], const u32 nonce[4]);
asmlinkage void poly1305_emit_avx(void *ctx, u8 mac[16], const u32 nonce[4]);
asmlinkage void poly1305_blocks_avx(void *ctx, const u8 *inp, size_t len, u32 padbit);
asmlinkage void poly1305_blocks_avx2(void *ctx, const u8 *inp, size_t len, u32 padbit);
asmlinkage void poly1305_blocks_avx512(void *ctx, const u8 *inp, size_t len, u32 padbit);

enum {
	POLY1305_BLOCK_SIZE = 16,
	POLY1305_KEY_SIZE = 32,
	POLY1305_MAC_SIZE = 16
};

struct poly1305_ctx {
	u8 opaque[24 * sizeof(u64)];
	u32 nonce[4];
	u8 data[POLY1305_BLOCK_SIZE];
	size_t num;
} __aligned(8);

static inline u32 le32_to_cpuvp(const void *p)
{
	return le32_to_cpup(p);
}

void poly1305_ossl_amd64(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k)
{
	size_t rem;
	struct poly1305_ctx ctx;
	ctx.nonce[0] = le32_to_cpuvp(&k[16]);
	ctx.nonce[1] = le32_to_cpuvp(&k[20]);
	ctx.nonce[2] = le32_to_cpuvp(&k[24]);
	ctx.nonce[3] = le32_to_cpuvp(&k[28]);
	poly1305_init_x86_64(ctx.opaque, k);
	ctx.num = 0;

	rem = inlen % POLY1305_BLOCK_SIZE;
	inlen -= rem;

	if (inlen >= POLY1305_BLOCK_SIZE) {
		poly1305_blocks_x86_64(ctx.opaque, in, inlen, 1);
		in += inlen;
	}
	if (rem) {
		memcpy(ctx.data, in, rem);
		ctx.data[rem++] = 1;   /* pad bit */
		while (rem < POLY1305_BLOCK_SIZE)
			ctx.data[rem++] = 0;
		poly1305_blocks_x86_64(ctx.opaque, ctx.data, POLY1305_BLOCK_SIZE, 0);
	}

	poly1305_emit_x86_64(ctx.opaque, out, ctx.nonce);
}

void poly1305_ossl_avx(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k)
{
	size_t rem;
	struct poly1305_ctx ctx;
	ctx.nonce[0] = le32_to_cpuvp(&k[16]);
	ctx.nonce[1] = le32_to_cpuvp(&k[20]);
	ctx.nonce[2] = le32_to_cpuvp(&k[24]);
	ctx.nonce[3] = le32_to_cpuvp(&k[28]);
	poly1305_init_x86_64(ctx.opaque, k);
	ctx.num = 0;

	rem = inlen % POLY1305_BLOCK_SIZE;
	inlen -= rem;

	if (inlen >= POLY1305_BLOCK_SIZE) {
		poly1305_blocks_avx(ctx.opaque, in, inlen, 1);
		in += inlen;
	}
	if (rem) {
		memcpy(ctx.data, in, rem);
		ctx.data[rem++] = 1;   /* pad bit */
		while (rem < POLY1305_BLOCK_SIZE)
			ctx.data[rem++] = 0;
		poly1305_blocks_avx(ctx.opaque, ctx.data, POLY1305_BLOCK_SIZE, 0);
	}

	poly1305_emit_avx(ctx.opaque, out, ctx.nonce);
}

void poly1305_ossl_avx2(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k)
{
	size_t rem;
	struct poly1305_ctx ctx;
	ctx.nonce[0] = le32_to_cpuvp(&k[16]);
	ctx.nonce[1] = le32_to_cpuvp(&k[20]);
	ctx.nonce[2] = le32_to_cpuvp(&k[24]);
	ctx.nonce[3] = le32_to_cpuvp(&k[28]);
	poly1305_init_x86_64(ctx.opaque, k);
	ctx.num = 0;

	rem = inlen % POLY1305_BLOCK_SIZE;
	inlen -= rem;

	if (inlen >= POLY1305_BLOCK_SIZE) {
		poly1305_blocks_avx2(ctx.opaque, in, inlen, 1);
		in += inlen;
	}
	if (rem) {
		memcpy(ctx.data, in, rem);
		ctx.data[rem++] = 1;   /* pad bit */
		while (rem < POLY1305_BLOCK_SIZE)
			ctx.data[rem++] = 0;
		poly1305_blocks_avx2(ctx.opaque, ctx.data, POLY1305_BLOCK_SIZE, 0);
	}

	poly1305_emit_avx(ctx.opaque, out, ctx.nonce);
}

void poly1305_ossl_avx512(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k)
{
	size_t rem;
	struct poly1305_ctx ctx;
	ctx.nonce[0] = le32_to_cpuvp(&k[16]);
	ctx.nonce[1] = le32_to_cpuvp(&k[20]);
	ctx.nonce[2] = le32_to_cpuvp(&k[24]);
	ctx.nonce[3] = le32_to_cpuvp(&k[28]);
	poly1305_init_x86_64(ctx.opaque, k);
	ctx.num = 0;

	rem = inlen % POLY1305_BLOCK_SIZE;
	inlen -= rem;

	if (inlen >= POLY1305_BLOCK_SIZE) {
		poly1305_blocks_avx512(ctx.opaque, in, inlen, 1);
		in += inlen;
	}
	if (rem) {
		memcpy(ctx.data, in, rem);
		ctx.data[rem++] = 1;   /* pad bit */
		while (rem < POLY1305_BLOCK_SIZE)
			ctx.data[rem++] = 0;
		poly1305_blocks_avx512(ctx.opaque, ctx.data, POLY1305_BLOCK_SIZE, 0);
	}

	poly1305_emit_avx(ctx.opaque, out, ctx.nonce);
}
