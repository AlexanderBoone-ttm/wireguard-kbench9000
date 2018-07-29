/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Curve25519 ECDH functions, based on TweetNaCl but cleaned up.
 */

#include <linux/kernel.h>
#include <linux/string.h>

enum { CURVE25519_POINT_SIZE = 32 };

static __always_inline void normalize_secret(u8 secret[CURVE25519_POINT_SIZE])
{
	secret[0] &= 248;
	secret[31] &= 127;
	secret[31] |= 64;
}

typedef s64 fe[16];

static void carry(fe o)
{
	int i;

	for (i = 0; i < 16; ++i) {
		o[(i + 1) % 16] += (i == 15 ? 38 : 1) * (o[i] >> 16);
		o[i] &= 0xffff;
	}
}

static void cswap(fe p, fe q, int b)
{
	int i;
	s64 t, c = ~(b - 1);

	for (i = 0; i < 16; ++i) {
		t = c & (p[i] ^ q[i]);
		p[i] ^= t;
		q[i] ^= t;
	}
}

static void pack(u8 *o, const fe n)
{
	int i, j, b;
	fe m, t;

	memcpy(t, n, sizeof(t));
	carry(t);
	carry(t);
	carry(t);
	for (j = 0; j < 2; ++j) {
		m[0] = t[0] - 0xffed;
		for (i = 1; i < 15; ++i) {
			m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
			m[i - 1] &= 0xffff;
		}
		m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
		b = (m[15] >> 16) & 1;
		m[14] &= 0xffff;
		cswap(t, m, 1 - b);
	}
	for (i = 0; i < 16; ++i) {
		o[2 * i] = t[i] & 0xff;
		o[2 * i + 1] = t[i] >> 8;
	}
}

static void unpack(fe o, const u8 *n)
{
	int i;

	for (i = 0; i < 16; ++i)
		o[i] = n[2 * i] + ((s64)n[2 * i + 1] << 8);
	o[15] &= 0x7fff;
}

static void add(fe o, const fe a, const fe b)
{
	int i;

	for (i = 0; i < 16; ++i)
		o[i] = a[i] + b[i];
}

static void subtract(fe o, const fe a, const fe b)
{
	int i;

	for (i = 0; i < 16; ++i)
		o[i] = a[i] - b[i];
}

static void multmod(fe o, const fe a, const fe b)
{
	int i, j;
	s64 t[31] = { 0 };

	for (i = 0; i < 16; ++i) {
		for (j = 0; j < 16; ++j)
			t[i + j] += a[i] * b[j];
	}
	for (i = 0; i < 15; ++i)
		t[i] += 38 * t[i + 16];
	memcpy(o, t, sizeof(fe));
	carry(o);
	carry(o);
}

static void invert(fe o, const fe i)
{
	fe c;
	int a;

	memcpy(c, i, sizeof(c));
	for (a = 253; a >= 0; --a) {
		multmod(c, c, c);
		if (a != 2 && a != 4)
			multmod(c, c, i);
	}
	memcpy(o, c, sizeof(fe));
}

bool curve25519_tweetnacl(u8 shared_secret[CURVE25519_POINT_SIZE], const u8 private_key[CURVE25519_POINT_SIZE], const u8 public_key[CURVE25519_POINT_SIZE])
{
	static const fe a24 = { 0xdb41, 1 };
	u8 z[32];
	s64 r;
	int i;
	fe a = { 1 }, b, c = { 0 }, d = { 1 }, e, f, x;

	memcpy(z, private_key, sizeof(z));
	normalize_secret(z);

	unpack(x, public_key);
	memcpy(b, x, sizeof(b));

	for (i = 254; i >= 0; --i) {
		r = (z[i >> 3] >> (i & 7)) & 1;
		cswap(a, b, r);
		cswap(c, d, r);
		add(e, a, c);
		subtract(a, a, c);
		add(c, b, d);
		subtract(b, b, d);
		multmod(d, e, e);
		multmod(f, a, a);
		multmod(a, c, a);
		multmod(c, b, e);
		add(e, a, c);
		subtract(a, a, c);
		multmod(b, a, a);
		subtract(c, d, f);
		multmod(a, c, a24);
		add(a, a, d);
		multmod(c, c, a);
		multmod(a, d, f);
		multmod(d, b, x);
		multmod(b, e, e);
		cswap(a, b, r);
		cswap(c, d, r);
	}
	invert(c, c);
	multmod(a, a, c);
	pack(shared_secret, a);

	return true;
}
