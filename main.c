/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/fpu/api.h>
#include <asm/simd.h>

static unsigned long stamp = 0;
module_param(stamp, ulong, 0);
int dummy;


enum { CURVE25519_POINT_SIZE = 32 };
u8 dummy_out[CURVE25519_POINT_SIZE];
#include "test_vectors.h"

#define declare_it(name) \
bool curve25519_ ## name(u8 mypublic[CURVE25519_POINT_SIZE], const u8 secret[CURVE25519_POINT_SIZE], const u8 basepoint[CURVE25519_POINT_SIZE]); \
static __always_inline int name(void) \
{ \
	return curve25519_ ## name(dummy_out, curve25519_test_vectors[0].private, curve25519_test_vectors[0].public); \
}

#define do_it(name) do { \
	for (i = 0; i < WARMUP; ++i) \
		ret |= name(); \
	start_ ## name = get_cycles(); \
	for (i = 0; i < TRIALS; ++i) \
		ret |= name(); \
	end_ ## name = get_cycles(); \
} while (0)

#define test_it(name, before, after) do { \
	memset(out, __LINE__, CURVE25519_POINT_SIZE); \
	before; \
	ret = curve25519_ ## name(out, curve25519_test_vectors[i].private, curve25519_test_vectors[i].public); \
	after; \
	if (memcmp(out, curve25519_test_vectors[i].result, CURVE25519_POINT_SIZE)) { \
		pr_err(#name " self-test %zu: FAIL\n", i + 1); \
		return false; \
	} \
} while (0)

#define report_it(name) do { \
	pr_err("%lu: %7s: %llu cycles per call\n", stamp, #name, (end_ ## name - start_ ## name) / TRIALS); \
} while (0)


declare_it(donna64)
declare_it(hacl64)
declare_it(fiat64)
declare_it(sandy2x)
declare_it(amd64)
declare_it(precomp)
declare_it(fiat32)
declare_it(donna32)

static bool verify(void)
{
	int ret;
	size_t i = 0;
	u8 out[CURVE25519_POINT_SIZE];

	for (i = 0; i < ARRAY_SIZE(curve25519_test_vectors); ++i) {
		test_it(donna64, {}, {});
		test_it(hacl64, {}, {});
		test_it(fiat64, {}, {});
		test_it(sandy2x, kernel_fpu_begin(), kernel_fpu_end());
		test_it(amd64, {}, {});
		test_it(precomp, {}, {});
		test_it(fiat32, {}, {});
		test_it(donna32, {}, {});
	}
	return true;
}

static int __init mod_init(void)
{
	enum { WARMUP = 5000, TRIALS = 10000, IDLE = 1 * 1000 };
	int ret = 0, i;
	cycles_t start_donna64, end_donna64;
	cycles_t start_hacl64, end_hacl64;
	cycles_t start_fiat64, end_fiat64;
	cycles_t start_sandy2x, end_sandy2x;
	cycles_t start_amd64, end_amd64;
	cycles_t start_precomp, end_precomp;
	cycles_t start_fiat32, end_fiat32;
	cycles_t start_donna32, end_donna32;
	unsigned long flags;
	DEFINE_SPINLOCK(lock);

	if (!verify())
		return -EBFONT;
	
	msleep(IDLE);

	spin_lock_irqsave(&lock, flags);

	do_it(donna64);
	do_it(hacl64);
	do_it(fiat64);
	kernel_fpu_begin();
	do_it(sandy2x);
	kernel_fpu_end();
	do_it(amd64);
	do_it(precomp);
	do_it(fiat32);
	do_it(donna32);

	spin_unlock_irqrestore(&lock, flags);
	
	report_it(donna64);
	report_it(hacl64);
	report_it(fiat64);
	report_it(sandy2x);
	report_it(amd64);
	report_it(precomp);
	report_it(fiat32);
	report_it(donna32);

	/* Don't let compiler be too clever. */
	dummy = ret;
	
	/* We should never actually agree to insert the module. Choosing
	 * -0x1000 here is an amazing hack. It causes the kernel to not
	 * actually load the module, while the standard userspace tools
	 * don't return an error, because it's too big. */
	return -0x1000;
}

module_init(mod_init);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("kBench9000 Cycle Counter");
MODULE_AUTHOR("Jason A. Donenfeld <Jason@zx2c4.com>");
