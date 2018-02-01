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


enum { POLY1305_MAC_SIZE = 16, POLY1305_KEY_SIZE = 32 };
u8 dummy_out[POLY1305_MAC_SIZE];
#include "test_vectors.h"

#define declare_it(name) \
  bool poly1305_ ## name(u8 tag[POLY1305_MAC_SIZE], const u8 * msg, const u32 len, const u8 key[POLY1305_KEY_SIZE]); \
static __always_inline int name(void) \
{ \
  return poly1305_ ## name(dummy_out, poly1305_test_vectors[0].input.data, poly1305_test_vectors[0].input.size, poly1305_test_vectors[0].key.data); \
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
	memset(out, __LINE__, POLY1305_MAC_SIZE); \
	before; \
	ret = poly1305_ ## name(out, poly1305_test_vectors[i].input.data,poly1305_test_vectors[i].input.size,poly1305_test_vectors[i].key.data); \
	after; \
	if (memcmp(out, poly1305_test_vectors[i].expected.data, POLY1305_MAC_SIZE)) { \
		pr_err(#name " self-test %zu: FAIL\n", i + 1); \
		return false; \
	} \
} while (0)

#define report_it(name) do { \
	pr_err("%lu: %7s: %llu cycles per call\n", stamp, #name, (end_ ## name - start_ ## name) / TRIALS); \
} while (0)


declare_it(hacl64)
declare_it(ref)

static bool verify(void)
{
	int ret;
	size_t i = 0;
	u8 out[POLY1305_MAC_SIZE];

	for (i = 0; i < ARRAY_SIZE(poly1305_test_vectors); ++i) {
	  		test_it(hacl64, {}, {});
	}
	for (i = 0; i < ARRAY_SIZE(poly1305_test_vectors); ++i) {
		test_it(ref, {}, {});
	}
	return true;
}

static int __init mod_init(void)
{
	enum { WARMUP = 5000, TRIALS = 10000, IDLE = 1 * 1000 };
	int ret = 0, i;
	cycles_t start_hacl64, end_hacl64;
	cycles_t start_ref, end_ref;
	unsigned long flags;
	DEFINE_SPINLOCK(lock);

	if (!verify())
		return -EBFONT;
	
	msleep(IDLE);

	spin_lock_irqsave(&lock, flags);

	do_it(hacl64);
	do_it(ref);

	spin_unlock_irqrestore(&lock, flags);
	
	report_it(hacl64);
	report_it(ref);

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
