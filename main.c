/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/fpu/api.h>
#include <asm/simd.h>

static unsigned long stamp = 0;
module_param(stamp, ulong, 0);
int dummy;

enum { POLY1305_MAC_SIZE = 16, POLY1305_KEY_SIZE = 32 };
#include "test_vectors.h"

#define declare_it(name) \
bool poly1305_ ## name(u8 tag[POLY1305_MAC_SIZE], const u8 * msg, const u32 len, const u8 key[POLY1305_KEY_SIZE]); \
static __always_inline int name(size_t len) \
{ \
	return poly1305_ ## name(dummy_out, input_data, len, input_key); \
}

#define do_it(name) do { \
	for (i = 0; i < WARMUP; ++i) \
		ret |= name(sizeof(input_data)); \
	for (j = 0, s = STARTING_SIZE; j <= DOUBLING_STEPS; ++j, s *= 2) { \
		start_ ## name[j] = get_cycles(); \
		for (i = 0; i < TRIALS; ++i) \
			ret |= name(s); \
		end_ ## name[j] = get_cycles(); \
	} \
} while (0)

#define test_it(name, before, after) do { \
	memset(out, __LINE__, POLY1305_MAC_SIZE); \
	before; \
	ret = poly1305_ ## name(out, poly1305_testvecs[i].input, poly1305_testvecs[i].ilen, poly1305_testvecs[i].key); \
	after; \
	if (memcmp(out, poly1305_testvecs[i].output, POLY1305_MAC_SIZE)) { \
		pr_err(#name " self-test %zu: FAIL\n", i + 1); \
		return false; \
	} \
} while (0)

#define report_it(name) do { \
	char dec[20]; \
	size_t l; \
	pr_err("%lu: %11s:", stamp, #name); \
	for (j = 0, s = STARTING_SIZE; j <= DOUBLING_STEPS; ++j, s *= 2) { \
		memset(dec, 0, sizeof(dec)); \
		l = scnprintf(dec, sizeof(dec) - 2, "%llu", 100ULL * (end_ ## name[j] - start_ ## name[j]) / TRIALS / s); \
		dec[l] = dec[l - 1]; \
		dec[l - 1] = dec[l - 2]; \
		dec[l - 2] = '.'; \
		printk(KERN_CONT " %6s", dec); \
	} \
	printk(KERN_CONT "\n"); \
} while (0)

enum { WARMUP = 50000, TRIALS = 100000, IDLE = 1 * 1000, STARTING_SIZE = 128, DOUBLING_STEPS = 5 };
u8 dummy_out[POLY1305_MAC_SIZE];
u8 input_key[POLY1305_KEY_SIZE];
u8 input_data[STARTING_SIZE * (1ULL << DOUBLING_STEPS)];

declare_it(ref)
declare_it(ossl_c)
declare_it(ossl_amd64)
declare_it(ossl_avx)
declare_it(ossl_avx2)
declare_it(ossl_avx512)
declare_it(donna32)
declare_it(donna64)
declare_it(hacl32)
declare_it(hacl64)
declare_it(hacl32x1)
declare_it(hacl128)
declare_it(hacl256)

static bool verify(void)
{
	int ret;
	size_t i = 0;
	u8 out[POLY1305_MAC_SIZE];

	for (i = 0; i < ARRAY_SIZE(poly1305_testvecs); ++i) {
		test_it(ref, {}, {});
		test_it(ossl_c, {}, {});
		test_it(donna32, {}, {});
		test_it(donna64, {}, {});
		test_it(hacl32, {}, {});
		test_it(hacl32x1, {}, {});
		test_it(hacl64, {}, {});
		if (boot_cpu_has(X86_FEATURE_AVX) && cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL))
		  test_it(hacl128, kernel_fpu_begin(), kernel_fpu_end());
		if (boot_cpu_has(X86_FEATURE_AVX) && boot_cpu_has(X86_FEATURE_AVX2) && cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL))
		  test_it(hacl256, kernel_fpu_begin(), kernel_fpu_end());
		test_it(ossl_amd64, {}, {});
		if (boot_cpu_has(X86_FEATURE_AVX) && cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL))
			test_it(ossl_avx, kernel_fpu_begin(), kernel_fpu_end());
		if (boot_cpu_has(X86_FEATURE_AVX) && boot_cpu_has(X86_FEATURE_AVX2) && cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL))
			test_it(ossl_avx2, kernel_fpu_begin(), kernel_fpu_end());
		if (boot_cpu_has(X86_FEATURE_AVX) && boot_cpu_has(X86_FEATURE_AVX2) && boot_cpu_has(X86_FEATURE_AVX512F) && cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM | XFEATURE_MASK_AVX512, NULL))
			test_it(ossl_avx512, kernel_fpu_begin(), kernel_fpu_end());
	}
	return true;
}

static int __init mod_init(void)
{
	size_t s;
	int ret = 0, i, j;
	cycles_t start_ref[DOUBLING_STEPS + 1], end_ref[DOUBLING_STEPS + 1];
	cycles_t start_ossl_c[DOUBLING_STEPS + 1], end_ossl_c[DOUBLING_STEPS + 1];
	cycles_t start_ossl_amd64[DOUBLING_STEPS + 1], end_ossl_amd64[DOUBLING_STEPS + 1];
	cycles_t start_ossl_avx[DOUBLING_STEPS + 1], end_ossl_avx[DOUBLING_STEPS + 1];
	cycles_t start_ossl_avx2[DOUBLING_STEPS + 1], end_ossl_avx2[DOUBLING_STEPS + 1];
	cycles_t start_ossl_avx512[DOUBLING_STEPS + 1], end_ossl_avx512[DOUBLING_STEPS + 1];
	cycles_t start_donna32[DOUBLING_STEPS + 1], end_donna32[DOUBLING_STEPS + 1];
	cycles_t start_donna64[DOUBLING_STEPS + 1], end_donna64[DOUBLING_STEPS + 1];
	cycles_t start_hacl32[DOUBLING_STEPS + 1], end_hacl32[DOUBLING_STEPS + 1];
	
	cycles_t start_hacl32x1[DOUBLING_STEPS + 1], end_hacl32x1[DOUBLING_STEPS + 1];
	cycles_t start_hacl128[DOUBLING_STEPS + 1], end_hacl128[DOUBLING_STEPS + 1];
	cycles_t start_hacl256[DOUBLING_STEPS + 1], end_hacl256[DOUBLING_STEPS + 1];
	cycles_t start_hacl64[DOUBLING_STEPS + 1], end_hacl64[DOUBLING_STEPS + 1];
	unsigned long flags;
	DEFINE_SPINLOCK(lock);

	if (!verify())
		return -EBFONT;

	for (i = 0; i < sizeof(input_data); ++i)
		input_data[i] = i;
	for (i = 0; i < sizeof(input_key); ++i)
		input_key[i] = i;
	
	msleep(IDLE);

	kernel_fpu_begin();

	spin_lock_irqsave(&lock, flags);

	do_it(ref);
	do_it(ossl_c);
	do_it(donna32);
	do_it(donna64);
	do_it(hacl32);
	do_it(hacl32x1);
	if (boot_cpu_has(X86_FEATURE_AVX) && cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL))
	  do_it(hacl128);
	if (boot_cpu_has(X86_FEATURE_AVX) && boot_cpu_has(X86_FEATURE_AVX2) && cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL))
	  do_it(hacl256);
	do_it(hacl64);
	do_it(ossl_amd64);
	if (boot_cpu_has(X86_FEATURE_AVX) && cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL))
		do_it(ossl_avx);
	if (boot_cpu_has(X86_FEATURE_AVX) && boot_cpu_has(X86_FEATURE_AVX2) && cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL))
		do_it(ossl_avx2);
	if (boot_cpu_has(X86_FEATURE_AVX) && boot_cpu_has(X86_FEATURE_AVX2) && boot_cpu_has(X86_FEATURE_AVX512F) && cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM | XFEATURE_MASK_AVX512, NULL))
		do_it(ossl_avx512);

	spin_unlock_irqrestore(&lock, flags);


	kernel_fpu_end();
	
	pr_err("%lu:             ", stamp);
	for (j = 0, s = STARTING_SIZE; j <= DOUBLING_STEPS; ++j, s *= 2) \
		printk(KERN_CONT " \x1b[4m%6zu\x1b[24m", s);
	report_it(ref);
	report_it(ossl_c);
	report_it(donna32);
	report_it(donna64);
	report_it(hacl32);
	report_it(hacl32x1);
	report_it(hacl64);
	if (boot_cpu_has(X86_FEATURE_AVX) && cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL))
	  report_it(hacl128);
	if (boot_cpu_has(X86_FEATURE_AVX) && boot_cpu_has(X86_FEATURE_AVX2) && cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL))
	  report_it(hacl256);
	report_it(ossl_amd64);
	if (boot_cpu_has(X86_FEATURE_AVX) && cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL))
		report_it(ossl_avx);
	if (boot_cpu_has(X86_FEATURE_AVX) && boot_cpu_has(X86_FEATURE_AVX2) && cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL))
		report_it(ossl_avx2);
	if (boot_cpu_has(X86_FEATURE_AVX) && boot_cpu_has(X86_FEATURE_AVX2) && boot_cpu_has(X86_FEATURE_AVX512F) && cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM | XFEATURE_MASK_AVX512, NULL))
		report_it(ossl_avx512);

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
