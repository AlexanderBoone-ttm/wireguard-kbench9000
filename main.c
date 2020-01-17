/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/fpu/api.h>
#include <asm/simd.h>

static unsigned long stamp = 0;
module_param(stamp, ulong, 0);
int dummy;

static bool dangerous = false;
module_param(dangerous, bool, 0600);

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
	u32 eax = 0, ebx = 0, ecx = 0, edx = 0; \
	for (i = 0; i < WARMUP; ++i) \
		ret |= name(); \
	asm volatile("cpuid" : "+a" (eax), "=b" (ebx), "=d" (edx), "+c" (ecx)); \
	for (i = 0; i <= TRIALS; ++i) { \
		trial_times[i] = get_cycles(); \
		ret |= name(); \
	} \
	for (i = 0; i < TRIALS; ++i) \
		trial_times[i] = trial_times[i + 1] - trial_times[i]; \
	sort(trial_times, TRIALS + 1, sizeof(cycles_t), compare_cycles, NULL); \
	median_ ## name = trial_times[TRIALS / 2]; \
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
	pr_err("%lu: %12s: %6llu cycles per call\n", stamp, #name, median_ ## name); \
} while (0)


declare_it(donna64)
declare_it(hacl64)
declare_it(fiat64)
declare_it(sandy2x)
declare_it(amd64)
declare_it(precomp_bmi2)
declare_it(precomp_adx)
declare_it(ever64)
declare_it(fiat32)
declare_it(donna32)
declare_it(tweetnacl)

static int compare_cycles(const void *a, const void *b)
{
	return *((cycles_t *)a) - *((cycles_t *)b);
}

static bool verify(void)
{
	int ret;
	size_t i = 0;
	u8 out[CURVE25519_POINT_SIZE];

	for (i = 0; i < ARRAY_SIZE(curve25519_test_vectors); ++i) {
		test_it(donna64, {}, {});
		test_it(hacl64, {}, {});
		test_it(fiat64, {}, {});
		if (boot_cpu_has(X86_FEATURE_AVX) && cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL))
			test_it(sandy2x, kernel_fpu_begin(), kernel_fpu_end());
		if (boot_cpu_has(X86_FEATURE_BMI2))
			test_it(precomp_bmi2, {}, {});
		if (boot_cpu_has(X86_FEATURE_BMI2) && boot_cpu_has(X86_FEATURE_ADX)) {
			test_it(precomp_adx, {}, {});
			test_it(ever64, {}, {});
		}
		if (dangerous)
			test_it(amd64, {}, {});
		test_it(fiat32, {}, {});
		test_it(donna32, {}, {});
		test_it(tweetnacl, {}, {});
	}
	return true;
}

static int __init mod_init(void)
{
	enum { WARMUP = 6000, TRIALS = 5000, IDLE = 1 * 1000 };
	int ret = 0, i;
	cycles_t *trial_times;
	cycles_t median_donna64 = 0;
	cycles_t median_hacl64 = 0;
	cycles_t median_fiat64 = 0;
	cycles_t median_sandy2x = 0;
	cycles_t median_amd64 = 0;
	cycles_t median_precomp_bmi2 = 0;
	cycles_t median_precomp_adx = 0;
	cycles_t median_ever64 = 0;
	cycles_t median_fiat32 = 0;
	cycles_t median_donna32 = 0;
	cycles_t median_tweetnacl = 0;
	unsigned long flags;
	DEFINE_SPINLOCK(lock);

	if (!verify())
		return -EBFONT;

	trial_times = kcalloc(TRIALS + 1, sizeof(cycles_t), GFP_KERNEL);
	if (!trial_times)
		return -ENOMEM;

	msleep(IDLE);

	spin_lock_irqsave(&lock, flags);

	do_it(donna64);
	do_it(hacl64);
	do_it(fiat64);
	if (boot_cpu_has(X86_FEATURE_AVX) && cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL)) {
		kernel_fpu_begin();
		do_it(sandy2x);
		kernel_fpu_end();
	}
	if (boot_cpu_has(X86_FEATURE_BMI2))
		do_it(precomp_bmi2);
	if (boot_cpu_has(X86_FEATURE_BMI2) && boot_cpu_has(X86_FEATURE_ADX)) {
		do_it(precomp_adx);
		do_it(ever64);
	}
	if (dangerous)
		do_it(amd64);
	do_it(fiat32);
	do_it(donna32);
	do_it(tweetnacl);

	spin_unlock_irqrestore(&lock, flags);
	
	report_it(donna64);
	report_it(hacl64);
	report_it(fiat64);
	if (boot_cpu_has(X86_FEATURE_AVX) && cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL))
		report_it(sandy2x);
	if (boot_cpu_has(X86_FEATURE_BMI2))
		report_it(precomp_bmi2);
	if (boot_cpu_has(X86_FEATURE_BMI2) && boot_cpu_has(X86_FEATURE_ADX)) {
		report_it(precomp_adx);
		report_it(ever64);
	}
	if (dangerous)
		report_it(amd64);
	report_it(fiat32);
	report_it(donna32);
	report_it(tweetnacl);

	/* Don't let compiler be too clever. */
	dummy = ret;
	kfree(trial_times);
	
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
