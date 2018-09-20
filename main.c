/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <asm/neon.h>

static unsigned long stamp = 0;
module_param(stamp, ulong, 0);


static inline u32 get_pmccntr(void)
{
	u32 tsc;
	asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(tsc));
	return tsc;
}

#define declare_it(name) void chacha20_ ## name(u8 *dst, const u8 *src, u32 len, const u32 key[8], const u32 counter[4]);

static int compare_cycles(const void *a, const void *b)
{
	return *((u32 *)a) - *((u32 *)b);
}

#define do_it(name, len, before, after) ({ \
	before; \
	for (j = 0; j < WARMUP; ++j) \
		chacha20_ ## name(output, input, len, key, counter); \
	for (j = 0; j <= TRIALS; ++j) { \
		mb(); \
		trial_times[j] = get_pmccntr(); \
		chacha20_ ## name(output, input, len, key, counter); \
	} \
	after; \
	for (j = 0; j < TRIALS; ++j) \
		trial_times[j] = trial_times[j + 1] - trial_times[j]; \
	sort(trial_times, TRIALS + 1, sizeof(u32), compare_cycles, NULL); \
	trial_times[TRIALS / 2]; \
})

declare_it(generic)
declare_it(ossl_scalar)
declare_it(ossl_neon)
declare_it(ard_neon)

static int __init mod_init(void)
{
	enum { WARMUP = 500, TRIALS = 10000, IDLE = 1 * 1000, STEP = 32, STEPS = 128 };
	u32 key[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	u32 counter[4] = { 1, 2, 3, 4 };
	u8 *input = NULL, *output = NULL;
	u32 *trial_times = NULL;
	u32 median_generic[STEPS], median_ossl_scalar[STEPS], median_ossl_neon[STEPS], median_ard_neon[STEPS];
	size_t i, j;
	unsigned long flags;
	DEFINE_SPINLOCK(lock);

	asm volatile("mcr p15, 0, %0, c9, c14, 0" : : "r"(1));
	asm volatile("mcr p15, 0, %0, c9, c12, 0" : : "r"(29));
	asm volatile("mcr p15, 0, %0, c9, c12, 1" : : "r"(0x8000000f));

	trial_times = kcalloc(TRIALS + 1, sizeof(u32), GFP_KERNEL);
	if (!trial_times)
		goto out;
	input = kcalloc(STEP, STEPS, GFP_KERNEL);
	if (!input)
		goto out;
	output = kcalloc(STEP, STEPS, GFP_KERNEL);
	if (!output)
		goto out;

	for (i = 0; i < (STEP * STEPS); ++i)
		input[i] = i;
	
	msleep(IDLE);

	spin_lock_irqsave(&lock, flags);

	for (i = 0; i < STEPS; ++i) {
		median_generic[i] = do_it(generic, i * STEP, {}, {});
		median_ossl_scalar[i] = do_it(ossl_scalar, i * STEP, {}, {});
		median_ossl_neon[i] = do_it(ossl_neon, i * STEP, { kernel_neon_begin(); }, { kernel_neon_end(); });
		median_ard_neon[i] = do_it(ard_neon, i * STEP, { kernel_neon_begin(); }, { kernel_neon_end(); });
	}

	spin_unlock_irqrestore(&lock, flags);

	pr_err("%lu: %12s %12s %12s %12s %12s\n", stamp, "length", "generic", "ossl scalar", "ossl neon", "ard neon");

	for (i = 0; i < STEPS; ++i)
		pr_err("%lu: %12u %12u %12u %12u %12u\n", stamp, i * STEP,
		       median_generic[i], median_ossl_scalar[i], median_ossl_neon[i], median_ard_neon[i]);

out:
	kfree(trial_times);
	kfree(input);
	kfree(output);
	
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
