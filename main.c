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

enum { BLOCKS_PER_CALL = 16 };

static u8 state[128];
static u8 input[64 * BLOCKS_PER_CALL];

#define declare_it(name) \
asmlinkage void blake2s_compress_ ## name(u8 state[128], const u8 *block, const size_t nblocks, const u32 inc); \
static __always_inline u8 name(void) \
{ \
	blake2s_compress_ ## name(state, input, BLOCKS_PER_CALL, 0); \
	return input[0]; \
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

#define report_it(name) do { \
	pr_err("%lu: %12s: %6llu cycles per block\n", stamp, #name, median_ ## name / BLOCKS_PER_CALL); \
} while (0)


declare_it(avx)
declare_it(avx512_ymm)
declare_it(avx512_zmm)

static int compare_cycles(const void *a, const void *b)
{
	return *((cycles_t *)a) - *((cycles_t *)b);
}

static int __init mod_init(void)
{
	enum { WARMUP = 6000, TRIALS = 5000, IDLE = 1 * 1000 };
	int ret = 0, i;
	cycles_t *trial_times;
	cycles_t median_avx = 0;
	cycles_t median_avx512_ymm = 0;
	cycles_t median_avx512_zmm = 0;
	unsigned long flags;
	DEFINE_SPINLOCK(lock);

	trial_times = kcalloc(TRIALS + 1, sizeof(cycles_t), GFP_KERNEL);
	if (!trial_times)
		return -ENOMEM;

	msleep(IDLE);

	spin_lock_irqsave(&lock, flags);

	kernel_fpu_begin();

	do_it(avx);
	do_it(avx512_ymm);
	do_it(avx512_zmm);

	kernel_fpu_end();

	spin_unlock_irqrestore(&lock, flags);
	
	report_it(avx);
	report_it(avx512_ymm);
	report_it(avx512_zmm);

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
