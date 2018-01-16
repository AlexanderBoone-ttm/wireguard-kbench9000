/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/delay.h>
#include "function.h"

static unsigned long stamp = 0;
module_param(stamp, ulong, 0);
int dummy;

static int __init mod_init(void)
{
	int ret = 0, i;
	cycles_t start, end;
	unsigned long flags;
	DEFINE_SPINLOCK(lock);
	
	msleep(IDLE);

	spin_lock_irqsave(&lock, flags);
	
	for (i = 0; i < WARMUP; ++i)
		ret |= function();

	start = get_cycles();
	for (i = 0; i < TRIALS; ++i)
		ret |= function();
	end = get_cycles();

	spin_unlock_irqrestore(&lock, flags);
	
	pr_err("%lu: %llu cycles per call\n", stamp, (end - start) / TRIALS);

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
