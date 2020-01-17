// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (c) 2016-2020 INRIA, CMU and Microsoft Corporation
 */

#include <linux/kernel.h>
#include <linux/string.h>

enum { CURVE25519_POINT_SIZE = 32 };

static __always_inline u64 eq_mask(u64 a, u64 b)
{
	u64 x = a ^ b;
	u64 minus_x = ~x + (u64)1U;
	u64 x_or_minus_x = x | minus_x;
	u64 xnx = x_or_minus_x >> (u32)63U;
	return xnx - (u64)1U;
}

static __always_inline u64 gte_mask(u64 a, u64 b)
{
	u64 x = a;
	u64 y = b;
	u64 x_xor_y = x ^ y;
	u64 x_sub_y = x - y;
	u64 x_sub_y_xor_y = x_sub_y ^ y;
	u64 q = x_xor_y | x_sub_y_xor_y;
	u64 x_xor_q = x ^ q;
	u64 x_xor_q_ = x_xor_q >> (u32)63U;
	return x_xor_q_ - (u64)1U;
}

// Computes the addition of four-element f1 with value in f2
// and returns the carry (if any)
static inline u64 add_scalar(u64 *out, const u64 *f1, u64 f2)
{
	u64 carry_r;

	asm volatile(
		// Clear registers to propagate the carry bit
		"  xor %%r8, %%r8;"
		"  xor %%r9, %%r9;"
		"  xor %%r10, %%r10;"
		"  xor %%r11, %%r11;"
		"  xor %1, %1;"

		// Begin addition chain
		"  addq 0(%3), %0;"
		"  movq %0, 0(%2);"
		"  adcxq 8(%3), %%r8;"
		"  movq %%r8, 8(%2);"
		"  adcxq 16(%3), %%r9;"
		"  movq %%r9, 16(%2);"
		"  adcxq 24(%3), %%r10;"
		"  movq %%r10, 24(%2);"

		// Return the carry bit in a register
		"  adcx %%r11, %1;"
	: "+&r" (f2), "=&r" (carry_r)
	: "r" (out), "r" (f1)
	: "%r8", "%r9", "%r10", "%r11", "memory", "cc"
	);

	return carry_r;
}

// Computes the field addition of two field elements
static inline void fadd(u64 *out, const u64 *f1, const u64 *f2)
{
	asm volatile(
		// Compute the raw addition of f1 + f2
		"  movq 0(%0), %%r8;"
		"  addq 0(%2), %%r8;"
		"  movq 8(%0), %%r9;"
		"  adcxq 8(%2), %%r9;"
		"  movq 16(%0), %%r10;"
		"  adcxq 16(%2), %%r10;"
		"  movq 24(%0), %%r11;"
		"  adcxq 24(%2), %%r11;"

		/////// Wrap the result back into the field //////

		// Step 1: Compute carry*38
		"  mov $0, %%rax;"
		"  mov $38, %0;"
		"  cmovc %0, %%rax;"

		// Step 2: Add carry*38 to the original sum
		"  xor %%rcx, %%rcx;"
		"  add %%rax, %%r8;"
		"  adcx %%rcx, %%r9;"
		"  movq %%r9, 8(%1);"
		"  adcx %%rcx, %%r10;"
		"  movq %%r10, 16(%1);"
		"  adcx %%rcx, %%r11;"
		"  movq %%r11, 24(%1);"

		// Step 3: Fold the carry bit back in; guaranteed not to carry at this point
		"  mov $0, %%rax;"
		"  cmovc %0, %%rax;"
		"  add %%rax, %%r8;"
		"  movq %%r8, 0(%1);"
	: "+&r" (f2)
	: "r" (out), "r" (f1)
	: "%rax", "%rcx", "%r8", "%r9", "%r10", "%r11", "memory", "cc"
	);
}

// Computes the field substraction of two field elements
static inline void fsub(u64 *out, const u64 *f1, const u64 *f2)
{
	asm volatile(
		// Compute the raw substraction of f1-f2
		"  movq 0(%1), %%r8;"
		"  subq 0(%2), %%r8;"
		"  movq 8(%1), %%r9;"
		"  sbbq 8(%2), %%r9;"
		"  movq 16(%1), %%r10;"
		"  sbbq 16(%2), %%r10;"
		"  movq 24(%1), %%r11;"
		"  sbbq 24(%2), %%r11;"

		/////// Wrap the result back into the field //////

		// Step 1: Compute carry*38
		"  mov $0, %%rax;"
		"  mov $38, %%rcx;"
		"  cmovc %%rcx, %%rax;"

		// Step 2: Substract carry*38 from the original difference
		"  sub %%rax, %%r8;"
		"  sbb $0, %%r9;"
		"  sbb $0, %%r10;"
		"  sbb $0, %%r11;"

		// Step 3: Fold the carry bit back in; guaranteed not to carry at this point
		"  mov $0, %%rax;"
		"  cmovc %%rcx, %%rax;"
		"  sub %%rax, %%r8;"

		// Store the result
		"  movq %%r8, 0(%0);"
		"  movq %%r9, 8(%0);"
		"  movq %%r10, 16(%0);"
		"  movq %%r11, 24(%0);"
	:
	: "r" (out), "r" (f1), "r" (f2)
	: "%rax", "%rcx", "%r8", "%r9", "%r10", "%r11", "memory", "cc"
	);
}

// Computes a field multiplication: out <- f1 * f2
// Uses the 8-element buffer tmp for intermediate results
static inline void fmul(u64 *out, const u64 *f1, const u64 *f2, u64 *tmp)
{
	asm volatile(
		/////// Compute the raw multiplication: tmp <- src1 * src2 //////

		// Compute src1[0] * src2
		"  movq 0(%1), %%rdx;"
		"  mulxq 0(%3), %%r8, %%r9;"       "  xor %%r10, %%r10;"     "  movq %%r8, 0(%0);"
		"  mulxq 8(%3), %%r10, %%r11;"     "  adox %%r9, %%r10;"     "  movq %%r10, 8(%0);"
		"  mulxq 16(%3), %%r12, %%r13;"    "  adox %%r11, %%r12;"
		"  mulxq 24(%3), %%r14, %%rdx;"    "  adox %%r13, %%r14;"    "  mov $0, %%rax;"
		                                   "  adox %%rdx, %%rax;"

		// Compute src1[1] * src2
		"  movq 8(%1), %%rdx;"
		"  mulxq 0(%3), %%r8, %%r9;"       "  xor %%r10, %%r10;"     "  adcxq 8(%0), %%r8;"    "  movq %%r8, 8(%0);"
		"  mulxq 8(%3), %%r10, %%r11;"     "  adox %%r9, %%r10;"     "  adcx %%r12, %%r10;"    "  movq %%r10, 16(%0);"
		"  mulxq 16(%3), %%r12, %%r13;"    "  adox %%r11, %%r12;"    "  adcx %%r14, %%r12;"    "  mov $0, %%r8;"
		"  mulxq 24(%3), %%r14, %%rdx;"    "  adox %%r13, %%r14;"    "  adcx %%rax, %%r14;"    "  mov $0, %%rax;"
		                                   "  adox %%rdx, %%rax;"    "  adcx %%r8, %%rax;"


		// Compute src1[2] * src2
		"  movq 16(%1), %%rdx;"
		"  mulxq 0(%3), %%r8, %%r9;"       "  xor %%r10, %%r10;"    "  adcxq 16(%0), %%r8;"    "  movq %%r8, 16(%0);"
		"  mulxq 8(%3), %%r10, %%r11;"     "  adox %%r9, %%r10;"     "  adcx %%r12, %%r10;"    "  movq %%r10, 24(%0);"
		"  mulxq 16(%3), %%r12, %%r13;"    "  adox %%r11, %%r12;"    "  adcx %%r14, %%r12;"    "  mov $0, %%r8;"
		"  mulxq 24(%3), %%r14, %%rdx;"    "  adox %%r13, %%r14;"    "  adcx %%rax, %%r14;"    "  mov $0, %%rax;"
		                                   "  adox %%rdx, %%rax;"    "  adcx %%r8, %%rax;"


		// Compute src1[3] * src2
		"  movq 24(%1), %%rdx;"
		"  mulxq 0(%3), %%r8, %%r9;"       "  xor %%r10, %%r10;"    "  adcxq 24(%0), %%r8;"    "  movq %%r8, 24(%0);"
		"  mulxq 8(%3), %%r10, %%r11;"     "  adox %%r9, %%r10;"     "  adcx %%r12, %%r10;"    "  movq %%r10, 32(%0);"
		"  mulxq 16(%3), %%r12, %%r13;"    "  adox %%r11, %%r12;"    "  adcx %%r14, %%r12;"    "  movq %%r12, 40(%0);"    "  mov $0, %%r8;"
		"  mulxq 24(%3), %%r14, %%rdx;"    "  adox %%r13, %%r14;"    "  adcx %%rax, %%r14;"    "  movq %%r14, 48(%0);"    "  mov $0, %%rax;"
		                                   "  adox %%rdx, %%rax;"    "  adcx %%r8, %%rax;"     "  movq %%rax, 56(%0);"

		// Line up pointers
		"  mov %0, %1;"
		"  mov %2, %0;"

		/////// Wrap the result back into the field //////

		// Step 1: Compute dst + carry == tmp_hi * 38 + tmp_lo
		"  mov $38, %%rdx;"
		"  mulxq 32(%1), %%r8, %%r13;"
		"  xor %3, %3;"
		"  adoxq 0(%1), %%r8;"
		"  mulxq 40(%1), %%r9, %%r12;"
		"  adcx %%r13, %%r9;"
		"  adoxq 8(%1), %%r9;"
		"  mulxq 48(%1), %%r10, %%r13;"
		"  adcx %%r12, %%r10;"
		"  adoxq 16(%1), %%r10;"
		"  mulxq 56(%1), %%r11, %%rax;"
		"  adcx %%r13, %%r11;"
		"  adoxq 24(%1), %%r11;"
		"  adcx %3, %%rax;"
		"  adox %3, %%rax;"
		"  imul %%rdx, %%rax;"

		// Step 2: Fold the carry back into dst
		"  add %%rax, %%r8;"
		"  adcx %3, %%r9;"
		"  movq %%r9, 8(%0);"
		"  adcx %3, %%r10;"
		"  movq %%r10, 16(%0);"
		"  adcx %3, %%r11;"
		"  movq %%r11, 24(%0);"

		// Step 3: Fold the carry bit back in; guaranteed not to carry at this point
		"  mov $0, %%rax;"
		"  cmovc %%rdx, %%rax;"
		"  add %%rax, %%r8;"
		"  movq %%r8, 0(%0);"
	: "+&r" (tmp), "+&r" (f1), "+&r" (out), "+&r" (f2)
	:
	: "%rax", "%rdx", "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "memory", "cc"
	);
}

// Computes two field multiplications:
//   out[0] <- f1[0] * f2[0]
//   out[1] <- f1[1] * f2[1]
// Uses the 16-element buffer tmp for intermediate results:
static inline void fmul2(u64 *out, const u64 *f1, const u64 *f2, u64 *tmp)
{
	asm volatile(
		/////// Compute the raw multiplication tmp[0] <- f1[0] * f2[0] //////

		// Compute src1[0] * src2
		"  movq 0(%1), %%rdx;"
		"  mulxq 0(%3), %%r8, %%r9;"       "  xor %%r10, %%r10;"     "  movq %%r8, 0(%0);"
		"  mulxq 8(%3), %%r10, %%r11;"     "  adox %%r9, %%r10;"     "  movq %%r10, 8(%0);"
		"  mulxq 16(%3), %%r12, %%r13;"    "  adox %%r11, %%r12;"
		"  mulxq 24(%3), %%r14, %%rdx;"    "  adox %%r13, %%r14;"    "  mov $0, %%rax;"
		                                   "  adox %%rdx, %%rax;"

		// Compute src1[1] * src2
		"  movq 8(%1), %%rdx;"
		"  mulxq 0(%3), %%r8, %%r9;"       "  xor %%r10, %%r10;"     "  adcxq 8(%0), %%r8;"    "  movq %%r8, 8(%0);"
		"  mulxq 8(%3), %%r10, %%r11;"     "  adox %%r9, %%r10;"     "  adcx %%r12, %%r10;"    "  movq %%r10, 16(%0);"
		"  mulxq 16(%3), %%r12, %%r13;"    "  adox %%r11, %%r12;"    "  adcx %%r14, %%r12;"    "  mov $0, %%r8;"
		"  mulxq 24(%3), %%r14, %%rdx;"    "  adox %%r13, %%r14;"    "  adcx %%rax, %%r14;"    "  mov $0, %%rax;"
		                                   "  adox %%rdx, %%rax;"    "  adcx %%r8, %%rax;"


		// Compute src1[2] * src2
		"  movq 16(%1), %%rdx;"
		"  mulxq 0(%3), %%r8, %%r9;"       "  xor %%r10, %%r10;"    "  adcxq 16(%0), %%r8;"    "  movq %%r8, 16(%0);"
		"  mulxq 8(%3), %%r10, %%r11;"     "  adox %%r9, %%r10;"     "  adcx %%r12, %%r10;"    "  movq %%r10, 24(%0);"
		"  mulxq 16(%3), %%r12, %%r13;"    "  adox %%r11, %%r12;"    "  adcx %%r14, %%r12;"    "  mov $0, %%r8;"
		"  mulxq 24(%3), %%r14, %%rdx;"    "  adox %%r13, %%r14;"    "  adcx %%rax, %%r14;"    "  mov $0, %%rax;"
		                                   "  adox %%rdx, %%rax;"    "  adcx %%r8, %%rax;"


		// Compute src1[3] * src2
		"  movq 24(%1), %%rdx;"
		"  mulxq 0(%3), %%r8, %%r9;"       "  xor %%r10, %%r10;"    "  adcxq 24(%0), %%r8;"    "  movq %%r8, 24(%0);"
		"  mulxq 8(%3), %%r10, %%r11;"     "  adox %%r9, %%r10;"     "  adcx %%r12, %%r10;"    "  movq %%r10, 32(%0);"
		"  mulxq 16(%3), %%r12, %%r13;"    "  adox %%r11, %%r12;"    "  adcx %%r14, %%r12;"    "  movq %%r12, 40(%0);"    "  mov $0, %%r8;"
		"  mulxq 24(%3), %%r14, %%rdx;"    "  adox %%r13, %%r14;"    "  adcx %%rax, %%r14;"    "  movq %%r14, 48(%0);"    "  mov $0, %%rax;"
		                                   "  adox %%rdx, %%rax;"    "  adcx %%r8, %%rax;"     "  movq %%rax, 56(%0);"

		/////// Compute the raw multiplication tmp[1] <- f1[1] * f2[1] //////

		// Compute src1[0] * src2
		"  movq 32(%1), %%rdx;"
		"  mulxq 32(%3), %%r8, %%r9;"       "  xor %%r10, %%r10;"     "  movq %%r8, 64(%0);"
		"  mulxq 40(%3), %%r10, %%r11;"     "  adox %%r9, %%r10;"     "  movq %%r10, 72(%0);"
		"  mulxq 48(%3), %%r12, %%r13;"    "  adox %%r11, %%r12;"
		"  mulxq 56(%3), %%r14, %%rdx;"    "  adox %%r13, %%r14;"    "  mov $0, %%rax;"
		                                   "  adox %%rdx, %%rax;"

		// Compute src1[1] * src2
		"  movq 40(%1), %%rdx;"
		"  mulxq 32(%3), %%r8, %%r9;"       "  xor %%r10, %%r10;"     "  adcxq 72(%0), %%r8;"    "  movq %%r8, 72(%0);"
		"  mulxq 40(%3), %%r10, %%r11;"     "  adox %%r9, %%r10;"     "  adcx %%r12, %%r10;"    "  movq %%r10, 80(%0);"
		"  mulxq 48(%3), %%r12, %%r13;"    "  adox %%r11, %%r12;"    "  adcx %%r14, %%r12;"    "  mov $0, %%r8;"
		"  mulxq 56(%3), %%r14, %%rdx;"    "  adox %%r13, %%r14;"    "  adcx %%rax, %%r14;"    "  mov $0, %%rax;"
		                                   "  adox %%rdx, %%rax;"    "  adcx %%r8, %%rax;"


		// Compute src1[2] * src2
		"  movq 48(%1), %%rdx;"
		"  mulxq 32(%3), %%r8, %%r9;"       "  xor %%r10, %%r10;"    "  adcxq 80(%0), %%r8;"    "  movq %%r8, 80(%0);"
		"  mulxq 40(%3), %%r10, %%r11;"     "  adox %%r9, %%r10;"     "  adcx %%r12, %%r10;"    "  movq %%r10, 88(%0);"
		"  mulxq 48(%3), %%r12, %%r13;"    "  adox %%r11, %%r12;"    "  adcx %%r14, %%r12;"    "  mov $0, %%r8;"
		"  mulxq 56(%3), %%r14, %%rdx;"    "  adox %%r13, %%r14;"    "  adcx %%rax, %%r14;"    "  mov $0, %%rax;"
		                                   "  adox %%rdx, %%rax;"    "  adcx %%r8, %%rax;"


		// Compute src1[3] * src2
		"  movq 56(%1), %%rdx;"
		"  mulxq 32(%3), %%r8, %%r9;"       "  xor %%r10, %%r10;"    "  adcxq 88(%0), %%r8;"    "  movq %%r8, 88(%0);"
		"  mulxq 40(%3), %%r10, %%r11;"     "  adox %%r9, %%r10;"     "  adcx %%r12, %%r10;"    "  movq %%r10, 96(%0);"
		"  mulxq 48(%3), %%r12, %%r13;"    "  adox %%r11, %%r12;"    "  adcx %%r14, %%r12;"    "  movq %%r12, 104(%0);"    "  mov $0, %%r8;"
		"  mulxq 56(%3), %%r14, %%rdx;"    "  adox %%r13, %%r14;"    "  adcx %%rax, %%r14;"    "  movq %%r14, 112(%0);"    "  mov $0, %%rax;"
		                                   "  adox %%rdx, %%rax;"    "  adcx %%r8, %%rax;"     "  movq %%rax, 120(%0);"

		// Line up pointers
		"  mov %0, %1;"
		"  mov %2, %0;"

		/////// Wrap the results back into the field //////

		// Step 1: Compute dst + carry == tmp_hi * 38 + tmp_lo
		"  mov $38, %%rdx;"
		"  mulxq 32(%1), %%r8, %%r13;"
		"  xor %3, %3;"
		"  adoxq 0(%1), %%r8;"
		"  mulxq 40(%1), %%r9, %%r12;"
		"  adcx %%r13, %%r9;"
		"  adoxq 8(%1), %%r9;"
		"  mulxq 48(%1), %%r10, %%r13;"
		"  adcx %%r12, %%r10;"
		"  adoxq 16(%1), %%r10;"
		"  mulxq 56(%1), %%r11, %%rax;"
		"  adcx %%r13, %%r11;"
		"  adoxq 24(%1), %%r11;"
		"  adcx %3, %%rax;"
		"  adox %3, %%rax;"
		"  imul %%rdx, %%rax;"

		// Step 2: Fold the carry back into dst
		"  add %%rax, %%r8;"
		"  adcx %3, %%r9;"
		"  movq %%r9, 8(%0);"
		"  adcx %3, %%r10;"
		"  movq %%r10, 16(%0);"
		"  adcx %3, %%r11;"
		"  movq %%r11, 24(%0);"

		// Step 3: Fold the carry bit back in; guaranteed not to carry at this point
		"  mov $0, %%rax;"
		"  cmovc %%rdx, %%rax;"
		"  add %%rax, %%r8;"
		"  movq %%r8, 0(%0);"

		// Step 1: Compute dst + carry == tmp_hi * 38 + tmp_lo
		"  mov $38, %%rdx;"
		"  mulxq 96(%1), %%r8, %%r13;"
		"  xor %3, %3;"
		"  adoxq 64(%1), %%r8;"
		"  mulxq 104(%1), %%r9, %%r12;"
		"  adcx %%r13, %%r9;"
		"  adoxq 72(%1), %%r9;"
		"  mulxq 112(%1), %%r10, %%r13;"
		"  adcx %%r12, %%r10;"
		"  adoxq 80(%1), %%r10;"
		"  mulxq 120(%1), %%r11, %%rax;"
		"  adcx %%r13, %%r11;"
		"  adoxq 88(%1), %%r11;"
		"  adcx %3, %%rax;"
		"  adox %3, %%rax;"
		"  imul %%rdx, %%rax;"

		// Step 2: Fold the carry back into dst
		"  add %%rax, %%r8;"
		"  adcx %3, %%r9;"
		"  movq %%r9, 40(%0);"
		"  adcx %3, %%r10;"
		"  movq %%r10, 48(%0);"
		"  adcx %3, %%r11;"
		"  movq %%r11, 56(%0);"

		// Step 3: Fold the carry bit back in; guaranteed not to carry at this point
		"  mov $0, %%rax;"
		"  cmovc %%rdx, %%rax;"
		"  add %%rax, %%r8;"
		"  movq %%r8, 32(%0);"
	: "+&r" (tmp), "+&r" (f1), "+&r" (out), "+&r" (f2)
	:
	: "%rax", "%rdx", "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "memory", "cc"
	);
}

// Computes the field multiplication of four-element f1 with value in f2
static inline void fmul_scalar(u64 *out, const u64 *f1, u64 f2)
{
	register u64 f2_r asm("rdx") = f2;

	asm volatile(
		// Compute the raw multiplication of f1*f2
		"  mulxq 0(%2), %%r8, %%rcx;"      // f1[0]*f2
		"  mulxq 8(%2), %%r9, %%r12;"      // f1[1]*f2
		"  add %%rcx, %%r9;"
		"  mov $0, %%rcx;"
		"  mulxq 16(%2), %%r10, %%r13;"    // f1[2]*f2
		"  adcx %%r12, %%r10;"
		"  mulxq 24(%2), %%r11, %%rax;"    // f1[3]*f2
		"  adcx %%r13, %%r11;"
		"  adcx %%rcx, %%rax;"

		/////// Wrap the result back into the field //////

		// Step 1: Compute carry*38
		"  mov $38, %%rdx;"
		"  imul %%rdx, %%rax;"

		// Step 2: Fold the carry back into dst
		"  add %%rax, %%r8;"
		"  adcx %%rcx, %%r9;"
		"  movq %%r9, 8(%1);"
		"  adcx %%rcx, %%r10;"
		"  movq %%r10, 16(%1);"
		"  adcx %%rcx, %%r11;"
		"  movq %%r11, 24(%1);"

		// Step 3: Fold the carry bit back in; guaranteed not to carry at this point
		"  mov $0, %%rax;"
		"  cmovc %%rdx, %%rax;"
		"  add %%rax, %%r8;"
		"  movq %%r8, 0(%1);"
	: "+&r" (f2_r)
	: "r" (out), "r" (f1)
	: "%rax", "%rcx", "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "memory", "cc"
	);
}

// Computes p1 <- bit ? p2 : p1 in constant time
static inline void cswap2(u64 bit, const u64 *p1, const u64 *p2)
{
	asm volatile(
		// Invert the polarity of bit to match cmov expectations
		"  add $18446744073709551615, %0;"

		// cswap p1[0], p2[0]
		"  movq 0(%1), %%r8;"
		"  movq 0(%2), %%r9;"
		"  mov %%r8, %%r10;"
		"  cmovc %%r9, %%r8;"
		"  cmovc %%r10, %%r9;"
		"  movq %%r8, 0(%1);"
		"  movq %%r9, 0(%2);"

		// cswap p1[1], p2[1]
		"  movq 8(%1), %%r8;"
		"  movq 8(%2), %%r9;"
		"  mov %%r8, %%r10;"
		"  cmovc %%r9, %%r8;"
		"  cmovc %%r10, %%r9;"
		"  movq %%r8, 8(%1);"
		"  movq %%r9, 8(%2);"

		// cswap p1[2], p2[2]
		"  movq 16(%1), %%r8;"
		"  movq 16(%2), %%r9;"
		"  mov %%r8, %%r10;"
		"  cmovc %%r9, %%r8;"
		"  cmovc %%r10, %%r9;"
		"  movq %%r8, 16(%1);"
		"  movq %%r9, 16(%2);"

		// cswap p1[3], p2[3]
		"  movq 24(%1), %%r8;"
		"  movq 24(%2), %%r9;"
		"  mov %%r8, %%r10;"
		"  cmovc %%r9, %%r8;"
		"  cmovc %%r10, %%r9;"
		"  movq %%r8, 24(%1);"
		"  movq %%r9, 24(%2);"

		// cswap p1[4], p2[4]
		"  movq 32(%1), %%r8;"
		"  movq 32(%2), %%r9;"
		"  mov %%r8, %%r10;"
		"  cmovc %%r9, %%r8;"
		"  cmovc %%r10, %%r9;"
		"  movq %%r8, 32(%1);"
		"  movq %%r9, 32(%2);"

		// cswap p1[5], p2[5]
		"  movq 40(%1), %%r8;"
		"  movq 40(%2), %%r9;"
		"  mov %%r8, %%r10;"
		"  cmovc %%r9, %%r8;"
		"  cmovc %%r10, %%r9;"
		"  movq %%r8, 40(%1);"
		"  movq %%r9, 40(%2);"

		// cswap p1[6], p2[6]
		"  movq 48(%1), %%r8;"
		"  movq 48(%2), %%r9;"
		"  mov %%r8, %%r10;"
		"  cmovc %%r9, %%r8;"
		"  cmovc %%r10, %%r9;"
		"  movq %%r8, 48(%1);"
		"  movq %%r9, 48(%2);"

		// cswap p1[7], p2[7]
		"  movq 56(%1), %%r8;"
		"  movq 56(%2), %%r9;"
		"  mov %%r8, %%r10;"
		"  cmovc %%r9, %%r8;"
		"  cmovc %%r10, %%r9;"
		"  movq %%r8, 56(%1);"
		"  movq %%r9, 56(%2);"
	: "+&r" (bit)
	: "r" (p1), "r" (p2)
	: "%r8", "%r9", "%r10", "memory", "cc"
	);
}

// Computes the square of a field element: out <- f * f
// Uses the 8-element buffer tmp for intermediate results
static inline void fsqr(u64 *out, const u64 *f, u64 *tmp)
{
	asm volatile(
		/////// Compute the raw multiplication: tmp <- f * f //////

		// Step 1: Compute all partial products
		"  movq 0(%1), %%rdx;"                                       // f[0]
		"  mulxq 8(%1), %%r8, %%r14;"      "  xor %%r15, %%r15;"     // f[1]*f[0]
		"  mulxq 16(%1), %%r9, %%r10;"     "  adcx %%r14, %%r9;"     // f[2]*f[0]
		"  mulxq 24(%1), %%rax, %%rcx;"    "  adcx %%rax, %%r10;"    // f[3]*f[0]
		"  movq 24(%1), %%rdx;"                                      // f[3]
		"  mulxq 8(%1), %%r11, %%r12;"     "  adcx %%rcx, %%r11;"    // f[1]*f[3]
		"  mulxq 16(%1), %%rax, %%r13;"    "  adcx %%rax, %%r12;"    // f[2]*f[3]
		"  movq 8(%1), %%rdx;"             "  adcx %%r15, %%r13;"    // f1
		"  mulxq 16(%1), %%rax, %%rcx;"    "  mov $0, %%r14;"        // f[2]*f[1]

		// Step 2: Compute two parallel carry chains
		"  xor %%r15, %%r15;"
		"  adox %%rax, %%r10;"
		"  adcx %%r8, %%r8;"
		"  adox %%rcx, %%r11;"
		"  adcx %%r9, %%r9;"
		"  adox %%r15, %%r12;"
		"  adcx %%r10, %%r10;"
		"  adox %%r15, %%r13;"
		"  adcx %%r11, %%r11;"
		"  adox %%r15, %%r14;"
		"  adcx %%r12, %%r12;"
		"  adcx %%r13, %%r13;"
		"  adcx %%r14, %%r14;"

		// Step 3: Compute intermediate squares
		"  movq 0(%1), %%rdx;"     "  mulx %%rdx, %%rax, %%rcx;"    // f[0]^2
		                           "  movq %%rax, 0(%0);"
		"  add %%rcx, %%r8;"       "  movq %%r8, 8(%0);"
		"  movq 8(%1), %%rdx;"     "  mulx %%rdx, %%rax, %%rcx;"    // f[1]^2
		"  adcx %%rax, %%r9;"      "  movq %%r9, 16(%0);"
		"  adcx %%rcx, %%r10;"     "  movq %%r10, 24(%0);"
		"  movq 16(%1), %%rdx;"    "  mulx %%rdx, %%rax, %%rcx;"    // f[2]^2
		"  adcx %%rax, %%r11;"     "  movq %%r11, 32(%0);"
		"  adcx %%rcx, %%r12;"     "  movq %%r12, 40(%0);"
		"  movq 24(%1), %%rdx;"    "  mulx %%rdx, %%rax, %%rcx;"    // f[3]^2
		"  adcx %%rax, %%r13;"     "  movq %%r13, 48(%0);"
		"  adcx %%rcx, %%r14;"     "  movq %%r14, 56(%0);"

		// Line up pointers
		"  mov %0, %1;"
		"  mov %2, %0;"

		/////// Wrap the result back into the field //////

		// Step 1: Compute dst + carry == tmp_hi * 38 + tmp_lo
		"  mov $38, %%rdx;"
		"  mulxq 32(%1), %%r8, %%r13;"
		"  xor %%rcx, %%rcx;"
		"  adoxq 0(%1), %%r8;"
		"  mulxq 40(%1), %%r9, %%r12;"
		"  adcx %%r13, %%r9;"
		"  adoxq 8(%1), %%r9;"
		"  mulxq 48(%1), %%r10, %%r13;"
		"  adcx %%r12, %%r10;"
		"  adoxq 16(%1), %%r10;"
		"  mulxq 56(%1), %%r11, %%rax;"
		"  adcx %%r13, %%r11;"
		"  adoxq 24(%1), %%r11;"
		"  adcx %%rcx, %%rax;"
		"  adox %%rcx, %%rax;"
		"  imul %%rdx, %%rax;"

		// Step 2: Fold the carry back into dst
		"  add %%rax, %%r8;"
		"  adcx %%rcx, %%r9;"
		"  movq %%r9, 8(%0);"
		"  adcx %%rcx, %%r10;"
		"  movq %%r10, 16(%0);"
		"  adcx %%rcx, %%r11;"
		"  movq %%r11, 24(%0);"

		// Step 3: Fold the carry bit back in; guaranteed not to carry at this point
		"  mov $0, %%rax;"
		"  cmovc %%rdx, %%rax;"
		"  add %%rax, %%r8;"
		"  movq %%r8, 0(%0);"
	: "+&r" (tmp), "+&r" (f), "+&r" (out)
	:
	: "%rax", "%rcx", "%rdx", "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15", "memory", "cc"
	);
}

// Computes two field squarings:
//   out[0] <- f[0] * f[0]
//   out[1] <- f[1] * f[1]
// Uses the 16-element buffer tmp for intermediate results
static inline void fsqr2(u64 *out, const u64 *f, u64 *tmp)
{
	asm volatile(
		// Step 1: Compute all partial products
		"  movq 0(%1), %%rdx;"                                       // f[0]
		"  mulxq 8(%1), %%r8, %%r14;"      "  xor %%r15, %%r15;"     // f[1]*f[0]
		"  mulxq 16(%1), %%r9, %%r10;"     "  adcx %%r14, %%r9;"     // f[2]*f[0]
		"  mulxq 24(%1), %%rax, %%rcx;"    "  adcx %%rax, %%r10;"    // f[3]*f[0]
		"  movq 24(%1), %%rdx;"                                      // f[3]
		"  mulxq 8(%1), %%r11, %%r12;"     "  adcx %%rcx, %%r11;"    // f[1]*f[3]
		"  mulxq 16(%1), %%rax, %%r13;"    "  adcx %%rax, %%r12;"    // f[2]*f[3]
		"  movq 8(%1), %%rdx;"             "  adcx %%r15, %%r13;"    // f1
		"  mulxq 16(%1), %%rax, %%rcx;"    "  mov $0, %%r14;"        // f[2]*f[1]

		// Step 2: Compute two parallel carry chains
		"  xor %%r15, %%r15;"
		"  adox %%rax, %%r10;"
		"  adcx %%r8, %%r8;"
		"  adox %%rcx, %%r11;"
		"  adcx %%r9, %%r9;"
		"  adox %%r15, %%r12;"
		"  adcx %%r10, %%r10;"
		"  adox %%r15, %%r13;"
		"  adcx %%r11, %%r11;"
		"  adox %%r15, %%r14;"
		"  adcx %%r12, %%r12;"
		"  adcx %%r13, %%r13;"
		"  adcx %%r14, %%r14;"

		// Step 3: Compute intermediate squares
		"  movq 0(%1), %%rdx;"     "  mulx %%rdx, %%rax, %%rcx;"    // f[0]^2
		                           "  movq %%rax, 0(%0);"
		"  add %%rcx, %%r8;"       "  movq %%r8, 8(%0);"
		"  movq 8(%1), %%rdx;"     "  mulx %%rdx, %%rax, %%rcx;"    // f[1]^2
		"  adcx %%rax, %%r9;"      "  movq %%r9, 16(%0);"
		"  adcx %%rcx, %%r10;"     "  movq %%r10, 24(%0);"
		"  movq 16(%1), %%rdx;"    "  mulx %%rdx, %%rax, %%rcx;"    // f[2]^2
		"  adcx %%rax, %%r11;"     "  movq %%r11, 32(%0);"
		"  adcx %%rcx, %%r12;"     "  movq %%r12, 40(%0);"
		"  movq 24(%1), %%rdx;"    "  mulx %%rdx, %%rax, %%rcx;"    // f[3]^2
		"  adcx %%rax, %%r13;"     "  movq %%r13, 48(%0);"
		"  adcx %%rcx, %%r14;"     "  movq %%r14, 56(%0);"

		// Step 1: Compute all partial products
		"  movq 32(%1), %%rdx;"                                       // f[0]
		"  mulxq 40(%1), %%r8, %%r14;"      "  xor %%r15, %%r15;"     // f[1]*f[0]
		"  mulxq 48(%1), %%r9, %%r10;"     "  adcx %%r14, %%r9;"     // f[2]*f[0]
		"  mulxq 56(%1), %%rax, %%rcx;"    "  adcx %%rax, %%r10;"    // f[3]*f[0]
		"  movq 56(%1), %%rdx;"                                      // f[3]
		"  mulxq 40(%1), %%r11, %%r12;"     "  adcx %%rcx, %%r11;"    // f[1]*f[3]
		"  mulxq 48(%1), %%rax, %%r13;"    "  adcx %%rax, %%r12;"    // f[2]*f[3]
		"  movq 40(%1), %%rdx;"             "  adcx %%r15, %%r13;"    // f1
		"  mulxq 48(%1), %%rax, %%rcx;"    "  mov $0, %%r14;"        // f[2]*f[1]

		// Step 2: Compute two parallel carry chains
		"  xor %%r15, %%r15;"
		"  adox %%rax, %%r10;"
		"  adcx %%r8, %%r8;"
		"  adox %%rcx, %%r11;"
		"  adcx %%r9, %%r9;"
		"  adox %%r15, %%r12;"
		"  adcx %%r10, %%r10;"
		"  adox %%r15, %%r13;"
		"  adcx %%r11, %%r11;"
		"  adox %%r15, %%r14;"
		"  adcx %%r12, %%r12;"
		"  adcx %%r13, %%r13;"
		"  adcx %%r14, %%r14;"

		// Step 3: Compute intermediate squares
		"  movq 32(%1), %%rdx;"     "  mulx %%rdx, %%rax, %%rcx;"    // f[0]^2
		                           "  movq %%rax, 64(%0);"
		"  add %%rcx, %%r8;"       "  movq %%r8, 72(%0);"
		"  movq 40(%1), %%rdx;"     "  mulx %%rdx, %%rax, %%rcx;"    // f[1]^2
		"  adcx %%rax, %%r9;"      "  movq %%r9, 80(%0);"
		"  adcx %%rcx, %%r10;"     "  movq %%r10, 88(%0);"
		"  movq 48(%1), %%rdx;"    "  mulx %%rdx, %%rax, %%rcx;"    // f[2]^2
		"  adcx %%rax, %%r11;"     "  movq %%r11, 96(%0);"
		"  adcx %%rcx, %%r12;"     "  movq %%r12, 104(%0);"
		"  movq 56(%1), %%rdx;"    "  mulx %%rdx, %%rax, %%rcx;"    // f[3]^2
		"  adcx %%rax, %%r13;"     "  movq %%r13, 112(%0);"
		"  adcx %%rcx, %%r14;"     "  movq %%r14, 120(%0);"

		// Line up pointers
		"  mov %0, %1;"
		"  mov %2, %0;"

		// Step 1: Compute dst + carry == tmp_hi * 38 + tmp_lo
		"  mov $38, %%rdx;"
		"  mulxq 32(%1), %%r8, %%r13;"
		"  xor %%rcx, %%rcx;"
		"  adoxq 0(%1), %%r8;"
		"  mulxq 40(%1), %%r9, %%r12;"
		"  adcx %%r13, %%r9;"
		"  adoxq 8(%1), %%r9;"
		"  mulxq 48(%1), %%r10, %%r13;"
		"  adcx %%r12, %%r10;"
		"  adoxq 16(%1), %%r10;"
		"  mulxq 56(%1), %%r11, %%rax;"
		"  adcx %%r13, %%r11;"
		"  adoxq 24(%1), %%r11;"
		"  adcx %%rcx, %%rax;"
		"  adox %%rcx, %%rax;"
		"  imul %%rdx, %%rax;"

		// Step 2: Fold the carry back into dst
		"  add %%rax, %%r8;"
		"  adcx %%rcx, %%r9;"
		"  movq %%r9, 8(%0);"
		"  adcx %%rcx, %%r10;"
		"  movq %%r10, 16(%0);"
		"  adcx %%rcx, %%r11;"
		"  movq %%r11, 24(%0);"

		// Step 3: Fold the carry bit back in; guaranteed not to carry at this point
		"  mov $0, %%rax;"
		"  cmovc %%rdx, %%rax;"
		"  add %%rax, %%r8;"
		"  movq %%r8, 0(%0);"

		// Step 1: Compute dst + carry == tmp_hi * 38 + tmp_lo
		"  mov $38, %%rdx;"
		"  mulxq 96(%1), %%r8, %%r13;"
		"  xor %%rcx, %%rcx;"
		"  adoxq 64(%1), %%r8;"
		"  mulxq 104(%1), %%r9, %%r12;"
		"  adcx %%r13, %%r9;"
		"  adoxq 72(%1), %%r9;"
		"  mulxq 112(%1), %%r10, %%r13;"
		"  adcx %%r12, %%r10;"
		"  adoxq 80(%1), %%r10;"
		"  mulxq 120(%1), %%r11, %%rax;"
		"  adcx %%r13, %%r11;"
		"  adoxq 88(%1), %%r11;"
		"  adcx %%rcx, %%rax;"
		"  adox %%rcx, %%rax;"
		"  imul %%rdx, %%rax;"

		// Step 2: Fold the carry back into dst
		"  add %%rax, %%r8;"
		"  adcx %%rcx, %%r9;"
		"  movq %%r9, 40(%0);"
		"  adcx %%rcx, %%r10;"
		"  movq %%r10, 48(%0);"
		"  adcx %%rcx, %%r11;"
		"  movq %%r11, 56(%0);"

		// Step 3: Fold the carry bit back in; guaranteed not to carry at this point
		"  mov $0, %%rax;"
		"  cmovc %%rdx, %%rax;"
		"  add %%rax, %%r8;"
		"  movq %%r8, 32(%0);"
	: "+&r" (tmp), "+&r" (f), "+&r" (out)
	:
	: "%rax", "%rcx", "%rdx", "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15", "memory", "cc"
	);
}

static void point_add_and_double(u64 *q, u64 *p01_tmp1, u64 *tmp2)
{
	u64 *nq = p01_tmp1;
	u64 *nq_p1 = p01_tmp1 + (u32)8U;
	u64 *tmp1 = p01_tmp1 + (u32)16U;
	u64 *x1 = q;
	u64 *x2 = nq;
	u64 *z2 = nq + (u32)4U;
	u64 *z3 = nq_p1 + (u32)4U;
	u64 *a = tmp1;
	u64 *b = tmp1 + (u32)4U;
	u64 *ab = tmp1;
	u64 *dc = tmp1 + (u32)8U;
	u64 *x3;
	u64 *z31;
	u64 *d0;
	u64 *c0;
	u64 *a1;
	u64 *b1;
	u64 *d;
	u64 *c;
	u64 *ab1;
	u64 *dc1;
	fadd(a, x2, z2);
	fsub(b, x2, z2);
	x3 = nq_p1;
	z31 = nq_p1 + (u32)4U;
	d0 = dc;
	c0 = dc + (u32)4U;
	fadd(c0, x3, z31);
	fsub(d0, x3, z31);
	fmul2(dc, dc, ab, tmp2);
	fadd(x3, d0, c0);
	fsub(z31, d0, c0);
	a1 = tmp1;
	b1 = tmp1 + (u32)4U;
	d = tmp1 + (u32)8U;
	c = tmp1 + (u32)12U;
	ab1 = tmp1;
	dc1 = tmp1 + (u32)8U;
	fsqr2(dc1, ab1, tmp2);
	fsqr2(nq_p1, nq_p1, tmp2);
	a1[0U] = c[0U];
	a1[1U] = c[1U];
	a1[2U] = c[2U];
	a1[3U] = c[3U];
	fsub(c, d, c);
	fmul_scalar(b1, c, (u64)121665U);
	fadd(b1, b1, d);
	fmul2(nq, dc1, ab1, tmp2);
	fmul(z3, z3, x1, tmp2);
}

static void point_double(u64 *nq, u64 *tmp1, u64 *tmp2)
{
	u64 *x2 = nq;
	u64 *z2 = nq + (u32)4U;
	u64 *a = tmp1;
	u64 *b = tmp1 + (u32)4U;
	u64 *d = tmp1 + (u32)8U;
	u64 *c = tmp1 + (u32)12U;
	u64 *ab = tmp1;
	u64 *dc = tmp1 + (u32)8U;
	fadd(a, x2, z2);
	fsub(b, x2, z2);
	fsqr2(dc, ab, tmp2);
	a[0U] = c[0U];
	a[1U] = c[1U];
	a[2U] = c[2U];
	a[3U] = c[3U];
	fsub(c, d, c);
	fmul_scalar(b, c, (u64)121665U);
	fadd(b, b, d);
	fmul2(nq, dc, ab, tmp2);
}

static void montgomery_ladder(u64 *out, const u8 *key, u64 *init1)
{
	u64 tmp2[16U] = { 0U };
	u64 p01_tmp1_swap[33U] = { 0U };
	u64 *p0 = p01_tmp1_swap;
	u64 *p01 = p01_tmp1_swap;
	u64 *p03 = p01;
	u64 *p11 = p01 + (u32)8U;
	u64 *x0;
	u64 *z0;
	u64 *p01_tmp1;
	u64 *p01_tmp11;
	u64 *nq10;
	u64 *nq_p11;
	u64 *swap1;
	u64 sw0;
	u64 *nq1;
	u64 *tmp1;
	memcpy(p11, init1, (u32)8U * sizeof(init1[0U]));
	x0 = p03;
	z0 = p03 + (u32)4U;
	x0[0U] = (u64)1U;
	x0[1U] = (u64)0U;
	x0[2U] = (u64)0U;
	x0[3U] = (u64)0U;
	z0[0U] = (u64)0U;
	z0[1U] = (u64)0U;
	z0[2U] = (u64)0U;
	z0[3U] = (u64)0U;
	p01_tmp1 = p01_tmp1_swap;
	p01_tmp11 = p01_tmp1_swap;
	nq10 = p01_tmp1_swap;
	nq_p11 = p01_tmp1_swap + (u32)8U;
	swap1 = p01_tmp1_swap + (u32)32U;
	cswap2((u64)1U, nq10, nq_p11);
	point_add_and_double(init1, p01_tmp11, tmp2);
	swap1[0U] = (u64)1U;
	{
		u32 i;
		for (i = (u32)0U; i < (u32)251U; i = i + (u32)1U) {
			u64 *p01_tmp12 = p01_tmp1_swap;
			u64 *swap2 = p01_tmp1_swap + (u32)32U;
			u64 *nq2 = p01_tmp12;
			u64 *nq_p12 = p01_tmp12 + (u32)8U;
			u64 bit = (u64)(key[((u32)253U - i) / (u32)8U] >> ((u32)253U - i) % (u32)8U & (u8)1U);
			u64 sw = swap2[0U] ^ bit;
			cswap2(sw, nq2, nq_p12);
			point_add_and_double(init1, p01_tmp12, tmp2);
			swap2[0U] = bit;
		}
	}
	sw0 = swap1[0U];
	cswap2(sw0, nq10, nq_p11);
	nq1 = p01_tmp1;
	tmp1 = p01_tmp1 + (u32)16U;
	point_double(nq1, tmp1, tmp2);
	point_double(nq1, tmp1, tmp2);
	point_double(nq1, tmp1, tmp2);
	memcpy(out, p0, (u32)8U * sizeof(p0[0U]));
}

static void fsquare_times(u64 *o, u64 *inp, u64 *tmp, u32 n1)
{
	u32 i;
	fsqr(o, inp, tmp);
	for (i = (u32)0U; i < n1 - (u32)1U; i = i + (u32)1U)
		fsqr(o, o, tmp);
}

static void finv(u64 *o, u64 *i, u64 *tmp)
{
	u64 t1[16U] = { 0U };
	u64 *a0 = t1;
	u64 *b = t1 + (u32)4U;
	u64 *c = t1 + (u32)8U;
	u64 *t00 = t1 + (u32)12U;
	u64 *tmp1 = tmp;
	u64 *a;
	u64 *t0;
	fsquare_times(a0, i, tmp1, (u32)1U);
	fsquare_times(t00, a0, tmp1, (u32)2U);
	fmul(b, t00, i, tmp);
	fmul(a0, b, a0, tmp);
	fsquare_times(t00, a0, tmp1, (u32)1U);
	fmul(b, t00, b, tmp);
	fsquare_times(t00, b, tmp1, (u32)5U);
	fmul(b, t00, b, tmp);
	fsquare_times(t00, b, tmp1, (u32)10U);
	fmul(c, t00, b, tmp);
	fsquare_times(t00, c, tmp1, (u32)20U);
	fmul(t00, t00, c, tmp);
	fsquare_times(t00, t00, tmp1, (u32)10U);
	fmul(b, t00, b, tmp);
	fsquare_times(t00, b, tmp1, (u32)50U);
	fmul(c, t00, b, tmp);
	fsquare_times(t00, c, tmp1, (u32)100U);
	fmul(t00, t00, c, tmp);
	fsquare_times(t00, t00, tmp1, (u32)50U);
	fmul(t00, t00, b, tmp);
	fsquare_times(t00, t00, tmp1, (u32)5U);
	a = t1;
	t0 = t1 + (u32)12U;
	fmul(o, t0, a, tmp);
}

static void store_felem(u64 *b, u64 *f)
{
	u64 f30 = f[3U];
	u64 top_bit0 = f30 >> (u32)63U;
	u64 carry0;
	u64 f31;
	u64 top_bit;
	u64 carry;
	u64 f0;
	u64 f1;
	u64 f2;
	u64 f3;
	u64 m0;
	u64 m1;
	u64 m2;
	u64 m3;
	u64 mask;
	u64 f0_;
	u64 f1_;
	u64 f2_;
	u64 f3_;
	u64 o0;
	u64 o1;
	u64 o2;
	u64 o3;
	f[3U] = f30 & (u64)0x7fffffffffffffffU;
	carry0 = add_scalar(f, f, (u64)19U * top_bit0);
	f31 = f[3U];
	top_bit = f31 >> (u32)63U;
	f[3U] = f31 & (u64)0x7fffffffffffffffU;
	carry = add_scalar(f, f, (u64)19U * top_bit);
	f0 = f[0U];
	f1 = f[1U];
	f2 = f[2U];
	f3 = f[3U];
	m0 = gte_mask(f0, (u64)0xffffffffffffffedU);
	m1 = eq_mask(f1, (u64)0xffffffffffffffffU);
	m2 = eq_mask(f2, (u64)0xffffffffffffffffU);
	m3 = eq_mask(f3, (u64)0x7fffffffffffffffU);
	mask = ((m0 & m1) & m2) & m3;
	f0_ = f0 - (mask & (u64)0xffffffffffffffedU);
	f1_ = f1 - (mask & (u64)0xffffffffffffffffU);
	f2_ = f2 - (mask & (u64)0xffffffffffffffffU);
	f3_ = f3 - (mask & (u64)0x7fffffffffffffffU);
	o0 = f0_;
	o1 = f1_;
	o2 = f2_;
	o3 = f3_;
	b[0U] = o0;
	b[1U] = o1;
	b[2U] = o2;
	b[3U] = o3;
}

static void encode_point(u8 *o, u64 *i)
{
	u64 *x = i;
	u64 *z = i + (u32)4U;
	u64 tmp[4U] = { 0U };
	u64 tmp_w[16U] = { 0U };
	finv(tmp, z, tmp_w);
	fmul(tmp, tmp, x, tmp_w);
	store_felem((u64 *)o, tmp);
}

void curve25519_ever64(u8 *out, const u8 *priv, const u8 *pub)
{
	u64 init1[8U] = { 0U };
	u64 tmp[4U] = { 0U };
	u64 tmp3;
	u64 *x;
	u64 *z;
	{
		u32 i;
		for (i = (u32)0U; i < (u32)4U; i = i + (u32)1U) {
			u64 *os = tmp;
			const u8 *bj = pub + i * (u32)8U;
			u64 u = *(u64 *)bj;
			u64 r = u;
			u64 x0 = r;
			os[i] = x0;
		}
	}
	tmp3 = tmp[3U];
	tmp[3U] = tmp3 & (u64)0x7fffffffffffffffU;
	x = init1;
	z = init1 + (u32)4U;
	z[0U] = (u64)1U;
	z[1U] = (u64)0U;
	z[2U] = (u64)0U;
	z[3U] = (u64)0U;
	x[0U] = tmp[0U];
	x[1U] = tmp[1U];
	x[2U] = tmp[2U];
	x[3U] = tmp[3U];
	montgomery_ladder(init1, priv, init1);
	encode_point(out, init1);
}
