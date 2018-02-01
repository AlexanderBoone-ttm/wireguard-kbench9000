/* MIT License
 *
 * Copyright (c) 2016-2017 INRIA and Microsoft Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/kernel.h>
#include <linux/string.h>

typedef struct 
{
  u64* r;
  u64* h;
  u64* r5;
}
Hacl_Impl_Poly1305_64_State_poly1305_state;

typedef __uint128_t u128;

#define u128_logand(a,b) ((a) & (b))
#define u128_logor(a,b) ((a) | (b))
#define u128_add(a,b) ((a) + (b))
#define u128_add_mod(a,b) ((a) + (b))
#define u128_shift_right(a,b) ((a) >> (b))
#define u128_shift_left(a,b) ((a) << (b))
#define u128_mul_wide(a,b) (((u128)(a)) * b)

#define KRML_CHECK_SIZE(a,b) {}
#define u64_to_u128(a) ((u128)a)
#define u128_to_u64(a) ((u64)a)

static __always_inline u64 FStar_UInt64_eq_mask(u64 x, u64 y) {
  x = ~(x ^ y);
  x &= x << 32;
  x &= x << 16;
  x &= x << 8;
  x &= x << 4;
  x &= x << 2;
  x &= x << 1;
  return ((s64)x) >> 63;
}

static __always_inline u64 FStar_UInt64_gte_mask(u64 x, u64 y) {
  u64 low63 =
    ~((u64)((s64)((s64)(x & (u64)(0x7fffffffffffffff)) -
		    (s64)(y & (u64)(0x7fffffffffffffff))) >>
                   63));
  u64 high_bit =
    ~((u64)((s64)((s64)(x & (u64)(0x8000000000000000)) -
		    (s64)(y & (u64)(0x8000000000000000))) >>
                   63));
  return low63 & high_bit;
}

static __always_inline u128 load128_le(u8 *b) {
  u64 l = le64_to_cpup((__force __le64 *)b);
  u64 h = le64_to_cpup((__force __le64 *)(b+8));
  return ((((u128)h) << 64) | l);
}

static __always_inline void store128_le(u8 *b, u128 n) {
  *(__force __le64 *)b = cpu_to_le64((u64)n);
  *(__force __le64 *)(b+8) = cpu_to_le64((u64)(n >> 64));
}

__always_inline static void Hacl_Bignum_Modulo_carry_top(u64 *b)
{
  u64 b2 = b[2U];
  u64 b0 = b[0U];
  u64 b2_42 = b2 >> (u32)42U;
  b[2U] = b2 & (u64)0x3ffffffffffU;
  b[0U] = (b2_42 << (u32)2U) + b2_42 + b0;
}

__always_inline static void Hacl_Bignum_Modulo_carry_top_wide(u128 *b)
{
  u128 b2 = b[2U];
  u128 b0 = b[0U];
  u128
  b2_ = u128_logand(b2, u64_to_u128((u64)0x3ffffffffffU));
  u64 b2_42 = u128_to_u64(u128_shift_right(b2, (u32)42U));
  u128
  b0_ = u128_add(b0, u64_to_u128((b2_42 << (u32)2U) + b2_42));
  b[2U] = b2_;
  b[0U] = b0_;
}

__always_inline static void
Hacl_Bignum_Fproduct_copy_from_wide_(u64 *output, u128 *input)
{
  u32 i;
  { i = 0;
    u128 xi = input[i];
    output[i] = u128_to_u64(xi);
  }
  { i = 1;
    u128 xi = input[i];
    output[i] = u128_to_u64(xi);
  }
  { i = 2;
    u128 xi = input[i];
    output[i] = u128_to_u64(xi);
  }
}

__always_inline static void
Hacl_Bignum_Fproduct_sum_scalar_multiplication_(
  u128 *output,
  u64 *input,
  u64 s
)
{
  u32 i;
  {
    i = 0;
    u128 xi = output[i];
    u64 yi = input[i];
    output[i] = u128_add_mod(xi, u128_mul_wide(yi, s));
  }
  {
    i = 1;
    u128 xi = output[i];
    u64 yi = input[i];
    output[i] = u128_add_mod(xi, u128_mul_wide(yi, s));
  }
  {
    i = 2;
    u128 xi = output[i];
    u64 yi = input[i];
    output[i] = u128_add_mod(xi, u128_mul_wide(yi, s));
  }
}

__always_inline static void Hacl_Bignum_Fproduct_carry_wide_(u128 *tmp)
{
  {
    u32 ctr = 0;
    u128 tctr = tmp[ctr];
    u128 tctrp1 = tmp[ctr + (u32)1U];
    u64 r0 = u128_to_u64(tctr) & (u64)0xfffffffffffU;
    u128 c = u128_shift_right(tctr, (u32)44U);
    tmp[ctr] = u64_to_u128(r0);
    tmp[ctr + (u32)1U] = u128_add(tctrp1, c);
  }
  {
    u32 ctr = 1;
    u128 tctr = tmp[ctr];
    u128 tctrp1 = tmp[ctr + (u32)1U];
    u64 r0 = u128_to_u64(tctr) & (u64)0xfffffffffffU;
    u128 c = u128_shift_right(tctr, (u32)44U);
    tmp[ctr] = u64_to_u128(r0);
    tmp[ctr + (u32)1U] = u128_add(tctrp1, c);
  }
}

__always_inline static void Hacl_Bignum_Fproduct_carry_limb_(u64 *tmp)
{
  {
    u32 ctr = 0;
    u64 tctr = tmp[ctr];
    u64 tctrp1 = tmp[ctr + (u32)1U];
    u64 r0 = tctr & (u64)0xfffffffffffU;
    u64 c = tctr >> (u32)44U;
    tmp[ctr] = r0;
    tmp[ctr + (u32)1U] = tctrp1 + c;
  }
  {
    u32 ctr = 1;
    u64 tctr = tmp[ctr];
    u64 tctrp1 = tmp[ctr + (u32)1U];
    u64 r0 = tctr & (u64)0xfffffffffffU;
    u64 c = tctr >> (u32)44U;
    tmp[ctr] = r0;
    tmp[ctr + (u32)1U] = tctrp1 + c;
  }
}


__always_inline static void Hacl_Bignum_Modulo_reduce(u64 *key, u64 *key5, u32 i)
{
  u64 b0 = key5[2-i];
  key[0U] = b0;
}


__always_inline static void Hacl_Bignum_Fmul_shift_reduce(u64 *key,u64 *key5, u32 i)
{
  u64 tmp = key[2U];
  {
    u32 ctr = (u32)3U - 0 - (u32)1U;
    u64 z = key[ctr - (u32)1U];
    key[ctr] = z;
  }
  {
    u32 ctr = (u32)3U - 1 - (u32)1U;
    u64 z = key[ctr - (u32)1U];
    key[ctr] = z;
  }
  key[0U] = tmp;
  Hacl_Bignum_Modulo_reduce(key,key5,i);
}

__always_inline static void
Hacl_Bignum_Fmul_mul_shift_reduce_(u128 *output, u64 *input, u64 *key, u64 *key5)
{
  u64 tmp[3U];
  memcpy(tmp, key, (u32)3U * sizeof key[0U]);
  u32 i;
  {
    i = 0;
    u64 inputi = input[i];
    Hacl_Bignum_Fproduct_sum_scalar_multiplication_(output, tmp, inputi);
    Hacl_Bignum_Fmul_shift_reduce(tmp,key5,i);
  }
  {
    i = 1;
    u64 inputi = input[i];
    Hacl_Bignum_Fproduct_sum_scalar_multiplication_(output, tmp, inputi);
    Hacl_Bignum_Fmul_shift_reduce(tmp,key5,i);
  }
  i = 2;
  u64 inputi = input[i];
  Hacl_Bignum_Fproduct_sum_scalar_multiplication_(output, tmp, inputi);
}

__always_inline static void Hacl_Bignum_Fmul_fmul(u64 *output, u64 *input, u64 *key, u64* key5)
{
  u128 t[3U] = {0};
  Hacl_Bignum_Fmul_mul_shift_reduce_(t, input, key, key5);
  Hacl_Bignum_Fproduct_carry_wide_(t);
  Hacl_Bignum_Modulo_carry_top_wide(t);
  Hacl_Bignum_Fproduct_copy_from_wide_(output, t);
  u64 i0 = output[0U];
  u64 i1 = output[1U];
  u64 i0_ = i0 & (u64)0xfffffffffffU;
  u64 i1_ = i1 + (i0 >> (u32)44U);
  output[0U] = i0_;
  output[1U] = i1_;
}

__always_inline static void
Hacl_Bignum_AddAndMultiply_add_and_multiply(u64 *acc, u64 *block, u64 *r, u64* r5)
{
  u32 i;
  { i = 0;
    u64 xi = acc[i];
    u64 yi = block[i];
    acc[i] = xi + yi;
  }
  { i = 1;
    u64 xi = acc[i];
    u64 yi = block[i];
    acc[i] = xi + yi;
  }
  { i = 2;
    u64 xi = acc[i];
    u64 yi = block[i];
    acc[i] = xi + yi;
  }
  Hacl_Bignum_Fmul_fmul(acc, acc, r, r5);
}


__always_inline static void
Hacl_Impl_Poly1305_64_poly1305_update(
  Hacl_Impl_Poly1305_64_State_poly1305_state st,
  u8 *m
)
{
  Hacl_Impl_Poly1305_64_State_poly1305_state scrut0 = st;
  u64 *h = scrut0.h;
  u64 *acc = h;
  Hacl_Impl_Poly1305_64_State_poly1305_state scrut = st;
  u64 *r = scrut.r;
  u64 *r3 = r;
  u64 *r5 = scrut.r5;
  u64 tmp[3U] = { 0U };
  u128 m0 = load128_le(m);
  u64 r0 = u128_to_u64(m0) & (u64)0xfffffffffffU;
  u64
  r1 =
    u128_to_u64(u128_shift_right(m0, (u32)44U))
    & (u64)0xfffffffffffU;
  u64 r2 = u128_to_u64(u128_shift_right(m0, (u32)88U));
  tmp[0U] = r0;
  tmp[1U] = r1;
  tmp[2U] = r2;
  u64 b2 = tmp[2U];
  u64 b2_ = (u64)0x10000000000U | b2;
  tmp[2U] = b2_;
  Hacl_Bignum_AddAndMultiply_add_and_multiply(acc, tmp, r3, r5);
}

__always_inline static void
Hacl_Impl_Poly1305_64_poly1305_process_last_block_(
  u8 *block,
  Hacl_Impl_Poly1305_64_State_poly1305_state st,
  u8 *m,
  u64 rem_
)
{
  u64 tmp[3U] = { 0U };
  u128 m0 = load128_le(block);
  u64 r0 = u128_to_u64(m0) & (u64)0xfffffffffffU;
  u64
  r1 =
    u128_to_u64(u128_shift_right(m0, (u32)44U))
    & (u64)0xfffffffffffU;
  u64 r2 = u128_to_u64(u128_shift_right(m0, (u32)88U));
  tmp[0U] = r0;
  tmp[1U] = r1;
  tmp[2U] = r2;
  Hacl_Impl_Poly1305_64_State_poly1305_state scrut0 = st;
  u64 *h = scrut0.h;
  Hacl_Impl_Poly1305_64_State_poly1305_state scrut = st;
  u64 *r = scrut.r;
  Hacl_Bignum_AddAndMultiply_add_and_multiply(h, tmp, r, scrut.r5);
}

__always_inline static void
Hacl_Impl_Poly1305_64_poly1305_process_last_block(
  Hacl_Impl_Poly1305_64_State_poly1305_state st,
  u8 *m,
  u64 rem_
)
{
  u8 block[16U] = {0};
  u32 i0 = (u32)rem_;
  u32 i = (u32)rem_;
  memcpy(block, m, i * sizeof m[0U]);
  block[i0] = (u8)1U;
  Hacl_Impl_Poly1305_64_poly1305_process_last_block_(block, st, m, rem_);
}

__always_inline static void Hacl_Impl_Poly1305_64_poly1305_last_pass(u64 *acc)
{
  Hacl_Bignum_Fproduct_carry_limb_(acc);
  Hacl_Bignum_Modulo_carry_top(acc);
  u64 a0 = acc[0U];
  u64 a10 = acc[1U];
  u64 a20 = acc[2U];
  u64 a0_ = a0 & (u64)0xfffffffffffU;
  u64 r0 = a0 >> (u32)44U;
  u64 a1_ = (a10 + r0) & (u64)0xfffffffffffU;
  u64 r1 = (a10 + r0) >> (u32)44U;
  u64 a2_ = a20 + r1;
  acc[0U] = a0_;
  acc[1U] = a1_;
  acc[2U] = a2_;
  Hacl_Bignum_Modulo_carry_top(acc);
  u64 i0 = acc[0U];
  u64 i1 = acc[1U];
  u64 i0_ = i0 & (u64)0xfffffffffffU;
  u64 i1_ = i1 + (i0 >> (u32)44U);
  acc[0U] = i0_;
  acc[1U] = i1_;
  u64 a00 = acc[0U];
  u64 a1 = acc[1U];
  u64 a2 = acc[2U];
  u64 mask0 = FStar_UInt64_gte_mask(a00, (u64)0xffffffffffbU);
  u64 mask1 = FStar_UInt64_eq_mask(a1, (u64)0xfffffffffffU);
  u64 mask2 = FStar_UInt64_eq_mask(a2, (u64)0x3ffffffffffU);
  u64 mask = (mask0 & mask1) & mask2;
  u64 a0_0 = a00 - ((u64)0xffffffffffbU & mask);
  u64 a1_0 = a1 - ((u64)0xfffffffffffU & mask);
  u64 a2_0 = a2 - ((u64)0x3ffffffffffU & mask);
  acc[0U] = a0_0;
  acc[1U] = a1_0;
  acc[2U] = a2_0;
}

__always_inline static Hacl_Impl_Poly1305_64_State_poly1305_state
Hacl_Impl_Poly1305_64_mk_state(u64 *r, u64 *h, u64* r5)
{
  Hacl_Impl_Poly1305_64_State_poly1305_state st;
  st.r = r;
  st.h = h;
  st.r5 = r5;
  return st;
}

static void
Hacl_Standalone_Poly1305_64_poly1305_blocks(
  Hacl_Impl_Poly1305_64_State_poly1305_state st,
  u8 *m,
  u64 len1
)
{
  u32 i;
  u8* msg = m;
  for (i = 0; i < len1; ++i) {
    Hacl_Impl_Poly1305_64_poly1305_update(st, msg);
    msg = msg + (u32)16U;
  }
}
  

__always_inline static void
Hacl_Standalone_Poly1305_64_poly1305_partial(
  Hacl_Impl_Poly1305_64_State_poly1305_state st,
  u8 *input,
  u64 len1,
  u8 *kr
)
{
  Hacl_Impl_Poly1305_64_State_poly1305_state scrut = st;
  u64 *r = scrut.r;
  u64 *x0 = r;
  u128 k1 = load128_le(kr);
  u128
  k_clamped =
    u128_logand(k1,
      u128_logor(u128_shift_left(u64_to_u128((u64)0x0ffffffc0ffffffcU),
          (u32)64U),
        u64_to_u128((u64)0x0ffffffc0fffffffU)));
  u64 r0 = u128_to_u64(k_clamped) & (u64)0xfffffffffffU;
  u64
  r1 =
    u128_to_u64(u128_shift_right(k_clamped, (u32)44U))
    & (u64)0xfffffffffffU;
  u64
  r2 = u128_to_u64(u128_shift_right(k_clamped, (u32)88U));
  x0[0U] = r0;
  x0[1U] = r1;
  x0[2U] = r2;
  u64 *r5 = scrut.r5;
  r5[0U] = 20 * r0;
  r5[1U] = 20 * r1;
  r5[2U] = 20 * r2;
  Hacl_Impl_Poly1305_64_State_poly1305_state scrut0 = st;
  u64 *h = scrut0.h;
  u64 *x00 = h;
  x00[0U] = (u64)0U;
  x00[1U] = (u64)0U;
  x00[2U] = (u64)0U;
  Hacl_Standalone_Poly1305_64_poly1305_blocks(st, input, len1);
}

__always_inline static void
Hacl_Standalone_Poly1305_64_poly1305_complete(
  Hacl_Impl_Poly1305_64_State_poly1305_state st,
  u8 *m,
  u64 len1,
  u8 *k1
)
{
  u8 *kr = k1;
  u64 len16 = len1 >> (u32)4U;
  u64 rem16 = len1 & (u64)0xfU;
  u8 *part_input = m;
  u8 *last_block = m + (u32)((u64)16U * len16);
  Hacl_Standalone_Poly1305_64_poly1305_partial(st, part_input, len16, kr);
  if (!(rem16 == (u64)0U))
    Hacl_Impl_Poly1305_64_poly1305_process_last_block(st, last_block, rem16);
  Hacl_Impl_Poly1305_64_State_poly1305_state scrut = st;
  u64 *h = scrut.h;
  u64 *acc = h;
  Hacl_Impl_Poly1305_64_poly1305_last_pass(acc);
}

__always_inline static void
Hacl_Standalone_Poly1305_64_crypto_onetimeauth_(
  u8 *output,
  u8 *input,
  u64 len1,
  u8 *k1
)
{
  u64 buf[9U] = { 0U };
  u64 *r = buf;
  u64 *h = buf + (u32)3U;
  u64 *r5 = buf + (u32)6U;
  
  Hacl_Impl_Poly1305_64_State_poly1305_state st = Hacl_Impl_Poly1305_64_mk_state(r, h, r5);
  u8 *key_s = k1 + (u32)16U;
  Hacl_Standalone_Poly1305_64_poly1305_complete(st, input, len1, k1);
  Hacl_Impl_Poly1305_64_State_poly1305_state scrut = st;
  u64 *h3 = scrut.h;
  u64 *acc = h3;
  u128 k_ = load128_le(key_s);
  u64 h0 = acc[0U];
  u64 h1 = acc[1U];
  u64 h2 = acc[2U];
  u128
  acc_ =
    u128_logor(u128_shift_left(u64_to_u128(h2
          << (u32)24U
          | h1 >> (u32)20U),
        (u32)64U),
      u64_to_u128(h1 << (u32)44U | h0));
  u128 mac_ = u128_add_mod(acc_, k_);
  store128_le(output, mac_);
}

__always_inline static void
Hacl_Standalone_Poly1305_64_crypto_onetimeauth(
  u8 *output,
  u8 *input,
  u64 len1,
  u8 *k1
)
{
  Hacl_Standalone_Poly1305_64_crypto_onetimeauth_(output, input, len1, k1);
}

void Hacl_Poly1305_64_init(Hacl_Impl_Poly1305_64_State_poly1305_state st, u8 *k1)
{
  Hacl_Impl_Poly1305_64_State_poly1305_state scrut = st;
  u64 *r = scrut.r;
  u64 *r5= scrut.r5;
  u64 *x0 = r;
  u128 k10 = load128_le(k1);
  u128
  k_clamped =
    u128_logand(k10,
      u128_logor(u128_shift_left(u64_to_u128((u64)0x0ffffffc0ffffffcU),
          (u32)64U),
        u64_to_u128((u64)0x0ffffffc0fffffffU)));
  u64 r0 = u128_to_u64(k_clamped) & (u64)0xfffffffffffU;
  u64
  r1 =
    u128_to_u64(u128_shift_right(k_clamped, (u32)44U))
    & (u64)0xfffffffffffU;
  u64
  r2 = u128_to_u64(u128_shift_right(k_clamped, (u32)88U));
  x0[0U] = r0;
  x0[1U] = r1;
  x0[2U] = r2;
  r5[0U] = 20 * r0;
  r5[1U] = 20 * r1;
  r5[2U] = 20 * r2; 
  Hacl_Impl_Poly1305_64_State_poly1305_state scrut0 = st;
  u64 *h = scrut0.h;
  u64 *x00 = h;
  x00[0U] = (u64)0U;
  x00[1U] = (u64)0U;
  x00[2U] = (u64)0U;
}

void Hacl_Poly1305_64_update_block(Hacl_Impl_Poly1305_64_State_poly1305_state st, u8 *m)
{
  Hacl_Impl_Poly1305_64_poly1305_update(st, m);
}

void
Hacl_Poly1305_64_update(
  Hacl_Impl_Poly1305_64_State_poly1305_state st,
  u8 *m,
  u32 num_blocks
)
{
  u32 i;
  u8* msg = m;
  for (i = 0; i < num_blocks; i++)
  {
    u8 *block = msg;
    Hacl_Poly1305_64_update_block(st, block);
    msg = msg + (u32)16U;
  }
}

void
Hacl_Poly1305_64_update_last(
  Hacl_Impl_Poly1305_64_State_poly1305_state st,
  u8 *m,
  u32 len1
)
{
  if (!((u64)len1 == (u64)0U))
    Hacl_Impl_Poly1305_64_poly1305_process_last_block(st, m, (u64)len1);
  Hacl_Impl_Poly1305_64_State_poly1305_state scrut = st;
  u64 *h = scrut.h;
  u64 *acc = h;
  Hacl_Impl_Poly1305_64_poly1305_last_pass(acc);
}

void
Hacl_Poly1305_64_finish(
  Hacl_Impl_Poly1305_64_State_poly1305_state st,
  u8 *mac,
  u8 *k1
)
{
  Hacl_Impl_Poly1305_64_State_poly1305_state scrut = st;
  u64 *h = scrut.h;
  u64 *acc = h;
  u128 k_ = load128_le(k1);
  u64 h0 = acc[0U];
  u64 h1 = acc[1U];
  u64 h2 = acc[2U];
  u128
  acc_ =
    u128_logor(u128_shift_left(u64_to_u128(h2
          << (u32)24U
          | h1 >> (u32)20U),
        (u32)64U),
      u64_to_u128(h1 << (u32)44U | h0));
  u128 mac_ = u128_add_mod(acc_, k_);
  store128_le(mac, mac_);
}

void
poly1305_hacl64(
  u8 *output,
  u8 *input,
  u64 len1,
  u8 *k1
)
{
  Hacl_Standalone_Poly1305_64_crypto_onetimeauth(output, input, len1, k1);
}

