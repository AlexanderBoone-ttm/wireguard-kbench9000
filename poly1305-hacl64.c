/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2016-2018 INRIA and Microsoft Corporation
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/unaligned.h>

typedef __uint128_t uint128_t;
#define store64_le(d, s) put_unaligned_le64(s, d)
#define load64_le(x) get_unaligned_le64(x)

static uint64_t Lib_Utils_uint64_eq_mask(uint64_t a, uint64_t b)
{
  uint64_t x = a ^ b;
  uint64_t minus_x = ~x + (uint64_t)1U;
  uint64_t x_or_minus_x = x | minus_x;
  uint64_t xnx = x_or_minus_x >> (uint32_t)63U;
  uint64_t c = xnx - (uint64_t)1U;
  return c;
}

static uint64_t Lib_Utils_uint64_gte_mask(uint64_t a, uint64_t b)
{
  uint64_t x = a;
  uint64_t y = b;
  uint64_t x_xor_y = x ^ y;
  uint64_t x_sub_y = x - y;
  uint64_t x_sub_y_xor_y = x_sub_y ^ y;
  uint64_t q = x_xor_y | x_sub_y_xor_y;
  uint64_t x_xor_q = x ^ q;
  uint64_t x_xor_q_ = x_xor_q >> (uint32_t)63U;
  uint64_t c = x_xor_q_ - (uint64_t)1U;
  return c;
}

inline static void Hacl_Impl_Poly1305_Field64_add_felem(uint64_t *f1, uint64_t *f2)
{
  uint64_t f10 = f1[0U];
  uint64_t f11 = f1[1U];
  uint64_t f12 = f1[2U];
  uint64_t f20 = f2[0U];
  uint64_t f21 = f2[1U];
  uint64_t f22 = f2[2U];
  f1[0U] = f10 + f20;
  f1[1U] = f11 + f21;
  f1[2U] = f12 + f22;
}

inline static void
Hacl_Impl_Poly1305_Field64_smul_felem(uint128_t *out, uint64_t u1, uint64_t *f2)
{
  uint64_t f20 = f2[0U];
  uint64_t f21 = f2[1U];
  uint64_t f22 = f2[2U];
  out[0U] = (uint128_t)u1 * f20;
  out[1U] = (uint128_t)u1 * f21;
  out[2U] = (uint128_t)u1 * f22;
}

inline static void
Hacl_Impl_Poly1305_Field64_smul_add_felem(uint128_t *out, uint64_t u1, uint64_t *f2)
{
  uint64_t f20 = f2[0U];
  uint64_t f21 = f2[1U];
  uint64_t f22 = f2[2U];
  uint128_t o0 = out[0U];
  uint128_t o1 = out[1U];
  uint128_t o2 = out[2U];
  out[0U] = o0 + (uint128_t)u1 * f20;
  out[1U] = o1 + (uint128_t)u1 * f21;
  out[2U] = o2 + (uint128_t)u1 * f22;
}

inline static void
Hacl_Impl_Poly1305_Field64_mul_felem(
  uint128_t *out,
  uint64_t *f1,
  uint64_t *f2,
  uint64_t *f2_20
)
{
  uint64_t tmp[3U] = { 0U };
  Hacl_Impl_Poly1305_Field64_smul_felem(out, f1[0U], f2);
  tmp[0U] = f2_20[2U];
  tmp[1U] = f2[0U];
  tmp[2U] = f2[1U];
  Hacl_Impl_Poly1305_Field64_smul_add_felem(out, f1[1U], tmp);
  tmp[0U] = f2_20[1U];
  tmp[1U] = f2_20[2U];
  tmp[2U] = f2[0U];
  Hacl_Impl_Poly1305_Field64_smul_add_felem(out, f1[2U], tmp);
}

inline static void Hacl_Impl_Poly1305_Field64_carry_wide_felem(uint64_t *out, uint128_t *inp)
{
  uint128_t i0 = inp[0U];
  uint128_t i1 = inp[1U];
  uint128_t i2 = inp[2U];
  uint128_t l = i0 + (uint128_t)(uint64_t)0U;
  uint64_t tmp0 = (uint64_t)l & (uint64_t)0xfffffffffffU;
  uint64_t carry1 = (uint64_t)(l >> (uint32_t)44U);
  uint128_t l0 = i1 + (uint128_t)carry1;
  uint64_t tmp1 = (uint64_t)l0 & (uint64_t)0xfffffffffffU;
  uint64_t carry2 = (uint64_t)(l0 >> (uint32_t)44U);
  uint128_t l1 = i2 + (uint128_t)carry2;
  uint64_t tmp2 = (uint64_t)l1 & (uint64_t)0x3ffffffffffU;
  uint64_t carry3 = (uint64_t)(l1 >> (uint32_t)42U);
  out[0U] = tmp0 + carry3 * (uint64_t)5U;
  out[1U] = tmp1;
  out[2U] = tmp2;
}

inline static void Hacl_Impl_Poly1305_Field64_carry_felem(uint64_t *f)
{
  uint64_t f0 = f[0U];
  uint64_t f1 = f[1U];
  uint64_t f2 = f[2U];
  uint64_t l = f0 + (uint64_t)0U;
  uint64_t tmp0 = l & (uint64_t)0xfffffffffffU;
  uint64_t carry1 = l >> (uint32_t)44U;
  uint64_t l0 = f1 + carry1;
  uint64_t tmp1 = l0 & (uint64_t)0xfffffffffffU;
  uint64_t carry2 = l0 >> (uint32_t)44U;
  uint64_t tmp2 = f2 + carry2;
  f[0U] = tmp0;
  f[1U] = tmp1;
  f[2U] = tmp2;
}

inline static void Hacl_Impl_Poly1305_Field64_carry_top_felem(uint64_t *f)
{
  uint64_t f0 = f[0U];
  uint64_t f1 = f[1U];
  uint64_t f2 = f[2U];
  uint64_t l = f2 + (uint64_t)0U;
  uint64_t tmp2 = l & (uint64_t)0x3ffffffffffU;
  uint64_t carry1 = l >> (uint32_t)42U;
  uint64_t l0 = f0 + carry1 * (uint64_t)5U;
  uint64_t tmp0 = l0 & (uint64_t)0xfffffffffffU;
  uint64_t carry2 = l0 >> (uint32_t)44U;
  uint64_t tmp1 = f1 + carry2;
  f[0U] = tmp0;
  f[1U] = tmp1;
  f[2U] = tmp2;
}

inline static void
Hacl_Impl_Poly1305_Field64_fadd_mul_felem(
  uint64_t *acc,
  uint64_t *f1,
  uint64_t *f2,
  uint64_t *f2_20
)
{
  {
    uint128_t tmp[3U];
    {
      uint32_t _i;
      for (_i = 0U; _i < (uint32_t)3U; ++_i)
        tmp[_i] = (uint128_t)(uint64_t)0U;
    }
    Hacl_Impl_Poly1305_Field64_add_felem(acc, f1);
    Hacl_Impl_Poly1305_Field64_mul_felem(tmp, acc, f2, f2_20);
    Hacl_Impl_Poly1305_Field64_carry_wide_felem(acc, tmp);
  }
}

uint32_t Hacl_Poly1305_64_ctxlen = (uint32_t)12U;

uint32_t Hacl_Poly1305_64_blocklen = (uint32_t)16U;

void Hacl_Poly1305_64_poly1305_init(uint64_t *ctx, uint8_t *key)
{
  uint8_t *kr = key;
  uint8_t *ks = key + (uint32_t)16U;
  uint64_t *acc = ctx;
  uint64_t *r = ctx + (uint32_t)3U;
  uint64_t *r_20 = ctx + (uint32_t)3U * (uint32_t)2U;
  uint64_t *sk = ctx + (uint32_t)3U * (uint32_t)3U;
  uint64_t u0;
  uint64_t lo0;
  uint64_t u1;
  uint64_t hi0;
  uint64_t lo2;
  uint64_t hi2;
  uint64_t mask0;
  uint64_t mask1;
  uint64_t lo1;
  uint64_t hi1;
  uint64_t u2;
  uint64_t lo;
  uint64_t u;
  uint64_t hi;
  uint64_t sl;
  uint64_t sh;
  acc[0U] = (uint64_t)0U;
  acc[1U] = (uint64_t)0U;
  acc[2U] = (uint64_t)0U;
  u0 = load64_le(kr);
  lo0 = u0;
  u1 = load64_le(kr + (uint32_t)8U);
  hi0 = u1;
  lo2 = lo0;
  hi2 = hi0;
  mask0 = (uint64_t)0x0ffffffc0fffffffU;
  mask1 = (uint64_t)0x0ffffffc0ffffffcU;
  lo1 = lo2 & mask0;
  hi1 = hi2 & mask1;
  r[0U] = lo1 & (uint64_t)0xfffffffffffU;
  r[1U] = lo1 >> (uint32_t)44U ^ (hi1 & (uint64_t)0xffffffU) << (uint32_t)20U;
  r[2U] = hi1 >> (uint32_t)24U;
  r_20[0U] = r[0U] * (uint64_t)20U;
  r_20[1U] = r[1U] * (uint64_t)20U;
  r_20[2U] = r[2U] * (uint64_t)20U;
  u2 = load64_le(ks);
  lo = u2;
  u = load64_le(ks + (uint32_t)8U);
  hi = u;
  sl = lo;
  sh = hi;
  sk[0U] = sl & (uint64_t)0xfffffffffffU;
  sk[1U] = sl >> (uint32_t)44U ^ (sh & (uint64_t)0xffffffU) << (uint32_t)20U;
  sk[2U] = sh >> (uint32_t)24U;
}

void Hacl_Poly1305_64_poly1305_update(uint64_t *ctx, uint8_t *text, uint32_t len)
{
  uint64_t *acc = ctx;
  uint64_t *r = ctx + (uint32_t)3U;
  uint64_t *r_20 = ctx + (uint32_t)3U * (uint32_t)2U;
  uint64_t e[3U] = { 0U };
  uint32_t blocks = len / (uint32_t)16U;
  uint32_t rem1;
  {
    uint32_t i;
    for (i = (uint32_t)0U; i < blocks; i = i + (uint32_t)1U)
    {
      uint8_t *b = text + i * (uint32_t)16U;
      uint64_t u0 = load64_le(b);
      uint64_t lo0 = u0;
      uint64_t u = load64_le(b + (uint32_t)8U);
      uint64_t hi0 = u;
      uint64_t lo = lo0;
      uint64_t hi = hi0;
      e[0U] = lo & (uint64_t)0xfffffffffffU;
      e[1U] = lo >> (uint32_t)44U ^ (hi & (uint64_t)0xffffffU) << (uint32_t)20U;
      e[2U] = hi >> (uint32_t)24U;
      e[2U] = e[2U] | (uint64_t)0x10000000000U;
      Hacl_Impl_Poly1305_Field64_fadd_mul_felem(acc, e, r, r_20);
    }
  }
  rem1 = len % (uint32_t)16U;
  if (rem1 > (uint32_t)0U)
  {
    uint8_t *b = text + blocks * (uint32_t)16U;
    uint8_t tmp[16U] = { 0U };
    memcpy(tmp, b, rem1 * sizeof b[0U]);
    {
      uint64_t u0 = load64_le(tmp);
      uint64_t lo0 = u0;
      uint64_t u = load64_le(tmp + (uint32_t)8U);
      uint64_t hi0 = u;
      uint64_t lo = lo0;
      uint64_t hi = hi0;
      e[0U] = lo & (uint64_t)0xfffffffffffU;
      e[1U] = lo >> (uint32_t)44U ^ (hi & (uint64_t)0xffffffU) << (uint32_t)20U;
      e[2U] = hi >> (uint32_t)24U;
      if (rem1 * (uint32_t)8U < (uint32_t)44U)
      {
        e[0U] = e[0U] | (uint64_t)1U << rem1 * (uint32_t)8U;
      }
      else
      {
        if (rem1 * (uint32_t)8U < (uint32_t)88U)
        {
          e[1U] = e[1U] | (uint64_t)1U << (rem1 * (uint32_t)8U - (uint32_t)44U);
        }
        else
        {
          e[2U] = e[2U] | (uint64_t)1U << (rem1 * (uint32_t)8U - (uint32_t)88U);
        }
      }
      Hacl_Impl_Poly1305_Field64_fadd_mul_felem(acc, e, r, r_20);
    }
  }
}

void Hacl_Poly1305_64_poly1305_finish(uint64_t *ctx, uint8_t *tag)
{
  uint64_t *acc = ctx;
  uint64_t *sk = ctx + (uint32_t)3U * (uint32_t)3U;
  uint64_t f00;
  uint64_t f10;
  uint64_t f2;
  uint64_t mask;
  uint64_t mask1;
  uint64_t mask2;
  uint64_t p0;
  uint64_t p1;
  uint64_t p2;
  uint64_t f0;
  uint64_t f1;
  uint64_t lo;
  uint64_t hi;
  Hacl_Impl_Poly1305_Field64_carry_felem(acc);
  Hacl_Impl_Poly1305_Field64_carry_top_felem(acc);
  f00 = acc[0U];
  f10 = acc[1U];
  f2 = acc[2U];
  mask = Lib_Utils_uint64_eq_mask(f2, (uint64_t)0x3ffffffffffU);
  mask1 = mask & Lib_Utils_uint64_eq_mask(f10, (uint64_t)0xfffffffffffU);
  mask2 = mask1 & Lib_Utils_uint64_gte_mask(f00, (uint64_t)0xffffffffffbU);
  p0 = mask2 & (uint64_t)0xffffffffffbU;
  p1 = mask2 & (uint64_t)0xfffffffffffU;
  p2 = mask2 & (uint64_t)0x3ffffffffffU;
  acc[0U] = f00 - p0;
  acc[1U] = f10 - p1;
  acc[2U] = f2 - p2;
  Hacl_Impl_Poly1305_Field64_add_felem(acc, sk);
  Hacl_Impl_Poly1305_Field64_carry_felem(acc);
  f0 = acc[0U] | acc[1U] << (uint32_t)44U;
  f1 = acc[1U] >> (uint32_t)20U | acc[2U] << (uint32_t)24U;
  lo = f0;
  hi = f1;
  store64_le(tag, lo);
  store64_le(tag + (uint32_t)8U, hi);
}

void poly1305_hacl64(uint8_t *o, uint8_t *t, uint32_t l, uint8_t *k)
{
  {
    uint64_t ctx[(uint32_t)3U * (uint32_t)4U];
    memset(ctx, 0U, (uint32_t)3U * (uint32_t)4U * sizeof ctx[0U]);
    {
      uint8_t *kr = k;
      uint8_t *ks = k + (uint32_t)16U;
      uint64_t *acc0 = ctx;
      uint64_t *r0 = ctx + (uint32_t)3U;
      uint64_t *r_200 = ctx + (uint32_t)3U * (uint32_t)2U;
      uint64_t *sk0 = ctx + (uint32_t)3U * (uint32_t)3U;
      uint64_t u0;
      uint64_t lo0;
      uint64_t u1;
      uint64_t hi0;
      uint64_t lo2;
      uint64_t hi2;
      uint64_t mask0;
      uint64_t mask10;
      uint64_t lo1;
      uint64_t hi1;
      uint64_t u2;
      uint64_t lo3;
      uint64_t u3;
      uint64_t hi3;
      uint64_t sl;
      uint64_t sh;
      acc0[0U] = (uint64_t)0U;
      acc0[1U] = (uint64_t)0U;
      acc0[2U] = (uint64_t)0U;
      u0 = load64_le(kr);
      lo0 = u0;
      u1 = load64_le(kr + (uint32_t)8U);
      hi0 = u1;
      lo2 = lo0;
      hi2 = hi0;
      mask0 = (uint64_t)0x0ffffffc0fffffffU;
      mask10 = (uint64_t)0x0ffffffc0ffffffcU;
      lo1 = lo2 & mask0;
      hi1 = hi2 & mask10;
      r0[0U] = lo1 & (uint64_t)0xfffffffffffU;
      r0[1U] = lo1 >> (uint32_t)44U ^ (hi1 & (uint64_t)0xffffffU) << (uint32_t)20U;
      r0[2U] = hi1 >> (uint32_t)24U;
      r_200[0U] = r0[0U] * (uint64_t)20U;
      r_200[1U] = r0[1U] * (uint64_t)20U;
      r_200[2U] = r0[2U] * (uint64_t)20U;
      u2 = load64_le(ks);
      lo3 = u2;
      u3 = load64_le(ks + (uint32_t)8U);
      hi3 = u3;
      sl = lo3;
      sh = hi3;
      sk0[0U] = sl & (uint64_t)0xfffffffffffU;
      sk0[1U] = sl >> (uint32_t)44U ^ (sh & (uint64_t)0xffffffU) << (uint32_t)20U;
      sk0[2U] = sh >> (uint32_t)24U;
      {
        uint64_t *acc1 = ctx;
        uint64_t *r = ctx + (uint32_t)3U;
        uint64_t *r_20 = ctx + (uint32_t)3U * (uint32_t)2U;
        uint64_t e[3U] = { 0U };
        uint32_t blocks = l / (uint32_t)16U;
        uint32_t rem1;
        uint64_t *acc;
        uint64_t *sk;
        uint64_t f00;
        uint64_t f10;
        uint64_t f2;
        uint64_t mask;
        uint64_t mask1;
        uint64_t mask2;
        uint64_t p0;
        uint64_t p1;
        uint64_t p2;
        uint64_t f0;
        uint64_t f1;
        uint64_t lo4;
        uint64_t hi4;
        {
          uint32_t i;
          for (i = (uint32_t)0U; i < blocks; i = i + (uint32_t)1U)
          {
            uint8_t *b = t + i * (uint32_t)16U;
            uint64_t u0 = load64_le(b);
            uint64_t lo0 = u0;
            uint64_t u = load64_le(b + (uint32_t)8U);
            uint64_t hi0 = u;
            uint64_t lo = lo0;
            uint64_t hi = hi0;
            e[0U] = lo & (uint64_t)0xfffffffffffU;
            e[1U] = lo >> (uint32_t)44U ^ (hi & (uint64_t)0xffffffU) << (uint32_t)20U;
            e[2U] = hi >> (uint32_t)24U;
            e[2U] = e[2U] | (uint64_t)0x10000000000U;
            Hacl_Impl_Poly1305_Field64_fadd_mul_felem(acc1, e, r, r_20);
          }
        }
        rem1 = l % (uint32_t)16U;
        if (rem1 > (uint32_t)0U)
        {
          uint8_t *b = t + blocks * (uint32_t)16U;
          uint8_t tmp[16U] = { 0U };
          memcpy(tmp, b, rem1 * sizeof b[0U]);
          {
            uint64_t u0 = load64_le(tmp);
            uint64_t lo0 = u0;
            uint64_t u = load64_le(tmp + (uint32_t)8U);
            uint64_t hi0 = u;
            uint64_t lo = lo0;
            uint64_t hi = hi0;
            e[0U] = lo & (uint64_t)0xfffffffffffU;
            e[1U] = lo >> (uint32_t)44U ^ (hi & (uint64_t)0xffffffU) << (uint32_t)20U;
            e[2U] = hi >> (uint32_t)24U;
            if (rem1 * (uint32_t)8U < (uint32_t)44U)
            {
              e[0U] = e[0U] | (uint64_t)1U << rem1 * (uint32_t)8U;
            }
            else
            {
              if (rem1 * (uint32_t)8U < (uint32_t)88U)
              {
                e[1U] = e[1U] | (uint64_t)1U << (rem1 * (uint32_t)8U - (uint32_t)44U);
              }
              else
              {
                e[2U] = e[2U] | (uint64_t)1U << (rem1 * (uint32_t)8U - (uint32_t)88U);
              }
            }
            Hacl_Impl_Poly1305_Field64_fadd_mul_felem(acc1, e, r, r_20);
          }
        }
        acc = ctx;
        sk = ctx + (uint32_t)3U * (uint32_t)3U;
        Hacl_Impl_Poly1305_Field64_carry_felem(acc);
        Hacl_Impl_Poly1305_Field64_carry_top_felem(acc);
        f00 = acc[0U];
        f10 = acc[1U];
        f2 = acc[2U];
        mask = Lib_Utils_uint64_eq_mask(f2, (uint64_t)0x3ffffffffffU);
        mask1 = mask & Lib_Utils_uint64_eq_mask(f10, (uint64_t)0xfffffffffffU);
        mask2 = mask1 & Lib_Utils_uint64_gte_mask(f00, (uint64_t)0xffffffffffbU);
        p0 = mask2 & (uint64_t)0xffffffffffbU;
        p1 = mask2 & (uint64_t)0xfffffffffffU;
        p2 = mask2 & (uint64_t)0x3ffffffffffU;
        acc[0U] = f00 - p0;
        acc[1U] = f10 - p1;
        acc[2U] = f2 - p2;
        Hacl_Impl_Poly1305_Field64_add_felem(acc, sk);
        Hacl_Impl_Poly1305_Field64_carry_felem(acc);
        f0 = acc[0U] | acc[1U] << (uint32_t)44U;
        f1 = acc[1U] >> (uint32_t)20U | acc[2U] << (uint32_t)24U;
        lo4 = f0;
        hi4 = f1;
        store64_le(o, lo4);
        store64_le(o + (uint32_t)8U, hi4);
      }
    }
  }
}
