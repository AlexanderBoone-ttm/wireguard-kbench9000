/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2016-2018 INRIA and Microsoft Corporation
 */


#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/unaligned.h>

#define load64_le(x) get_unaligned_le64(x)
#define store64_le(d, s) put_unaligned_le64(s, d)
#define KRML_CHECK_SIZE(a,b) {}

static uint32_t Lib_Utils_uint32_eq_mask(uint32_t a, uint32_t b)
{
  uint32_t x = a ^ b;
  uint32_t minus_x = ~x + (uint32_t)1U;
  uint32_t x_or_minus_x = x | minus_x;
  uint32_t xnx = x_or_minus_x >> (uint32_t)31U;
  uint32_t c = xnx - (uint32_t)1U;
  return c;
}

static uint32_t Lib_Utils_uint32_gte_mask(uint32_t a, uint32_t b)
{
  uint32_t x = a;
  uint32_t y = b;
  uint32_t x_xor_y = x ^ y;
  uint32_t x_sub_y = x - y;
  uint32_t x_sub_y_xor_y = x_sub_y ^ y;
  uint32_t q = x_xor_y | x_sub_y_xor_y;
  uint32_t x_xor_q = x ^ q;
  uint32_t x_xor_q_ = x_xor_q >> (uint32_t)31U;
  uint32_t c = x_xor_q_ - (uint32_t)1U;
  return c;
}

inline static void Hacl_Impl_Poly1305_Field32_add_felem(uint32_t *f1, uint32_t *f2)
{
  uint32_t f10 = f1[0U];
  uint32_t f11 = f1[1U];
  uint32_t f12 = f1[2U];
  uint32_t f13 = f1[3U];
  uint32_t f14 = f1[4U];
  uint32_t f20 = f2[0U];
  uint32_t f21 = f2[1U];
  uint32_t f22 = f2[2U];
  uint32_t f23 = f2[3U];
  uint32_t f24 = f2[4U];
  f1[0U] = f10 + f20;
  f1[1U] = f11 + f21;
  f1[2U] = f12 + f22;
  f1[3U] = f13 + f23;
  f1[4U] = f14 + f24;
}

inline static void
Hacl_Impl_Poly1305_Field32_smul_felem(uint64_t *out, uint32_t u1, uint32_t *f2)
{
  uint32_t f20 = f2[0U];
  uint32_t f21 = f2[1U];
  uint32_t f22 = f2[2U];
  uint32_t f23 = f2[3U];
  uint32_t f24 = f2[4U];
  out[0U] = (uint64_t)u1 * (uint64_t)f20;
  out[1U] = (uint64_t)u1 * (uint64_t)f21;
  out[2U] = (uint64_t)u1 * (uint64_t)f22;
  out[3U] = (uint64_t)u1 * (uint64_t)f23;
  out[4U] = (uint64_t)u1 * (uint64_t)f24;
}

inline static void
Hacl_Impl_Poly1305_Field32_smul_add_felem(uint64_t *out, uint32_t u1, uint32_t *f2)
{
  uint32_t f20 = f2[0U];
  uint32_t f21 = f2[1U];
  uint32_t f22 = f2[2U];
  uint32_t f23 = f2[3U];
  uint32_t f24 = f2[4U];
  uint64_t o0 = out[0U];
  uint64_t o1 = out[1U];
  uint64_t o2 = out[2U];
  uint64_t o3 = out[3U];
  uint64_t o4 = out[4U];
  out[0U] = o0 + (uint64_t)u1 * (uint64_t)f20;
  out[1U] = o1 + (uint64_t)u1 * (uint64_t)f21;
  out[2U] = o2 + (uint64_t)u1 * (uint64_t)f22;
  out[3U] = o3 + (uint64_t)u1 * (uint64_t)f23;
  out[4U] = o4 + (uint64_t)u1 * (uint64_t)f24;
}

inline static void
Hacl_Impl_Poly1305_Field32_mul_felem(
  uint64_t *out,
  uint32_t *f1,
  uint32_t *f2,
  uint32_t *f2_20
)
{
  uint32_t tmp[5U] = { 0U };
  Hacl_Impl_Poly1305_Field32_smul_felem(out, f1[0U], f2);
  tmp[0U] = f2_20[4U];
  tmp[1U] = f2[0U];
  tmp[2U] = f2[1U];
  tmp[3U] = f2[2U];
  tmp[4U] = f2[3U];
  Hacl_Impl_Poly1305_Field32_smul_add_felem(out, f1[1U], tmp);
  tmp[0U] = f2_20[3U];
  tmp[1U] = f2_20[4U];
  tmp[2U] = f2[0U];
  tmp[3U] = f2[1U];
  tmp[4U] = f2[2U];
  Hacl_Impl_Poly1305_Field32_smul_add_felem(out, f1[2U], tmp);
  tmp[0U] = f2_20[2U];
  tmp[1U] = f2_20[3U];
  tmp[2U] = f2_20[4U];
  tmp[3U] = f2[0U];
  tmp[4U] = f2[1U];
  Hacl_Impl_Poly1305_Field32_smul_add_felem(out, f1[3U], tmp);
  tmp[0U] = f2_20[1U];
  tmp[1U] = f2_20[2U];
  tmp[2U] = f2_20[3U];
  tmp[3U] = f2_20[4U];
  tmp[4U] = f2[0U];
  Hacl_Impl_Poly1305_Field32_smul_add_felem(out, f1[4U], tmp);
}

inline static void Hacl_Impl_Poly1305_Field32_carry_wide_felem(uint32_t *out, uint64_t *inp)
{
  uint64_t i0 = inp[0U];
  uint64_t i1 = inp[1U];
  uint64_t i2 = inp[2U];
  uint64_t i3 = inp[3U];
  uint64_t i4 = inp[4U];
  uint64_t l = i0 + (uint64_t)(uint32_t)0U;
  uint32_t tmp0 = (uint32_t)l & (uint32_t)0x3ffffffU;
  uint32_t carry1 = (uint32_t)(l >> (uint32_t)26U);
  uint64_t l0 = i1 + (uint64_t)carry1;
  uint32_t tmp1 = (uint32_t)l0 & (uint32_t)0x3ffffffU;
  uint32_t carry2 = (uint32_t)(l0 >> (uint32_t)26U);
  uint64_t l1 = i2 + (uint64_t)carry2;
  uint32_t tmp2 = (uint32_t)l1 & (uint32_t)0x3ffffffU;
  uint32_t carry3 = (uint32_t)(l1 >> (uint32_t)26U);
  uint64_t l2 = i3 + (uint64_t)carry3;
  uint32_t tmp3 = (uint32_t)l2 & (uint32_t)0x3ffffffU;
  uint32_t carry4 = (uint32_t)(l2 >> (uint32_t)26U);
  uint64_t l3 = i4 + (uint64_t)carry4;
  uint32_t tmp4 = (uint32_t)l3 & (uint32_t)0x3ffffffU;
  uint32_t carry5 = (uint32_t)(l3 >> (uint32_t)26U);
  uint32_t tmp01 = tmp0 + carry5 * (uint32_t)5U;
  out[0U] = tmp01;
  out[1U] = tmp1;
  out[2U] = tmp2;
  out[3U] = tmp3;
  out[4U] = tmp4;
}

inline static void Hacl_Impl_Poly1305_Field32_carry_felem(uint32_t *f)
{
  uint32_t f0 = f[0U];
  uint32_t f1 = f[1U];
  uint32_t f2 = f[2U];
  uint32_t f3 = f[3U];
  uint32_t f4 = f[4U];
  uint32_t l = f0 + (uint32_t)0U;
  uint32_t tmp0 = l & (uint32_t)0x3ffffffU;
  uint32_t carry1 = l >> (uint32_t)26U;
  uint32_t l0 = f1 + carry1;
  uint32_t tmp1 = l0 & (uint32_t)0x3ffffffU;
  uint32_t carry2 = l0 >> (uint32_t)26U;
  uint32_t l1 = f2 + carry2;
  uint32_t tmp2 = l1 & (uint32_t)0x3ffffffU;
  uint32_t carry3 = l1 >> (uint32_t)26U;
  uint32_t l2 = f3 + carry3;
  uint32_t tmp3 = l2 & (uint32_t)0x3ffffffU;
  uint32_t carry4 = l2 >> (uint32_t)26U;
  uint32_t tmp4 = f4 + carry4;
  f[0U] = tmp0;
  f[1U] = tmp1;
  f[2U] = tmp2;
  f[3U] = tmp3;
  f[4U] = tmp4;
}

inline static void Hacl_Impl_Poly1305_Field32_carry_top_felem(uint32_t *f)
{
  uint32_t f0 = f[0U];
  uint32_t f1 = f[1U];
  uint32_t f4 = f[4U];
  uint32_t l = f4 + (uint32_t)0U;
  uint32_t tmp4 = l & (uint32_t)0x3ffffffU;
  uint32_t carry1 = l >> (uint32_t)26U;
  uint32_t l0 = f0 + carry1 * (uint32_t)5U;
  uint32_t tmp0 = l0 & (uint32_t)0x3ffffffU;
  uint32_t carry2 = l0 >> (uint32_t)26U;
  uint32_t tmp1 = f1 + carry2;
  f[0U] = tmp0;
  f[1U] = tmp1;
  f[4U] = tmp4;
}

uint32_t Hacl_Poly1305_32_ctxlen = (uint32_t)20U;

uint32_t Hacl_Poly1305_32_blocklen = (uint32_t)16U;

void Hacl_Poly1305_32_poly1305_init(uint32_t *ctx, uint8_t *key)
{
  uint8_t *kr = key;
  uint8_t *ks = key + (uint32_t)16U;
  uint32_t *acc = ctx;
  uint32_t *r = ctx + (uint32_t)5U;
  uint32_t *r_20 = ctx + (uint32_t)5U * (uint32_t)2U;
  uint32_t *sk = ctx + (uint32_t)5U * (uint32_t)3U;
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
  acc[0U] = (uint32_t)0U;
  acc[1U] = (uint32_t)0U;
  acc[2U] = (uint32_t)0U;
  acc[3U] = (uint32_t)0U;
  acc[4U] = (uint32_t)0U;
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
  r[0U] = (uint32_t)lo1 & (uint32_t)0x3ffffffU;
  r[1U] = (uint32_t)(lo1 >> (uint32_t)26U) & (uint32_t)0x3ffffffU;
  r[2U] = (uint32_t)(lo1 >> (uint32_t)52U) ^ ((uint32_t)hi1 & (uint32_t)0x3fffU) << (uint32_t)12U;
  r[3U] = (uint32_t)(hi1 >> (uint32_t)14U) & (uint32_t)0x3ffffffU;
  r[4U] = (uint32_t)(hi1 >> (uint32_t)40U);
  r_20[0U] = r[0U] * (uint32_t)5U;
  r_20[1U] = r[1U] * (uint32_t)5U;
  r_20[2U] = r[2U] * (uint32_t)5U;
  r_20[3U] = r[3U] * (uint32_t)5U;
  r_20[4U] = r[4U] * (uint32_t)5U;
  u2 = load64_le(ks);
  lo = u2;
  u = load64_le(ks + (uint32_t)8U);
  hi = u;
  sl = lo;
  sh = hi;
  sk[0U] = (uint32_t)sl & (uint32_t)0x3ffffffU;
  sk[1U] = (uint32_t)(sl >> (uint32_t)26U) & (uint32_t)0x3ffffffU;
  sk[2U] = (uint32_t)(sl >> (uint32_t)52U) ^ ((uint32_t)sh & (uint32_t)0x3fffU) << (uint32_t)12U;
  sk[3U] = (uint32_t)(sh >> (uint32_t)14U) & (uint32_t)0x3ffffffU;
  sk[4U] = (uint32_t)(sh >> (uint32_t)40U);
}

void Hacl_Poly1305_32_poly1305_update(uint32_t *ctx, uint8_t *text, uint32_t len)
{
  uint32_t *acc = ctx;
  uint32_t *r = ctx + (uint32_t)5U;
  uint32_t *r_20 = ctx + (uint32_t)5U * (uint32_t)2U;
  uint32_t e[5U] = { 0U };
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
      e[0U] = (uint32_t)lo & (uint32_t)0x3ffffffU;
      e[1U] = (uint32_t)(lo >> (uint32_t)26U) & (uint32_t)0x3ffffffU;
      e[2U] = (uint32_t)(lo >> (uint32_t)52U) ^ ((uint32_t)hi & (uint32_t)0x3fffU) << (uint32_t)12U;
      e[3U] = (uint32_t)(hi >> (uint32_t)14U) & (uint32_t)0x3ffffffU;
      e[4U] = (uint32_t)(hi >> (uint32_t)40U);
      e[4U] = e[4U] | (uint32_t)0x1000000U;
      {
        uint64_t tmp[5U] = { 0U };
        Hacl_Impl_Poly1305_Field32_add_felem(acc, e);
        Hacl_Impl_Poly1305_Field32_mul_felem(tmp, acc, r, r_20);
        Hacl_Impl_Poly1305_Field32_carry_wide_felem(acc, tmp);
      }
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
      e[0U] = (uint32_t)lo & (uint32_t)0x3ffffffU;
      e[1U] = (uint32_t)(lo >> (uint32_t)26U) & (uint32_t)0x3ffffffU;
      e[2U] = (uint32_t)(lo >> (uint32_t)52U) ^ ((uint32_t)hi & (uint32_t)0x3fffU) << (uint32_t)12U;
      e[3U] = (uint32_t)(hi >> (uint32_t)14U) & (uint32_t)0x3ffffffU;
      e[4U] = (uint32_t)(hi >> (uint32_t)40U);
      if (rem1 * (uint32_t)8U < (uint32_t)26U)
      {
        e[0U] = e[0U] | (uint32_t)1U << rem1 * (uint32_t)8U;
      }
      else
      {
        if (rem1 * (uint32_t)8U < (uint32_t)52U)
        {
          e[1U] = e[1U] | (uint32_t)1U << (rem1 * (uint32_t)8U - (uint32_t)26U);
        }
        else
        {
          if (rem1 * (uint32_t)8U < (uint32_t)78U)
          {
            e[2U] = e[2U] | (uint32_t)1U << (rem1 * (uint32_t)8U - (uint32_t)52U);
          }
          else
          {
            if (rem1 * (uint32_t)8U < (uint32_t)104U)
            {
              e[3U] = e[3U] | (uint32_t)1U << (rem1 * (uint32_t)8U - (uint32_t)78U);
            }
            else
            {
              e[4U] = e[4U] | (uint32_t)1U << (rem1 * (uint32_t)8U - (uint32_t)104U);
            }
          }
        }
      }
      {
        uint64_t tmp0[5U] = { 0U };
        Hacl_Impl_Poly1305_Field32_add_felem(acc, e);
        Hacl_Impl_Poly1305_Field32_mul_felem(tmp0, acc, r, r_20);
        Hacl_Impl_Poly1305_Field32_carry_wide_felem(acc, tmp0);
      }
    }
  }
}

void Hacl_Poly1305_32_poly1305_finish(uint32_t *ctx, uint8_t *tag)
{
  uint32_t *acc = ctx;
  uint32_t *sk = ctx + (uint32_t)5U * (uint32_t)3U;
  uint32_t f00;
  uint32_t f10;
  uint32_t f2;
  uint32_t f3;
  uint32_t f4;
  uint32_t mask;
  uint32_t mask1;
  uint32_t mask2;
  uint32_t mask3;
  uint32_t mask4;
  uint32_t p0;
  uint32_t p1;
  uint32_t p2;
  uint32_t p3;
  uint32_t p4;
  uint64_t f0;
  uint64_t f1;
  uint64_t lo;
  uint64_t hi;
  Hacl_Impl_Poly1305_Field32_carry_felem(acc);
  Hacl_Impl_Poly1305_Field32_carry_top_felem(acc);
  f00 = acc[0U];
  f10 = acc[1U];
  f2 = acc[2U];
  f3 = acc[3U];
  f4 = acc[4U];
  mask = Lib_Utils_uint32_eq_mask(f4, (uint32_t)0x3ffffffU);
  mask1 = mask & Lib_Utils_uint32_eq_mask(f3, (uint32_t)0x3ffffffU);
  mask2 = mask1 & Lib_Utils_uint32_eq_mask(f2, (uint32_t)0x3ffffffU);
  mask3 = mask2 & Lib_Utils_uint32_eq_mask(f10, (uint32_t)0x3ffffffU);
  mask4 = mask3 & Lib_Utils_uint32_gte_mask(f00, (uint32_t)0x3fffffbU);
  p0 = mask4 & (uint32_t)0x3fffffbU;
  p1 = mask4 & (uint32_t)0x3ffffffU;
  p2 = mask4 & (uint32_t)0x3ffffffU;
  p3 = mask4 & (uint32_t)0x3ffffffU;
  p4 = mask4 & (uint32_t)0x3ffffffU;
  acc[0U] = f00 - p0;
  acc[1U] = f10 - p1;
  acc[2U] = f2 - p2;
  acc[3U] = f3 - p3;
  acc[4U] = f4 - p4;
  Hacl_Impl_Poly1305_Field32_add_felem(acc, sk);
  Hacl_Impl_Poly1305_Field32_carry_felem(acc);
  f0 =
    ((uint64_t)acc[0U] | (uint64_t)acc[1U] << (uint32_t)26U)
    | (uint64_t)acc[2U] << (uint32_t)52U;
  f1 =
    ((uint64_t)acc[2U] >> (uint32_t)12U | (uint64_t)acc[3U] << (uint32_t)14U)
    | (uint64_t)acc[4U] << (uint32_t)40U;
  lo = f0;
  hi = f1;
  store64_le(tag, lo);
  store64_le(tag + (uint32_t)8U, hi);
}

void poly1305_hacl32(uint8_t *o, uint8_t *t, uint32_t l, uint8_t *k)
{
  {
    uint32_t ctx[(uint32_t)5U * (uint32_t)4U];
    memset(ctx, 0U, (uint32_t)5U * (uint32_t)4U * sizeof ctx[0U]);
    {
      uint8_t *kr = k;
      uint8_t *ks = k + (uint32_t)16U;
      uint32_t *acc0 = ctx;
      uint32_t *r0 = ctx + (uint32_t)5U;
      uint32_t *r_200 = ctx + (uint32_t)5U * (uint32_t)2U;
      uint32_t *sk0 = ctx + (uint32_t)5U * (uint32_t)3U;
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
      acc0[0U] = (uint32_t)0U;
      acc0[1U] = (uint32_t)0U;
      acc0[2U] = (uint32_t)0U;
      acc0[3U] = (uint32_t)0U;
      acc0[4U] = (uint32_t)0U;
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
      r0[0U] = (uint32_t)lo1 & (uint32_t)0x3ffffffU;
      r0[1U] = (uint32_t)(lo1 >> (uint32_t)26U) & (uint32_t)0x3ffffffU;
      r0[2U] =
        (uint32_t)(lo1 >> (uint32_t)52U)
        ^ ((uint32_t)hi1 & (uint32_t)0x3fffU) << (uint32_t)12U;
      r0[3U] = (uint32_t)(hi1 >> (uint32_t)14U) & (uint32_t)0x3ffffffU;
      r0[4U] = (uint32_t)(hi1 >> (uint32_t)40U);
      r_200[0U] = r0[0U] * (uint32_t)5U;
      r_200[1U] = r0[1U] * (uint32_t)5U;
      r_200[2U] = r0[2U] * (uint32_t)5U;
      r_200[3U] = r0[3U] * (uint32_t)5U;
      r_200[4U] = r0[4U] * (uint32_t)5U;
      u2 = load64_le(ks);
      lo3 = u2;
      u3 = load64_le(ks + (uint32_t)8U);
      hi3 = u3;
      sl = lo3;
      sh = hi3;
      sk0[0U] = (uint32_t)sl & (uint32_t)0x3ffffffU;
      sk0[1U] = (uint32_t)(sl >> (uint32_t)26U) & (uint32_t)0x3ffffffU;
      sk0[2U] =
        (uint32_t)(sl >> (uint32_t)52U)
        ^ ((uint32_t)sh & (uint32_t)0x3fffU) << (uint32_t)12U;
      sk0[3U] = (uint32_t)(sh >> (uint32_t)14U) & (uint32_t)0x3ffffffU;
      sk0[4U] = (uint32_t)(sh >> (uint32_t)40U);
      {
        uint32_t *acc1 = ctx;
        uint32_t *r = ctx + (uint32_t)5U;
        uint32_t *r_20 = ctx + (uint32_t)5U * (uint32_t)2U;
        uint32_t e[5U] = { 0U };
        uint32_t blocks = l / (uint32_t)16U;
        uint32_t rem1;
        uint32_t *acc;
        uint32_t *sk;
        uint32_t f00;
        uint32_t f10;
        uint32_t f2;
        uint32_t f3;
        uint32_t f4;
        uint32_t mask;
        uint32_t mask1;
        uint32_t mask2;
        uint32_t mask3;
        uint32_t mask4;
        uint32_t p0;
        uint32_t p1;
        uint32_t p2;
        uint32_t p3;
        uint32_t p4;
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
            e[0U] = (uint32_t)lo & (uint32_t)0x3ffffffU;
            e[1U] = (uint32_t)(lo >> (uint32_t)26U) & (uint32_t)0x3ffffffU;
            e[2U] =
              (uint32_t)(lo >> (uint32_t)52U)
              ^ ((uint32_t)hi & (uint32_t)0x3fffU) << (uint32_t)12U;
            e[3U] = (uint32_t)(hi >> (uint32_t)14U) & (uint32_t)0x3ffffffU;
            e[4U] = (uint32_t)(hi >> (uint32_t)40U);
            e[4U] = e[4U] | (uint32_t)0x1000000U;
            {
              uint64_t tmp[5U] = { 0U };
              Hacl_Impl_Poly1305_Field32_add_felem(acc1, e);
              Hacl_Impl_Poly1305_Field32_mul_felem(tmp, acc1, r, r_20);
              Hacl_Impl_Poly1305_Field32_carry_wide_felem(acc1, tmp);
            }
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
            e[0U] = (uint32_t)lo & (uint32_t)0x3ffffffU;
            e[1U] = (uint32_t)(lo >> (uint32_t)26U) & (uint32_t)0x3ffffffU;
            e[2U] =
              (uint32_t)(lo >> (uint32_t)52U)
              ^ ((uint32_t)hi & (uint32_t)0x3fffU) << (uint32_t)12U;
            e[3U] = (uint32_t)(hi >> (uint32_t)14U) & (uint32_t)0x3ffffffU;
            e[4U] = (uint32_t)(hi >> (uint32_t)40U);
            if (rem1 * (uint32_t)8U < (uint32_t)26U)
            {
              e[0U] = e[0U] | (uint32_t)1U << rem1 * (uint32_t)8U;
            }
            else
            {
              if (rem1 * (uint32_t)8U < (uint32_t)52U)
              {
                e[1U] = e[1U] | (uint32_t)1U << (rem1 * (uint32_t)8U - (uint32_t)26U);
              }
              else
              {
                if (rem1 * (uint32_t)8U < (uint32_t)78U)
                {
                  e[2U] = e[2U] | (uint32_t)1U << (rem1 * (uint32_t)8U - (uint32_t)52U);
                }
                else
                {
                  if (rem1 * (uint32_t)8U < (uint32_t)104U)
                  {
                    e[3U] = e[3U] | (uint32_t)1U << (rem1 * (uint32_t)8U - (uint32_t)78U);
                  }
                  else
                  {
                    e[4U] = e[4U] | (uint32_t)1U << (rem1 * (uint32_t)8U - (uint32_t)104U);
                  }
                }
              }
            }
            {
              uint64_t tmp0[5U] = { 0U };
              Hacl_Impl_Poly1305_Field32_add_felem(acc1, e);
              Hacl_Impl_Poly1305_Field32_mul_felem(tmp0, acc1, r, r_20);
              Hacl_Impl_Poly1305_Field32_carry_wide_felem(acc1, tmp0);
            }
          }
        }
        acc = ctx;
        sk = ctx + (uint32_t)5U * (uint32_t)3U;
        Hacl_Impl_Poly1305_Field32_carry_felem(acc);
        Hacl_Impl_Poly1305_Field32_carry_top_felem(acc);
        f00 = acc[0U];
        f10 = acc[1U];
        f2 = acc[2U];
        f3 = acc[3U];
        f4 = acc[4U];
        mask = Lib_Utils_uint32_eq_mask(f4, (uint32_t)0x3ffffffU);
        mask1 = mask & Lib_Utils_uint32_eq_mask(f3, (uint32_t)0x3ffffffU);
        mask2 = mask1 & Lib_Utils_uint32_eq_mask(f2, (uint32_t)0x3ffffffU);
        mask3 = mask2 & Lib_Utils_uint32_eq_mask(f10, (uint32_t)0x3ffffffU);
        mask4 = mask3 & Lib_Utils_uint32_gte_mask(f00, (uint32_t)0x3fffffbU);
        p0 = mask4 & (uint32_t)0x3fffffbU;
        p1 = mask4 & (uint32_t)0x3ffffffU;
        p2 = mask4 & (uint32_t)0x3ffffffU;
        p3 = mask4 & (uint32_t)0x3ffffffU;
        p4 = mask4 & (uint32_t)0x3ffffffU;
        acc[0U] = f00 - p0;
        acc[1U] = f10 - p1;
        acc[2U] = f2 - p2;
        acc[3U] = f3 - p3;
        acc[4U] = f4 - p4;
        Hacl_Impl_Poly1305_Field32_add_felem(acc, sk);
        Hacl_Impl_Poly1305_Field32_carry_felem(acc);
        f0 =
          ((uint64_t)acc[0U] | (uint64_t)acc[1U] << (uint32_t)26U)
          | (uint64_t)acc[2U] << (uint32_t)52U;
        f1 =
          ((uint64_t)acc[2U] >> (uint32_t)12U | (uint64_t)acc[3U] << (uint32_t)14U)
          | (uint64_t)acc[4U] << (uint32_t)40U;
        lo4 = f0;
        hi4 = f1;
        store64_le(o, lo4);
        store64_le(o + (uint32_t)8U, hi4);
      }
    }
  }
}
