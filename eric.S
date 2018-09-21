/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ChaCha scalar implementation for 32-bit ARM
 *
 * Author: Eric Biggers <ebiggers@google.com>
 */

/*
 * Design notes:
 *
 * 16 registers would be needed to hold the state matrix, but only 14 are
 * available because 'sp' and 'pc' cannot be used.  So we spill the elements
 * (x8, x9) to the stack and swap them out with (x10, x11).  This adds one
 * 'ldrd' and one 'strd' per round.
 *
 * All rotates are performed using the implicit rotate operand accepted by the
 * 'add' and 'eor' instructions.  This is faster than using explicit rotate
 * instructions.  To make this work, we allow the values in the second and last
 * rows of the ChaCha state matrix (rows 'b' and 'd') to temporarily have the
 * wrong rotation amount.  The rotation amount is then fixed up just in time
 * when the values are used.  'brot' is the number of bits the values in row 'b'
 * need to be rotated right to arrive at the correct values, and 'drot'
 * similarly for row 'd'.  (brot, drot) start out as (0, 0) but we make it such
 * that they end up as (25, 24) after every round.
 */

#include <linux/linkage.h>

       // ChaCha state registers
       X0      .req    r0
       X1      .req    r1
       X2      .req    r2
       X3      .req    r3
       X4      .req    r4
       X5      .req    r5
       X6      .req    r6
       X7      .req    r7
       X8_X10  .req    r8      // shared by x8 and x10
       X9_X11  .req    r9      // shared by x9 and x11
       X12     .req    r10
       X13     .req    r11
       X14     .req    r12
       X15     .req    r14

.macro _halfround      a1, b1, c1, d1,  a2, b2, c2, d2,  loadmode

       // a += b; d ^= a; d = rol(d, 16)
       add             \a1, \a1, \b1, ROR #brot
       add             \a2, \a2, \b2, ROR #brot
.if \loadmode == 1
       ldrd            X8_X10, X9_X11, [sp, #8]
.elseif \loadmode == 2
       ldrd            X8_X10, X9_X11, [sp]
.endif
       eor             \d1, \a1, \d1, ROR #drot
       eor             \d2, \a2, \d2, ROR #drot
       // drot == 32 - 16 == 16

       // c += d; b ^= c; b = rol(b, 12)
       add             \c1, \c1, \d1, ROR #16
       add             \c2, \c2, \d2, ROR #16
       eor             \b1, \c1, \b1, ROR #brot
       eor             \b2, \c2, \b2, ROR #brot
       // brot == 32 - 12 == 20

       // a += b; d ^= a; d = rol(d, 8)
       add             \a1, \a1, \b1, ROR #20
       add             \a2, \a2, \b2, ROR #20
       eor             \d1, \a1, \d1, ROR #16
       eor             \d2, \a2, \d2, ROR #16
       // drot == 32 - 8 == 24

       // c += d; b ^= c; b = rol(b, 7)
       add             \c1, \c1, \d1, ROR #24
       add             \c2, \c2, \d2, ROR #24
       eor             \b1, \c1, \b1, ROR #20
       eor             \b2, \c2, \b2, ROR #20
       // brot == 32 - 7 == 25
.endm

.macro _doubleround

       // column round

       // quarterrounds: (x0, x4, x8, x12) and (x1, x5, x9, x13)
       _halfround      X0, X4, X8_X10, X12,  X1, X5, X9_X11, X13,  0

       // save (x8, x9); restore (x10, x11)
       strd            X8_X10, X9_X11, [sp]

       // quarterrounds: (x2, x6, x10, x14) and (x3, x7, x11, x15)
       _halfround      X2, X6, X8_X10, X14,  X3, X7, X9_X11, X15,  1

       .set brot, 25
       .set drot, 24

       // diagonal round

       // quarterrounds: (x0, x5, x10, x15) and (x1, x6, x11, x12)
       _halfround      X0, X5, X8_X10, X15,  X1, X6, X9_X11, X12,  0

       // save (x10, x11); restore (x8, x9)
       strd            X8_X10, X9_X11, [sp, #8]

       // quarterrounds: (x2, x7, x8, x13) and (x3, x4, x9, x14)
       _halfround      X2, X7, X8_X10, X13,  X3, X4, X9_X11, X14,  2
.endm

.macro _chacha_permute nrounds
       .set brot, 0
       .set drot, 0
       .rept \nrounds / 2
        _doubleround
       .endr
.endm

.macro _le32_bswap     a, b, c, d
#ifdef __ARMEB__
       rev             \a, \a
       rev             \b, \b
       rev             \c, \c
       rev             \d, \d
#endif
.endm

.macro _chacha nrounds

       // Push state (x0-x15) onto stack.
       // Also store an extra copy of (x10,x11) just before the state.

       ldr             r4, [sp, #48]
       mov             r0, sp
       sub             sp, #80

       // iv: x12-x15
       ldm             r4, {X12,X13,X14,X15}
       stmdb           r0!, {X12,X13,X14,X15}

       // key: x4-x11
       ldrd            X8_X10, X9_X11, [r3, #24]
       strd            X8_X10, X9_X11, [sp, #8]
       stmdb           r0!, {X8_X10, X9_X11}
       ldm             r3, {X4-X9_X11}
       stmdb           r0!, {X4-X9_X11}

       b 1f
.Lexpand_32byte_k\@:
       // "expand 32-byte k"
       .word   0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
1:
       // constants: x0-x3
       adr             X3, .Lexpand_32byte_k\@
       ldm             X3, {X0-X3}
       strd            X0, X1, [sp, #16]
       strd            X2, X3, [sp, #24]

.Lnext_block\@:
       // Stack: <sp> empty_0-1 x10-x11 x0-x15 OUT IN LEN
       // Registers contain (x0-x9,x12-x15).

       // Do the core ChaCha permutation to update x0-x15.
       _chacha_permute \nrounds

       add             sp, #8
       // Stack: <sp> x10-x11 orig_x0-orig_x15 OUT IN LEN
       // Registers contain (x0-x9,x12-x15).

       // Free up some registers by pushing (x8-x9,x12-x15).
       push            {r8-r12,r14}

       // Stack: <sp> x8-x9 x12-x15 x10-x11 orig_x0-orig_x15 OUT IN LEN

       // Load (OUT, IN, LEN).
       ldrd            r8, r9, [sp, #96]
       ldr             r10, [sp, #104]
       orr             r14, r8, r9
       cmp             r10, #64        // Less than 64 bytes remaining?
       blt             .Lxor_slowpath\@
       tst             r14, #3         // IN or OUT isn't 4-byte aligned?
       bne             .Lxor_slowpath\@

       // Okay, there are at least 64 bytes of data remaining, and both IN and
       // OUT are 4-byte aligned.
       //
       // Add the original state and XOR the data with the keystream.
       // IN is r9, OUT is r8.

       // x0-x3
       ldrd            r10, r11, [sp, #32]
       add             X0, X0, r10
       add             X1, X1, r11
       ldrd            r10, r11, [sp, #40]
       add             X2, X2, r10
       add             X3, X3, r11
       ldmia           r9!, {r10-r12,r14}
       _le32_bswap     X0, X1, X2, X3
       eor             X0, X0, r10
       eor             X1, X1, r11
       eor             X2, X2, r12
       eor             X3, X3, r14
       stmia           r8!, {X0-X3}

       // x4-x7
       ldrd            r10, r11, [sp, #48]
       ldmia           r9!, {X0-X3}
       add             X4, r10, X4, ROR #brot
       add             X5, r11, X5, ROR #brot
       ldrd            r10, r11, [sp, #56]
       add             X6, r10, X6, ROR #brot
       add             X7, r11, X7, ROR #brot
       _le32_bswap     X4, X5, X6, X7
       eor             X4, X4, X0
       eor             X5, X5, X1
       eor             X6, X6, X2
       eor             X7, X7, X3
       stmia           r8!, {X4-X7}

       // x8-x15
       pop             {r0-r7}         // (x8-x9,x12-x15,x10-x11)
       ldrd            r10, r11, [sp, #32]
       add             r0, r0, r10     // x8
       add             r1, r1, r11     // x9
       ldrd            r10, r11, [sp, #40]
       add             r6, r6, r10     // x10
       add             r7, r7, r11     // x11
       ldmia           r9!, {r10-r12,r14}
       _le32_bswap     r0, r1, r6, r7
       eor             r0, r0, r10     // x8
       eor             r1, r1, r11     // x9
       eor             r6, r6, r12     // x10
       eor             r7, r7, r14     // x11
       stmia           r8!, {r0,r1,r6,r7}
       ldmia           r9!, {r0,r1,r6,r7}
       ldrd            r10, r11, [sp, #48]
       add             r2, r10, r2, ROR #drot  // x12
       add             r3, r11, r3, ROR #drot  // x13
       ldr             r12, [sp, #56]
       ldr             r14, [sp, #60]
       add             r4, r12, r4, ROR #drot  // x14
       add             r5, r14, r5, ROR #drot  // x15
       _le32_bswap     r2, r3, r4, r5
         ldr           r11, [sp, #72]  // LEN
       eor             r2, r2, r0      // x12
       eor             r3, r3, r1      // x13
       eor             r4, r4, r6      // x14
       eor             r5, r5, r7      // x15
         subs          r11, #64        // decrement and check LEN
       stmia           r8!, {r2-r5}

       beq             .Ldone\@

.Lprepare_for_next_block\@:

       // Stack: <sp> x0-x15 OUT IN LEN

       // Increment block counter (x12)
       add             r10, #1

       // Store updated (OUT, IN, LEN)
       strd            r8, r9, [sp, #64]
       str             r11, [sp, #72]

       // Store updated block counter (x12)
       str             r10, [sp, #48]

       // Reload state
       mov             r14, sp
       sub             sp, #16
       ldmia           r14!, {r0-r11}          // x0-x11
       strd            r10, r11, [sp, #8]      // save (x10,x11)
       ldmia           r14, {r10-r12,r14}      // x12-x15

       // Stack: <sp> empty0-1 x10-x11 x0-x15 OUT IN LEN
       b               .Lnext_block\@

.Lxor_slowpath\@:
       // Slow path: < 64 bytes remaining, or unaligned in or out buffer.  We
       // handle it in a fairly simple way: store the 64 bytes of keystream to
       // the stack, the XOR the needed portion with the data.

       // Allocate keystream buffer
       sub             sp, #64
       mov             r8, sp
       // Stack: <sp> ks0-ks15 x8-x9 x12-x15 x10-x11 orig_x0-orig_x15 OUT IN LEN

       // Save keystream for x0-x3
       ldrd            r10, r11, [sp, #96]
       add             X0, X0, r10
       add             X1, X1, r11
       ldrd            r10, r11, [sp, #104]
       add             X2, X2, r10
       add             X3, X3, r11
       _le32_bswap     X0, X1, X2, X3
       stmia           r8!, {X0-X3}

       // Save keystream for x4-x7
       ldrd            r10, r11, [sp, #112]
       add             X4, r10, X4, ROR #brot
       add             X5, r11, X5, ROR #brot
       ldrd            r10, r11, [sp, #120]
       add             X6, r10, X6, ROR #brot
       add             X7, r11, X7, ROR #brot
       _le32_bswap     X4, X5, X6, X7
         add           r14, sp, #64
       stmia           r8!, {X4-X7}

       // Save keystream for x8-x15
       ldm             r14, {r0-r7}            // (x8-x9,x12-x15,x10-x11)
       ldrd            r10, r11, [sp, #128]
       add             r0, r0, r10             // x8
       add             r1, r1, r11             // x9
       ldrd            r10, r11, [sp, #136]
       add             r6, r6, r10             // x10
       add             r7, r7, r11             // x11
       _le32_bswap     r0, r1, r6, r7
       stmia           r8!, {r0,r1,r6,r7}
       ldrd            r10, r11, [sp, #144]
       add             r2, r10, r2, ROR #drot  // x12
       add             r3, r11, r3, ROR #drot  // x13
       ldr             r12, [sp, #152]
       ldr             r14, [sp, #156]
       add             r4, r12, r4, ROR #drot  // x14
       add             r5, r14, r5, ROR #drot  // x15
       _le32_bswap     r2, r3, r4, r5
       stmia           r8, {r2-r5}

       // Stack: <sp> ks0-ks15 empty_0-empty_7 x0-x15 OUT IN LEN
       // Block counter is r10, IN is r9.

       mov             r0, sp
       ldr             r11, [sp, #168] // LEN
       ldr             r8, [sp, #160]  // OUT
       cmp             r11, #64
       movle           r1, r11
       movgt           r1, #64

       orr             r2, r8, r9
       tst             r2, #3          // IN or OUT misaligned?
       bne             .Lxor_next_byte\@

       // XOR a word at a time
.rept  16
       subs            r1, #4
       blt             .Lxor_words_done\@
       ldr             r3, [r9], #4
       ldr             r4, [r0], #4
       eor             r3, r3, r4
       str             r3, [r8], #4
.endr
       b               .Lxor_slowpath_done\@
.Lxor_words_done\@:
       ands            r1, r1, #3
       beq             .Lxor_slowpath_done\@

       // XOR a byte at a time
.Lxor_next_byte\@:
       ldrb            r3, [r9], #1
       ldrb            r4, [r0], #1
       eor             r3, r3, r4
       strb            r3, [r8], #1
       subs            r1, #1
       bne             .Lxor_next_byte\@

.Lxor_slowpath_done\@:
       subs            r11, #64
       add             sp, #96
       bgt             .Lprepare_for_next_block\@

.Ldone\@:
.endm  // _chacha

/*
 * void chacha_arm(u8 *out, const u8 *in, size_t len, const u32 key[8],
 *                const u32 iv[4], int nrounds);
 */
ENTRY(chacha_arm)
       cmp             r2, #0
       bxeq            lr

       push            {r0-r2,r4-r11,lr}

       ldr             r5, [sp, #52]   // nrounds
       cmp             r5, #12
       bne             .Lchacha20

       _chacha         12
       b               .Lchacha_done
.Lchacha20:
       _chacha         20

.Lchacha_done:
       add             sp, #76
       pop             {r4-r11, pc}
ENDPROC(chacha_arm)

.macro _hchacha        nrounds
       ldmia           r14!, {r0-r11}          // (x0-x11)
       push            {r10-r11}               // (x10,x11)
       sub             sp, #8
       ldm             r14, {r10-r12,r14}      // (x12-x15)
       _chacha_permute \nrounds
.endm

/*
 * void hchacha_arm(const u32 state[16], u32 out[8], int nrounds);
 */
ENTRY(hchacha_arm)
       push            {r1,r4-r11,lr}
       cmp             r2, #12
       mov             r14, r0
       bne             .Lhchacha20

       _hchacha        12
       b               .Lhchacha_done
.Lhchacha20:
       _hchacha        20

.Lhchacha_done:
       // skip over (x10,x11)
       add             sp, #16

       // fix up rotations of x12-x15
       mov             r10, r10, ROR #drot
       mov             r11, r11, ROR #drot
         pop           {r4}    // out
       mov             r12, r12, ROR #drot
       mov             r14, r14, ROR #drot

       // store (x0-x3,x12-x15) to out
       stm             r4, {r0-r3,r10-r12,r14}

       pop             {r4-r11,pc}
ENDPROC(hchacha_arm)
