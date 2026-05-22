/*
 * FIPS 180-2 SHA-224/256/384/512 implementation
 * Last update: 02/02/2007
 * Issue date:  04/30/2005
 *
 * Copyright (C) 2005, 2007 Olivier Gay <olivier.gay@a3.epfl.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* JS Park's posting:
	Modification for naming confilct.
	Attach prefix 'SDRM_' for all function and constants.
	Change name of data context to 'SDRM_SHAxxxContext' (xxx is bit length of digest)
*/

#include <string.h>

#include "sha2.h"

#define SDRM_SHA2_SHFR(x, n)	(x >> n)
#define SDRM_SHA2_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define SDRM_SHA2_ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define SDRM_SHA2_CH(x, y, z)  ((x & y) ^ (~x & z))
#define SDRM_SHA2_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define SDRM_SHA2_SHA256_F1(x) (SDRM_SHA2_ROTR(x,  2) ^ SDRM_SHA2_ROTR(x, 13) ^ SDRM_SHA2_ROTR(x, 22))
#define SDRM_SHA2_SHA256_F2(x) (SDRM_SHA2_ROTR(x,  6) ^ SDRM_SHA2_ROTR(x, 11) ^ SDRM_SHA2_ROTR(x, 25))
#define SDRM_SHA2_SHA256_F3(x) (SDRM_SHA2_ROTR(x,  7) ^ SDRM_SHA2_ROTR(x, 18) ^ SDRM_SHA2_SHFR(x,  3))
#define SDRM_SHA2_SHA256_F4(x) (SDRM_SHA2_ROTR(x, 17) ^ SDRM_SHA2_ROTR(x, 19) ^ SDRM_SHA2_SHFR(x, 10))

#define SDRM_SHA2_SHA512_F1(x) (SDRM_SHA2_ROTR(x, 28) ^ SDRM_SHA2_ROTR(x, 34) ^ SDRM_SHA2_ROTR(x, 39))
#define SDRM_SHA2_SHA512_F2(x) (SDRM_SHA2_ROTR(x, 14) ^ SDRM_SHA2_ROTR(x, 18) ^ SDRM_SHA2_ROTR(x, 41))
#define SDRM_SHA2_SHA512_F3(x) (SDRM_SHA2_ROTR(x,  1) ^ SDRM_SHA2_ROTR(x,  8) ^ SDRM_SHA2_SHFR(x,  7))
#define SDRM_SHA2_SHA512_F4(x) (SDRM_SHA2_ROTR(x, 19) ^ SDRM_SHA2_ROTR(x, 61) ^ SDRM_SHA2_SHFR(x,  6))

#define SDRM_SHA2_UNPACK32(x, str)				\
do {											\
	*((str) + 3) = (cc_u8) ((x)	  );			\
	*((str) + 2) = (cc_u8) ((x) >>  8);			\
	*((str) + 1) = (cc_u8) ((x) >> 16);			\
	*((str) + 0) = (cc_u8) ((x) >> 24);			\
} while(0)

#define SDRM_SHA2_PACK32(str, x)				\
do {											\
	*(x) =	  ((cc_u32) *((str) + 3)	  )		\
			| ((cc_u32) *((str) + 2) <<  8)		\
			| ((cc_u32) *((str) + 1) << 16)		\
			| ((cc_u32) *((str) + 0) << 24);	\
} while(0)

#define SDRM_SHA2_UNPACK64(x, str)				\
do {											\
	*((str) + 7) = (cc_u8) ((x)	  );			\
	*((str) + 6) = (cc_u8) ((x) >>  8);			\
	*((str) + 5) = (cc_u8) ((x) >> 16);			\
	*((str) + 4) = (cc_u8) ((x) >> 24);			\
	*((str) + 3) = (cc_u8) ((x) >> 32);			\
	*((str) + 2) = (cc_u8) ((x) >> 40);			\
	*((str) + 1) = (cc_u8) ((x) >> 48);			\
	*((str) + 0) = (cc_u8) ((x) >> 56);			\
} while(0)

#define SDRM_SHA2_PACK64(str, x)				\
do {											\
	*(x) =	((cc_u64) *((str) + 7)	  )			\
			| ((cc_u64) *((str) + 6) <<  8)		\
			| ((cc_u64) *((str) + 5) << 16)		\
			| ((cc_u64) *((str) + 4) << 24)		\
			| ((cc_u64) *((str) + 3) << 32)		\
			| ((cc_u64) *((str) + 2) << 40)		\
			| ((cc_u64) *((str) + 1) << 48)		\
			| ((cc_u64) *((str) + 0) << 56);	\
} while(0)

/* Macros used for loops unrolling */

#define SDRM_SHA2_SHA256_SCR(i)								\
{															\
	w[i] =  SDRM_SHA2_SHA256_F4(w[i -  2]) + w[i -  7]		\
			+ SDRM_SHA2_SHA256_F3(w[i - 15]) + w[i - 16];	\
}

#define SDRM_SHA2_SHA512_SCR(i)								\
{															\
	w[i] =  SDRM_SHA2_SHA512_F4(w[i -  2]) + w[i -  7]		\
			+ SDRM_SHA2_SHA512_F3(w[i - 15]) + w[i - 16];	\
}

#define SDRM_SHA2_SHA256_EXP(a, b, c, d, e, f, g, h, j)							\
{																				\
	t1 = wv[h] + SDRM_SHA2_SHA256_F2(wv[e]) + SDRM_SHA2_CH(wv[e], wv[f], wv[g])	\
		+ sha256_k[j] + w[j];													\
	t2 = SDRM_SHA2_SHA256_F1(wv[a]) + SDRM_SHA2_MAJ(wv[a], wv[b], wv[c]);		\
	wv[d] += t1;																\
	wv[h] = t1 + t2;															\
}

#define SDRM_SHA2_SHA512_EXP(a, b, c, d, e, f, g ,h, j)							\
{																				\
	t1 = wv[h] + SDRM_SHA2_SHA512_F2(wv[e]) + SDRM_SHA2_CH(wv[e], wv[f], wv[g]) \
		+ sha512_k[j] + w[j];													\
	t2 = SDRM_SHA2_SHA512_F1(wv[a]) + SDRM_SHA2_MAJ(wv[a], wv[b], wv[c]);		\
	wv[d] += t1;																\
	wv[h] = t1 + t2;															\
}

CRYPTOCORE_INTERNAL cc_u32 sha224_h0[8] =
            {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
             0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4};

CRYPTOCORE_INTERNAL cc_u32 sha256_h0[8] =
			{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
			 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

CRYPTOCORE_INTERNAL cc_u32 sha256_k[64] =
			{0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
			 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
			 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
			 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
			 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
			 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
			 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
			 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
			 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#ifndef _OP64_NOTSUPPORTED

#ifdef _WIN32
CRYPTOCORE_INTERNAL cc_u64 sha384_h0[8] =
			{0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
			 0x9159015a3070dd17, 0x152fecd8f70e5939,
			 0x67332667ffc00b31, 0x8eb44a8768581511,
			 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4};

CRYPTOCORE_INTERNAL cc_u64 sha512_h0[8] =
			{0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
			 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
			 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
			 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};

CRYPTOCORE_INTERNAL cc_u64 sha512_k[80] =
			{0x428a2f98d728ae22, 0x7137449123ef65cd,
			 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
			 0x3956c25bf348b538, 0x59f111f1b605d019,
			 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
			 0xd807aa98a3030242, 0x12835b0145706fbe,
			 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
			 0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
			 0x9bdc06a725c71235, 0xc19bf174cf692694,
			 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
			 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
			 0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
			 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
			 0x983e5152ee66dfab, 0xa831c66d2db43210,
			 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
			 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
			 0x06ca6351e003826f, 0x142929670a0e6e70,
			 0x27b70a8546d22ffc, 0x2e1b21385c26c926,
			 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
			 0x650a73548baf63de, 0x766a0abb3c77b2a8,
			 0x81c2c92e47edaee6, 0x92722c851482353b,
			 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
			 0xc24b8b70d0f89791, 0xc76c51a30654be30,
			 0xd192e819d6ef5218, 0xd69906245565a910,
			 0xf40e35855771202a, 0x106aa07032bbd1b8,
			 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
			 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
			 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
			 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
			 0x748f82ee5defb2fc, 0x78a5636f43172f60,
			 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
			 0x90befffa23631e28, 0xa4506cebde82bde9,
			 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
			 0xca273eceea26619c, 0xd186b8c721c0c207,
			 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
			 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
			 0x113f9804bef90dae, 0x1b710b35131c471b,
			 0x28db77f523047d84, 0x32caab7b40c72493,
			 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
			 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
			 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};
#else
CRYPTOCORE_INTERNAL cc_u64 sha384_h0[8] =
			{0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL,
			 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
			 0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
			 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL};

CRYPTOCORE_INTERNAL cc_u64 sha512_h0[8] =
			{0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
			 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
			 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
			 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

CRYPTOCORE_INTERNAL cc_u64 sha512_k[80] =
			{0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
			 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
			 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
			 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
			 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
			 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
			 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
			 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
			 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
			 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
			 0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
			 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
			 0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
			 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
			 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
			 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
			 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
			 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
			 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
			 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
			 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
			 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
			 0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
			 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
			 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
			 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
			 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
			 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
			 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
			 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
			 0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
			 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
			 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
			 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
			 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
			 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
			 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
			 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
			 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
			 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};
#endif //_WIN32
#endif //_OP64_NOTSUPPORTED

/* SHA-256 functions */

CRYPTOCORE_INTERNAL void SDRM_SHA256_Transf(SDRM_SHA256Context* ctx, const cc_u8 *message, cc_u32 block_nb)
{
	cc_u32 w[64];
	cc_u32 wv[8];
	cc_u32 t1, t2;
	const cc_u8 *sub_block;
	int i;

	int j;

	for (i = 0; i < (int) block_nb; i++)
	{
		sub_block = message + (i << 6);

		for (j = 0; j < 16; j++)
		{
			SDRM_SHA2_PACK32(&sub_block[j << 2], &w[j]);
		}

		for (j = 16; j < 64; j++)
		{
			SDRM_SHA2_SHA256_SCR(j);
		}

		for (j = 0; j < 8; j++)
		{
			wv[j] = ctx->h[j];
		}

		for (j = 0; j < 64; j++)
		{
			t1 = wv[7] + SDRM_SHA2_SHA256_F2(wv[4]) + SDRM_SHA2_CH(wv[4], wv[5], wv[6]) + sha256_k[j] + w[j];
			t2 = SDRM_SHA2_SHA256_F1(wv[0]) + SDRM_SHA2_MAJ(wv[0], wv[1], wv[2]);
			wv[7] = wv[6];
			wv[6] = wv[5];
			wv[5] = wv[4];
			wv[4] = wv[3] + t1;
			wv[3] = wv[2];
			wv[2] = wv[1];
			wv[1] = wv[0];
			wv[0] = t1 + t2;
		}

		for (j = 0; j < 8; j++)
		{
			ctx->h[j] += wv[j];
		}
	}
}

CRYPTOCORE_INTERNAL void SDRM_SHA256_Init(SDRM_SHA256Context* ctx)
{
	int i;
	for (i = 0; i < 8; i++)
	{
		ctx->h[i] = sha256_h0[i];
	}

	ctx->len = 0;
	ctx->tot_len = 0;
}

CRYPTOCORE_INTERNAL void SDRM_SHA256_Update(SDRM_SHA256Context* ctx, const cc_u8 *message, cc_u32 len)
{
	cc_u32 block_nb;
	cc_u32 new_len, rem_len, tmp_len;
	const cc_u8 *shifted_message;

	tmp_len = SDRM_SHA256_DATA_SIZE - ctx->len;
	rem_len = len < tmp_len ? len : tmp_len;

	memcpy(&ctx->block[ctx->len], message, rem_len);

	if (ctx->len + len < SDRM_SHA256_DATA_SIZE)
	{
		ctx->len += len;
		return;
	}

	new_len = len - rem_len;
	block_nb = new_len / SDRM_SHA256_DATA_SIZE;

	shifted_message = message + rem_len;

	SDRM_SHA256_Transf(ctx, ctx->block, 1);
	SDRM_SHA256_Transf(ctx, shifted_message, block_nb);

	rem_len = new_len % SDRM_SHA256_DATA_SIZE;

	memcpy(ctx->block, &shifted_message[block_nb << 6], rem_len);

	ctx->len = rem_len;
	ctx->tot_len += (block_nb + 1) << 6;
}

CRYPTOCORE_INTERNAL void SDRM_SHA256_Final(SDRM_SHA256Context* ctx, cc_u8 *digest)
{
	cc_u32 block_nb;
	cc_u32 pm_len;
	cc_u32 len_b;

	int i;

	block_nb = (1 + ((SDRM_SHA256_DATA_SIZE - 9) < (ctx->len % SDRM_SHA256_DATA_SIZE)));

	len_b = (ctx->tot_len + ctx->len) << 3;
	pm_len = block_nb << 6;

	memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
	ctx->block[ctx->len] = 0x80;
	SDRM_SHA2_UNPACK32(len_b, ctx->block + pm_len - 4);

	SDRM_SHA256_Transf(ctx, ctx->block, block_nb);

	for (i = 0 ; i < 8; i++)
	{
		SDRM_SHA2_UNPACK32(ctx->h[i], &digest[i << 2]);
	}
}

#ifndef _OP64_NOTSUPPORTED

/* SHA-512 functions */

CRYPTOCORE_INTERNAL void SDRM_SHA512_Transf(SDRM_SHA512Context* ctx, const cc_u8 *message, cc_u32 block_nb)
{
	cc_u64 w[80];
	cc_u64 wv[8];
	cc_u64 t1, t2;
	const cc_u8 *sub_block;
	int i, j;

	for (i = 0; i < (int) block_nb; i++)
	{
		sub_block = message + (i << 7);

		for (j = 0; j < 16; j++)
		{
			SDRM_SHA2_PACK64(&sub_block[j << 3], &w[j]);
		}

		for (j = 16; j < 80; j++)
		{
			SDRM_SHA2_SHA512_SCR(j);
		}

		for (j = 0; j < 8; j++)
		{
			wv[j] = ctx->h[j];
		}

		for (j = 0; j < 80; j++)
		{
			t1 = wv[7] + SDRM_SHA2_SHA512_F2(wv[4]) + SDRM_SHA2_CH(wv[4], wv[5], wv[6])
				+ sha512_k[j] + w[j];
			t2 = SDRM_SHA2_SHA512_F1(wv[0]) + SDRM_SHA2_MAJ(wv[0], wv[1], wv[2]);
			wv[7] = wv[6];
			wv[6] = wv[5];
			wv[5] = wv[4];
			wv[4] = wv[3] + t1;
			wv[3] = wv[2];
			wv[2] = wv[1];
			wv[1] = wv[0];
			wv[0] = t1 + t2;
		}

		for (j = 0; j < 8; j++)
		{
			ctx->h[j] += wv[j];
		}
	}
}

CRYPTOCORE_INTERNAL void SDRM_SHA512_Init(SDRM_SHA512Context* ctx)
{
	int i;
	for (i = 0; i < 8; i++)
	{
		ctx->h[i] = sha512_h0[i];
	}

	ctx->len = 0;
	ctx->tot_len = 0;
}

CRYPTOCORE_INTERNAL void SDRM_SHA512_Update(SDRM_SHA512Context* ctx, const cc_u8 *message, cc_u32 len)
{
	cc_u32 block_nb;
	cc_u32 new_len, rem_len, tmp_len;
	const cc_u8 *shifted_message;

	tmp_len = SDRM_SHA512_DATA_SIZE - ctx->len;
	rem_len = len < tmp_len ? len : tmp_len;

	memcpy(&ctx->block[ctx->len], message, rem_len);

	if (ctx->len + len < SDRM_SHA512_DATA_SIZE)
	{
		ctx->len += len;
		return;
	}

	new_len = len - rem_len;
	block_nb = new_len / SDRM_SHA512_DATA_SIZE;

	shifted_message = message + rem_len;

	SDRM_SHA512_Transf(ctx, ctx->block, 1);
	SDRM_SHA512_Transf(ctx, shifted_message, block_nb);

	rem_len = new_len % SDRM_SHA512_DATA_SIZE;

	memcpy(ctx->block, &shifted_message[block_nb << 7], rem_len);

	ctx->len = rem_len;
	ctx->tot_len += (block_nb + 1) << 7;
}

CRYPTOCORE_INTERNAL void SDRM_SHA512_Final(SDRM_SHA512Context* ctx, cc_u8 *digest)
{
	cc_u32 block_nb;
	cc_u32 pm_len;
	cc_u32 len_b;

	int i;

	block_nb = 1 + ((SDRM_SHA512_DATA_SIZE - 17) < (ctx->len % SDRM_SHA512_DATA_SIZE));

	len_b = (ctx->tot_len + ctx->len) << 3;
	pm_len = block_nb << 7;

	memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
	ctx->block[ctx->len] = 0x80;
	SDRM_SHA2_UNPACK32(len_b, ctx->block + pm_len - 4);

	SDRM_SHA512_Transf(ctx, ctx->block, block_nb);

	for (i = 0 ; i < 8; i++)
	{
		SDRM_SHA2_UNPACK64(ctx->h[i], &digest[i << 3]);
	}
}

/* SHA-384 functions */

CRYPTOCORE_INTERNAL void SDRM_SHA384_Init(SDRM_SHA384Context* ctx)
{
	int i;
	for (i = 0; i < 8; i++)
	{
		ctx->h[i] = sha384_h0[i];
	}

	ctx->len = 0;
	ctx->tot_len = 0;
}

CRYPTOCORE_INTERNAL void SDRM_SHA384_Update(SDRM_SHA384Context* ctx, const cc_u8 *message, cc_u32 len)
{
	cc_u32 block_nb;
	cc_u32 new_len, rem_len, tmp_len;
	const cc_u8 *shifted_message;

	tmp_len = SDRM_SHA384_DATA_SIZE - ctx->len;
	rem_len = len < tmp_len ? len : tmp_len;

	memcpy(&ctx->block[ctx->len], message, rem_len);

	if (ctx->len + len < SDRM_SHA384_DATA_SIZE)
	{
		ctx->len += len;
		return;
	}

	new_len = len - rem_len;
	block_nb = new_len / SDRM_SHA384_DATA_SIZE;

	shifted_message = message + rem_len;

	SDRM_SHA512_Transf(ctx, ctx->block, 1);
	SDRM_SHA512_Transf(ctx, shifted_message, block_nb);

	rem_len = new_len % SDRM_SHA384_DATA_SIZE;

	memcpy(ctx->block, &shifted_message[block_nb << 7], rem_len);

	ctx->len = rem_len;
	ctx->tot_len += (block_nb + 1) << 7;
}

CRYPTOCORE_INTERNAL void SDRM_SHA384_Final(SDRM_SHA384Context* ctx, cc_u8 *digest)
{
	cc_u32 block_nb;
	cc_u32 pm_len;
	cc_u32 len_b;

	int i;

	block_nb = (1 + ((SDRM_SHA384_DATA_SIZE - 17) < (ctx->len % SDRM_SHA384_DATA_SIZE)));

	len_b = (ctx->tot_len + ctx->len) << 3;
	pm_len = block_nb << 7;

	memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
	ctx->block[ctx->len] = 0x80;
	SDRM_SHA2_UNPACK32(len_b, ctx->block + pm_len - 4);

	SDRM_SHA512_Transf(ctx, ctx->block, block_nb);

	for (i = 0 ; i < 6; i++)
	{
		SDRM_SHA2_UNPACK64(ctx->h[i], &digest[i << 3]);
	}
}

#endif //_OP64_NOTSUPPORTED

/* SHA-224 functions */

CRYPTOCORE_INTERNAL void SDRM_SHA224_Init(SDRM_SHA224Context *ctx)
{
    int i;
    for (i = 0; i < 8; i++) {
        ctx->h[i] = sha224_h0[i];
    }

    ctx->len = 0;
    ctx->tot_len = 0;
}

CRYPTOCORE_INTERNAL void SDRM_SHA224_Update(SDRM_SHA224Context *ctx, const unsigned char *message,
                   unsigned int len)
{
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const unsigned char *shifted_message;

    tmp_len = SDRM_SHA224_DATA_SIZE - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(&ctx->block[ctx->len], message, rem_len);

    if (ctx->len + len < SDRM_SHA224_DATA_SIZE) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / SDRM_SHA224_DATA_SIZE;

    shifted_message = message + rem_len;

    SDRM_SHA256_Transf(ctx, ctx->block, 1);
    SDRM_SHA256_Transf(ctx, shifted_message, block_nb);

    rem_len = new_len % SDRM_SHA224_DATA_SIZE;

    memcpy(ctx->block, &shifted_message[block_nb << 6],
           rem_len);

    ctx->len = rem_len;
    ctx->tot_len += (block_nb + 1) << 6;
}

CRYPTOCORE_INTERNAL void SDRM_SHA224_Final(SDRM_SHA224Context *ctx, unsigned char *digest)
{
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;

    int i;

    block_nb = (1 + ((SDRM_SHA224_DATA_SIZE - 9)
                     < (ctx->len % SDRM_SHA224_DATA_SIZE)));

    len_b = (ctx->tot_len + ctx->len) << 3;
    pm_len = block_nb << 6;

    memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
    ctx->block[ctx->len] = 0x80;
    SDRM_SHA2_UNPACK32(len_b, ctx->block + pm_len - 4);

    SDRM_SHA256_Transf(ctx, ctx->block, block_nb);

    for (i = 0 ; i < 7; i++) {
        SDRM_SHA2_UNPACK32(ctx->h[i], &digest[i << 2]);
    }
}
