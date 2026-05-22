/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

/*
 * MD5 implementation
 */

#include "md5.h"

//Constants for MD5Transform routine.
static cc_u8 S[4][4] = {
	{7, 12, 17, 22},
	{5,  9, 14, 20},
	{4, 11, 16, 23},
	{6, 10, 15, 21}
};

static void SDRM_MD5Transform(cc_u32 [4], const unsigned char*);
static void SDRM_Encode (unsigned char *, cc_u32 *, cc_u32);
static void SDRM_Decode (cc_u32 *, const unsigned char *, cc_u32);

static unsigned char PADDING[64] = {0x80, 0,};

/* F, G, H and I are basic MD5 functions.
 */
//#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
//#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
//#define H(x, y, z) ((x) ^ (y) ^ (z))
//#define I(x, y, z) ((y) ^ ((x) | (~z)))

#define F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z) F(z, x, y)
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | ~(z)))


/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) {					\
 (a) += F ((b), (c), (d)) + (x) + (cc_u32)(ac);		\
 (a) = ROTATE_LEFT ((a), (s));						\
 (a) += (b);										\
}
#define GG(a, b, c, d, x, s, ac) {					\
 (a) += G ((b), (c), (d)) + (x) + (cc_u32)(ac);		\
 (a) = ROTATE_LEFT ((a), (s));						\
 (a) += (b);										\
}
#define HH(a, b, c, d, x, s, ac) {					\
 (a) += H ((b), (c), (d)) + (x) + (cc_u32)(ac);		\
 (a) = ROTATE_LEFT ((a), (s));						\
 (a) += (b);										\
}
#define II(a, b, c, d, x, s, ac) {					\
 (a) += I ((b), (c), (d)) + (x) + (cc_u32)(ac);		\
 (a) = ROTATE_LEFT ((a), (s));						\
 (a) += (b);										\
}

/* MD5 initialization. Begins an MD5 operation, writing a new context.
 */
CRYPTOCORE_INTERNAL void SDRM_MD5_Init(SDRM_MD5Context *ctx)
{
	ctx->count[0] = 0;
	ctx->count[1] = 0;

	// Load magic initialization constants.
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
}

/* MD5 block update operation. Continues an MD5 message-digest
  operation, processing another message block, and updating the
  context.
 */
CRYPTOCORE_INTERNAL void SDRM_MD5_Update(SDRM_MD5Context *ctx, cc_u8* input, cc_u32 inputLen)
{
	cc_u32 i, idx, partLen;

	/* Compute number of bytes mod 64 */
	idx = (cc_u32)((ctx->count[0] >> 3) & 0x3F);

	/* Update number of bits */
	if ((ctx->count[0] += ((cc_u32)inputLen << 3)) < ((cc_u32)inputLen << 3))
	{
		ctx->count[1]++;
	}
	
	ctx->count[1] += ((cc_u32)inputLen >> 29);

	partLen = 64 - idx;

	// Transform as many times as possible.
	if (inputLen >= partLen)
	{
		memcpy(&ctx->buffer[idx], input, partLen);
		SDRM_MD5Transform(ctx->state, ctx->buffer);

		for (i = partLen; i + 63 < inputLen; i += 64) 
		{
			SDRM_MD5Transform(ctx->state, &input[i]);
		}

		idx = 0;
	}
	else
	{
		i = 0;
	}

	/* Buffer remaining input */
	memcpy(&ctx->buffer[idx], &input[i], inputLen-i);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
  the message digest and zeroizing the context.
 */
CRYPTOCORE_INTERNAL void SDRM_MD5_Final(SDRM_MD5Context *ctx, cc_u8* digest)
{
	unsigned char bits[8];
	cc_u32 idx, padLen;

	/* Save number of bits */
	SDRM_Encode(bits, ctx->count, 8);

	// Pad out to 56 mod 64.
	idx = (cc_u32)((ctx->count[0] >> 3) & 0x3f);
	padLen = (idx < 56) ? (56 - idx) : (120 - idx);
	SDRM_MD5_Update (ctx, PADDING, padLen);

	/* Append length (before padding) */
	SDRM_MD5_Update (ctx, bits, 8);

	/* Store state in digest */
	SDRM_Encode (digest, ctx->state, 16);

	// Zeroize sensitive information.
	memset(ctx, 0, sizeof(*ctx));
}

/* MD5 basic transformation. Transforms state based on block.
 */
static void SDRM_MD5Transform (cc_u32 state[4], const unsigned char* block)
{
	cc_u32 a = state[0], b = state[1], c = state[2], d = state[3], x[16];

	SDRM_Decode (x, block, 64);

	/* Round 1 */
	FF (a, b, c, d, x[ 0], S[0][0], 0xd76aa478); /* 1 */
	FF (d, a, b, c, x[ 1], S[0][1], 0xe8c7b756); /* 2 */
	FF (c, d, a, b, x[ 2], S[0][2], 0x242070db); /* 3 */
	FF (b, c, d, a, x[ 3], S[0][3], 0xc1bdceee); /* 4 */
	FF (a, b, c, d, x[ 4], S[0][0], 0xf57c0faf); /* 5 */
	FF (d, a, b, c, x[ 5], S[0][1], 0x4787c62a); /* 6 */
	FF (c, d, a, b, x[ 6], S[0][2], 0xa8304613); /* 7 */
	FF (b, c, d, a, x[ 7], S[0][3], 0xfd469501); /* 8 */
	FF (a, b, c, d, x[ 8], S[0][0], 0x698098d8); /* 9 */
	FF (d, a, b, c, x[ 9], S[0][1], 0x8b44f7af); /* 10 */
	FF (c, d, a, b, x[10], S[0][2], 0xffff5bb1); /* 11 */
	FF (b, c, d, a, x[11], S[0][3], 0x895cd7be); /* 12 */
	FF (a, b, c, d, x[12], S[0][0], 0x6b901122); /* 13 */
	FF (d, a, b, c, x[13], S[0][1], 0xfd987193); /* 14 */
	FF (c, d, a, b, x[14], S[0][2], 0xa679438e); /* 15 */
	FF (b, c, d, a, x[15], S[0][3], 0x49b40821); /* 16 */

	/* Round 2 */
	GG (a, b, c, d, x[ 1], S[1][0], 0xf61e2562); /* 17 */
	GG (d, a, b, c, x[ 6], S[1][1], 0xc040b340); /* 18 */
	GG (c, d, a, b, x[11], S[1][2], 0x265e5a51); /* 19 */
	GG (b, c, d, a, x[ 0], S[1][3], 0xe9b6c7aa); /* 20 */
	GG (a, b, c, d, x[ 5], S[1][0], 0xd62f105d); /* 21 */
	GG (d, a, b, c, x[10], S[1][1], 0x02441453); /* 22 */
	GG (c, d, a, b, x[15], S[1][2], 0xd8a1e681); /* 23 */
	GG (b, c, d, a, x[ 4], S[1][3], 0xe7d3fbc8); /* 24 */
	GG (a, b, c, d, x[ 9], S[1][0], 0x21e1cde6); /* 25 */
	GG (d, a, b, c, x[14], S[1][1], 0xc33707d6); /* 26 */
	GG (c, d, a, b, x[ 3], S[1][2], 0xf4d50d87); /* 27 */
	GG (b, c, d, a, x[ 8], S[1][3], 0x455a14ed); /* 28 */
	GG (a, b, c, d, x[13], S[1][0], 0xa9e3e905); /* 29 */
	GG (d, a, b, c, x[ 2], S[1][1], 0xfcefa3f8); /* 30 */
	GG (c, d, a, b, x[ 7], S[1][2], 0x676f02d9); /* 31 */
	GG (b, c, d, a, x[12], S[1][3], 0x8d2a4c8a); /* 32 */

	/* Round 3 */
	HH (a, b, c, d, x[ 5], S[2][0], 0xfffa3942); /* 33 */
	HH (d, a, b, c, x[ 8], S[2][1], 0x8771f681); /* 34 */
	HH (c, d, a, b, x[11], S[2][2], 0x6d9d6122); /* 35 */
	HH (b, c, d, a, x[14], S[2][3], 0xfde5380c); /* 36 */
	HH (a, b, c, d, x[ 1], S[2][0], 0xa4beea44); /* 37 */
	HH (d, a, b, c, x[ 4], S[2][1], 0x4bdecfa9); /* 38 */
	HH (c, d, a, b, x[ 7], S[2][2], 0xf6bb4b60); /* 39 */
	HH (b, c, d, a, x[10], S[2][3], 0xbebfbc70); /* 40 */
	HH (a, b, c, d, x[13], S[2][0], 0x289b7ec6); /* 41 */
	HH (d, a, b, c, x[ 0], S[2][1], 0xeaa127fa); /* 42 */
	HH (c, d, a, b, x[ 3], S[2][2], 0xd4ef3085); /* 43 */
	HH (b, c, d, a, x[ 6], S[2][3], 0x04881d05); /* 44 */
	HH (a, b, c, d, x[ 9], S[2][0], 0xd9d4d039); /* 45 */
	HH (d, a, b, c, x[12], S[2][1], 0xe6db99e5); /* 46 */
	HH (c, d, a, b, x[15], S[2][2], 0x1fa27cf8); /* 47 */
	HH (b, c, d, a, x[ 2], S[2][3], 0xc4ac5665); /* 48 */

	/* Round 4 */
	II (a, b, c, d, x[ 0], S[3][0], 0xf4292244); /* 49 */
	II (d, a, b, c, x[ 7], S[3][1], 0x432aff97); /* 50 */
	II (c, d, a, b, x[14], S[3][2], 0xab9423a7); /* 51 */
	II (b, c, d, a, x[ 5], S[3][3], 0xfc93a039); /* 52 */
	II (a, b, c, d, x[12], S[3][0], 0x655b59c3); /* 53 */
	II (d, a, b, c, x[ 3], S[3][1], 0x8f0ccc92); /* 54 */
	II (c, d, a, b, x[10], S[3][2], 0xffeff47d); /* 55 */
	II (b, c, d, a, x[ 1], S[3][3], 0x85845dd1); /* 56 */
	II (a, b, c, d, x[ 8], S[3][0], 0x6fa87e4f); /* 57 */
	II (d, a, b, c, x[15], S[3][1], 0xfe2ce6e0); /* 58 */
	II (c, d, a, b, x[ 6], S[3][2], 0xa3014314); /* 59 */
	II (b, c, d, a, x[13], S[3][3], 0x4e0811a1); /* 60 */
	II (a, b, c, d, x[ 4], S[3][0], 0xf7537e82); /* 61 */
	II (d, a, b, c, x[11], S[3][1], 0xbd3af235); /* 62 */
	II (c, d, a, b, x[ 2], S[3][2], 0x2ad7d2bb); /* 63 */
	II (b, c, d, a, x[ 9], S[3][3], 0xeb86d391); /* 64 */

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;

	//Zeroize sensitive information.
	memset (x, 0, sizeof (x));
}

/* Encodes input (cc_u4) into output (unsigned char). Assumes len is
  a multiple of 4.
 */
static void SDRM_Encode (unsigned char *output, cc_u32 *input, cc_u32 len)
{
	cc_u32 i, j;

	for (i = 0, j = 0; j < len; i++, j += 4)
	{
		output[j  ] = (unsigned char)((input[i]      ) & 0xff);
		output[j+1] = (unsigned char)((input[i] >>  8) & 0xff);
		output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);
		output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);
	}
}

/* Decodes input (unsigned char) into output (UINT4). Assumes len is
  a multiple of 4.
 */
static void SDRM_Decode (cc_u32 *output, const unsigned char *input, cc_u32 len)
{
	cc_u32 i, j;

	for (i = 0, j = 0; j < len; i++, j += 4)
	{
		output[i] = (
		(((cc_u32)input[j]    )      ) | 
		(((cc_u32)input[j + 1]) <<  8) |
		(((cc_u32)input[j + 2]) << 16) |
		(((cc_u32)input[j + 3]) << 24));
	}
}

/***************************** End of File *****************************/
