/**
 * \file	rc4.c
 * @brief	implementation of RC4 encryption scheme
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/12/01
 */

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include "rc4.h"

////////////////////////////////////////////////////////////////////////////
// initial vector of s
////////////////////////////////////////////////////////////////////////////
static cc_u32 RC4_S_VALUE_LITTLE[] = {
	0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
	0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
	0x23222120, 0x27262524, 0x2b2a2928, 0x2f2e2d2c,
	0x33323130, 0x37363534, 0x3b3a3938, 0x3f3e3d3c,
	0x43424140, 0x47464544, 0x4b4a4948, 0x4f4e4d4c,
	0x53525150, 0x57565554, 0x5b5a5958, 0x5f5e5d5c,
	0x63626160, 0x67666564, 0x6b6a6968, 0x6f6e6d6c,
	0x73727170, 0x77767574, 0x7b7a7978, 0x7f7e7d7c,
	0x83828180, 0x87868584, 0x8b8a8988, 0x8f8e8d8c,
	0x93929190, 0x97969594, 0x9b9a9998, 0x9f9e9d9c,
	0xa3a2a1a0, 0xa7a6a5a4, 0xabaaa9a8, 0xafaeadac,
	0xb3b2b1b0, 0xb7b6b5b4, 0xbbbab9b8, 0xbfbebdbc,
	0xc3c2c1c0, 0xc7c6c5c4, 0xcbcac9c8, 0xcfcecdcc,
	0xd3d2d1d0, 0xd7d6d5d4, 0xdbdad9d8, 0xdfdedddc,
	0xe3e2e1e0, 0xe7e6e5e4, 0xebeae9e8, 0xefeeedec,
	0xf3f2f1f0, 0xf7f6f5f4, 0xfbfaf9f8, 0xfffefdfc,
};

static cc_u32 RC4_S_VALUE_BIG[] = {
	0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
	0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f,
	0x20212223, 0x24252627, 0x28292a2b, 0x2c2d2e2f,
	0x30313233, 0x34353637, 0x38393a3b, 0x3c3d3e3f,
	0x40414243, 0x44454647, 0x48494a4b, 0x4c4d4e4f,
	0x50515253, 0x54555657, 0x58595a5b, 0x5c5d5e5f,
	0x60616263, 0x64656667, 0x68696a6b, 0x6c6d6e6f,
	0x70717273, 0x74757677, 0x78797a7b, 0x7c7d7e7f,
	0x80818283, 0x84858687, 0x88898a8b, 0x8c8d8e8f,
	0x90919293, 0x94959697, 0x98999a9b, 0x9c9d9e9f,
	0xa0a1a2a3, 0xa4a5a6a7, 0xa8a9aaab, 0xacadaeaf,
	0xb0b1b2b3, 0xb4b5b6b7, 0xb8b9babb, 0xbcbdbebf,
	0xc0c1c2c3, 0xc4c5c6c7, 0xc8c9cacb, 0xcccdcecf,
	0xd0d1d2d3, 0xd4d5d6d7, 0xd8d9dadb, 0xdcdddedf,
	0xe0e1e2e3, 0xe4e5e6e7, 0xe8e9eaeb, 0xecedeeef,
	0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff
};

/*
 * @fn		SDRM_RC4_Setup
 * @brief	intialize s
 *
 * @param	ctx					[in]crypto context
 * @param	UserKey				[in]user key
 * @param	keyLen				[out]byte-length of UserKey
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 */
CRYPTOCORE_INTERNAL int SDRM_RC4_Setup(SDRM_RC4Context *ctx, cc_u8 *UserKey, cc_u32 keyLen)
{
	cc_u32	i, j, loc = keyLen;
	cc_u8	temp;

	//initialization
	i = 0xff;
	if (((cc_u8*)&i)[0] == 0xff)
	{
//		LOG4DRM_INFO(&CryptoLogCTX), "is Little Endian machine\n");
		memcpy(ctx->s, RC4_S_VALUE_LITTLE, 256);
	}
	else
	{
//		LOG4DRM_INFO(&CryptoLogCTX), "is Big Endian machine\n");
		memcpy(ctx->s, RC4_S_VALUE_BIG, 256);
	}
	
	memcpy(ctx->key, UserKey, keyLen);

	ctx->keyLen = keyLen;
	ctx->i = 0;
	ctx->j = 0;

	//scrambling
	if ((keyLen == 16) || (keyLen == 32))
	{
		loc--;
		for (i = 0, j = 0; i < 256; ++i)
		{
			j= (j + ctx->key[i & loc] + ctx->s[i]) & 0xff;
			temp = ctx->s[i];
			ctx->s[i] = ctx->s[j];
			ctx->s[j] = temp;
		}
	}
	else
	{
		for (i = 0, j = 0; i < 256; ++i)
		{
			j = (j + ctx->key[i % ctx->keyLen] + ctx->s[i]) & 0xff;
			temp = ctx->s[i];
			ctx->s[i] = ctx->s[j];
			ctx->s[j] = temp;
		}
	}

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_RC4_PRNG
 * @brief	process stream data
 *
 * @param	ctx					[in]crypto context
 * @param	in					[in]plaintext
 * @param	inLen				[in]byte-length of in
 * @param	out					[out]cipher text
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 */
CRYPTOCORE_INTERNAL int SDRM_RC4_PRNG(SDRM_RC4Context *ctx, cc_u8 *in, cc_u32 inLen, cc_u8 *out)
{
	cc_u32	i, j, k;
	cc_u8	temp;
	
	i = ctx->i;
	j = ctx->j;

	for (k = 0; k < inLen; k++)
	{
		i++;
		i &= 0xff;
		j += ctx->s[i];
		j &= 0xff;

		temp = ctx->s[i];
		ctx->s[i] = ctx->s[j];
		ctx->s[j] = temp;

		temp = ctx->s[i] + ctx->s[j];

		out[k] = in[k]^(ctx->s[temp]);
	}

	ctx->i = i;
	ctx->j = j;

	return CRYPTO_SUCCESS;
}

/***************************** End of File *****************************/
