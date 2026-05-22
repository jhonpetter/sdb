/**
 * \file	hmac.c
 * @brief	funciton for c-mac code generation by SHA1 and MD5
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/12/19
 */

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include "hmac.h"
#include "sha1.h"
#include "sha2.h"
#include "md5.h"

////////////////////////////////////////////////////////////////////////////
// Functions
////////////////////////////////////////////////////////////////////////////
CRYPTOCORE_INTERNAL int SDRM_getK0(cc_u8* k0, cc_u8* Key, cc_u32 KeyLen, cc_u32 Algorithm, cc_u32 B);

/*
 * @fn		SDRM_HMAC_init
 * @brief	Parameter setting for mac code generation
 *
 * @param	crt							[out]crypto parameter
 * @param	Key							[in]user key
 * @param	KeyLen						[in]byte-length of Key
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_NULL_POINTER			if Parameter is NULL
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 */
CRYPTOCORE_INTERNAL int SDRM_HMAC_init(CryptoCoreContainer *crt, cc_u8 *Key, cc_u32 KeyLen)
{
	SDRM_HMACContext *ctx;
	cc_u8			 *ipad;
	cc_u32			 i;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->hmacctx == NULL) || (Key == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	ctx = crt->ctx->hmacctx;
	ctx->algorithm = crt->alg;

	switch(ctx->algorithm)
	{
		case ID_HMD5 :
			ctx->B = SDRM_MD5_DATA_SIZE;
			break;

		case ID_HSHA1 :
			ctx->B = SDRM_SHA1_DATA_SIZE;
			break;

		case ID_HSHA224 :
			ctx->B = SDRM_SHA224_DATA_SIZE;
			break;

		case ID_HSHA256 :
			ctx->B = SDRM_SHA256_DATA_SIZE;
			break;

#ifndef _OP64_NOTSUPPORTED
		case ID_HSHA384 :
			ctx->B = SDRM_SHA384_DATA_SIZE;
			break;

		case ID_HSHA512 :
			ctx->B = SDRM_SHA512_DATA_SIZE;
			break;
#endif //_OP64_NOTSUPPORTED

		default :
			return CRYPTO_INVALID_ARGUMENT;
	}

	ipad = (cc_u8*)malloc(ctx->B);
	if (ipad == NULL)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	ctx->k0 = (cc_u8*)malloc(ctx->B);
	if (ctx->k0 == NULL)
	{
		free(ipad);
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	//make k0
	SDRM_getK0(ctx->k0, Key, KeyLen, ctx->algorithm, ctx->B);

	//ipad = k0 xor ipad
	for (i = 0; i < ctx->B; i++)
	{
		ipad[i] = ctx->k0[i] ^ 0x36;
	}

	if (i != ctx->B)
	{
		for (; i < ctx->B; i++)
		{
			ipad[i] = ctx->k0[i] ^ 0x36;
		}
	}

	ctx->md5_ctx = NULL;
	ctx->sha1_ctx = NULL;
	ctx->sha224_ctx = NULL;
	ctx->sha256_ctx = NULL;
#ifndef _OP64_NOTSUPPORTED
	ctx->sha384_ctx = NULL;
	ctx->sha512_ctx = NULL;
#endif //_OP64_NOTSUPPORTED

	switch(ctx->algorithm)
	{
		case ID_HMD5 :
			ctx->md5_ctx = (SDRM_MD5Context*)malloc(sizeof(SDRM_MD5Context));

			if (ctx->md5_ctx == NULL)
			{
				if (ipad != NULL)
				{
					free(ipad);
				}
				return CRYPTO_MEMORY_ALLOC_FAIL;
			}

			SDRM_MD5_Init(ctx->md5_ctx);
			SDRM_MD5_Update(ctx->md5_ctx, ipad, ctx->B);
			break;

		case ID_HSHA1 :
			ctx->sha1_ctx = (SDRM_SHA1Context*)malloc(sizeof(SDRM_SHA1Context));

			if (ctx->sha1_ctx == NULL)
			{
				if (ipad != NULL)
				{
					free(ipad);
				}
				return CRYPTO_MEMORY_ALLOC_FAIL;
			}

			SDRM_SHA1_Init(ctx->sha1_ctx);
			SDRM_SHA1_Update(ctx->sha1_ctx, ipad, ctx->B);
			break;

		case ID_HSHA224 :
			ctx->sha224_ctx = (SDRM_SHA224Context*)malloc(sizeof(SDRM_SHA224Context));

			if (ctx->sha224_ctx == NULL)
			{
				if (ipad != NULL)
				{
					free(ipad);
				}
				return CRYPTO_MEMORY_ALLOC_FAIL;
			}

			SDRM_SHA224_Init(ctx->sha224_ctx);
			SDRM_SHA224_Update(ctx->sha224_ctx, ipad, ctx->B);
			break;

		case ID_HSHA256 :
			ctx->sha256_ctx = (SDRM_SHA256Context*)malloc(sizeof(SDRM_SHA256Context));

			if (ctx->sha256_ctx == NULL)
			{
				if (ipad != NULL)
				{
					free(ipad);
				}
				return CRYPTO_MEMORY_ALLOC_FAIL;
			}

			SDRM_SHA256_Init(ctx->sha256_ctx);
			SDRM_SHA256_Update(ctx->sha256_ctx, ipad, ctx->B);
			break;

#ifndef _OP64_NOTSUPPORTED
		case ID_HSHA384 :
			ctx->sha384_ctx = (SDRM_SHA384Context*)malloc(sizeof(SDRM_SHA384Context));

			if (ctx->sha384_ctx == NULL)
			{
				if (ipad != NULL)
				{
					free(ipad);
				}
				return CRYPTO_MEMORY_ALLOC_FAIL;
			}

			SDRM_SHA384_Init(ctx->sha384_ctx);
			SDRM_SHA384_Update(ctx->sha384_ctx, ipad, ctx->B);
			break;

		case ID_HSHA512 :
			ctx->sha512_ctx = (SDRM_SHA512Context*)malloc(sizeof(SDRM_SHA512Context));

			if (ctx->sha512_ctx == NULL)
			{
				if (ipad != NULL)
				{
					free(ipad);
				}
				return CRYPTO_MEMORY_ALLOC_FAIL;
			}

			SDRM_SHA512_Init(ctx->sha512_ctx);
			SDRM_SHA512_Update(ctx->sha512_ctx, ipad, ctx->B);
			break;
#endif //_OP64_NOTSUPPORTED

		default :
			free(ipad);
			return CRYPTO_INVALID_ARGUMENT;
	}

	free(ipad);
	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_HMAC_update
 * @brief	process data blocks
 *
 * @param	crt							[out]crypto parameter
 * @param	msg							[in]data block
 * @param	msgLen						[in]byte-length of Text
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_NULL_POINTER			if Parameter is NULL
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 */
CRYPTOCORE_INTERNAL int SDRM_HMAC_update(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msgLen)
{
	if (msgLen == 0)
	{
		return CRYPTO_SUCCESS;
	}

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->hmacctx == NULL) || (msg == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	switch(crt->ctx->hmacctx->algorithm)
	{
		case ID_HMD5 :
			SDRM_MD5_Update(crt->ctx->hmacctx->md5_ctx, msg, msgLen);
			break;
		case ID_HSHA1 :
			SDRM_SHA1_Update(crt->ctx->hmacctx->sha1_ctx, msg, msgLen);
			break;
		case ID_HSHA224 :
			SDRM_SHA224_Update(crt->ctx->hmacctx->sha224_ctx, msg, msgLen);
			break;
		case ID_HSHA256 :
			SDRM_SHA256_Update(crt->ctx->hmacctx->sha256_ctx, msg, msgLen);
			break;

#ifndef _OP64_NOTSUPPORTED
		case ID_HSHA384 :
			SDRM_SHA384_Update(crt->ctx->hmacctx->sha384_ctx, msg, msgLen);
			break;
		case ID_HSHA512 :
			SDRM_SHA512_Update(crt->ctx->hmacctx->sha512_ctx, msg, msgLen);
			break;
#endif //OP64_NOTSUPPORTED

		default :
			return CRYPTO_INVALID_ARGUMENT;
	}

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_HMAC_final
 * @brief	process last data block
 *
 * @param	crt							[in]crypto parameter
 * @param	output						[out]generated MAC
 * @param	outputLen					[out]byte-length of output
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_NULL_POINTER			if Parameter is NULL
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 */
CRYPTOCORE_INTERNAL int SDRM_HMAC_final(CryptoCoreContainer *crt, cc_u8 *output, cc_u32 *outputLen)
{
	SDRM_HMACContext	*ctx;
	SDRM_MD5Context		MD5ctx;
	SDRM_SHA1Context	SHA1ctx;
	SDRM_SHA224Context	SHA224ctx;
	SDRM_SHA256Context	SHA256ctx;
#ifndef _OP64_NOTSUPPORTED
	SDRM_SHA384Context	SHA384ctx;
	SDRM_SHA512Context	SHA512ctx;
#endif //_OP64_NOTSUPPORTED
	cc_u8				Step6_Result[64];
	cc_u32				HashLen, i;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->hmacctx == NULL) || (output == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	ctx = crt->ctx->hmacctx;

	//k0 = k0 xor opad
	for (i = 0; i < ctx->B; i++)
	{
		ctx->k0[i] ^= 0x5c;
	}

	if (i != ctx->B)
	{
		for (; i < ctx->B; i++)
		{
			ctx->k0[i] ^= 0x5c;
		}
	}

	//Step6 : get H((k0 xor ipad) | text) & Step 9 : make hash
	switch(ctx->algorithm)
	{
		case ID_HMD5 :
			SDRM_MD5_Final(ctx->md5_ctx, Step6_Result);
			free(ctx->md5_ctx);

			HashLen = SDRM_MD5_BLOCK_SIZ;

			SDRM_MD5_Init(&MD5ctx);
			SDRM_MD5_Update(&MD5ctx, ctx->k0, ctx->B);
			SDRM_MD5_Update(&MD5ctx, Step6_Result, HashLen);
			SDRM_MD5_Final(&MD5ctx, output);

			break;

		case ID_HSHA1 :
			SDRM_SHA1_Final(ctx->sha1_ctx, Step6_Result);
			free(ctx->sha1_ctx);

			HashLen = SDRM_SHA1_BLOCK_SIZ;

			SDRM_SHA1_Init(&SHA1ctx);
			SDRM_SHA1_Update(&SHA1ctx, ctx->k0, ctx->B);
			SDRM_SHA1_Update(&SHA1ctx, Step6_Result, HashLen);
			SDRM_SHA1_Final(&SHA1ctx, output);

			break;

		case ID_HSHA224 :
			SDRM_SHA224_Final(ctx->sha224_ctx, Step6_Result);
			free(ctx->sha224_ctx);

			HashLen = SDRM_SHA224_BLOCK_SIZ;

			SDRM_SHA224_Init(&SHA224ctx);
			SDRM_SHA224_Update(&SHA224ctx, ctx->k0, ctx->B);
			SDRM_SHA224_Update(&SHA224ctx, Step6_Result, HashLen);
			SDRM_SHA224_Final(&SHA224ctx, output);

			break;

		case ID_HSHA256 :
			SDRM_SHA256_Final(ctx->sha256_ctx, Step6_Result);
			free(ctx->sha256_ctx);

			HashLen = SDRM_SHA256_BLOCK_SIZ;

			SDRM_SHA256_Init(&SHA256ctx);
			SDRM_SHA256_Update(&SHA256ctx, ctx->k0, ctx->B);
			SDRM_SHA256_Update(&SHA256ctx, Step6_Result, HashLen);
			SDRM_SHA256_Final(&SHA256ctx, output);

			break;

#ifndef _OP64_NOTSUPPORTED
		case ID_HSHA384 :
			SDRM_SHA384_Final(ctx->sha384_ctx, Step6_Result);
			free(ctx->sha384_ctx);

			HashLen = SDRM_SHA384_BLOCK_SIZ;

			SDRM_SHA384_Init(&SHA384ctx);
			SDRM_SHA384_Update(&SHA384ctx, ctx->k0, ctx->B);
			SDRM_SHA384_Update(&SHA384ctx, Step6_Result, HashLen);
			SDRM_SHA384_Final(&SHA384ctx, output);

			break;

		case ID_HSHA512 :
			SDRM_SHA512_Final(ctx->sha512_ctx, Step6_Result);
			free(ctx->sha512_ctx);

			HashLen = SDRM_SHA512_BLOCK_SIZ;

			SDRM_SHA512_Init(&SHA512ctx);
			SDRM_SHA512_Update(&SHA512ctx, ctx->k0, ctx->B);
			SDRM_SHA512_Update(&SHA512ctx, Step6_Result, HashLen);
			SDRM_SHA512_Final(&SHA512ctx, output);

			break;
#endif

		default :
			if (ctx->k0) free(ctx->k0);
			return CRYPTO_INVALID_ARGUMENT;
	}

	if (outputLen != NULL)
	{
		*outputLen = HashLen;
	}

	if (ctx->k0)
	{
		free(ctx->k0);
	}

	return CRYPTO_SUCCESS;
}


/*
 * @fn		SDRM_HMAC_getMAC
 * @brief	generate h-mac code
 *
 * @param	crt							[in]crypto parameter
 * @param	Key							[in]user key
 * @param	KeyLen						[in]byte-length of Key
 * @param	msg							[in]data block
 * @param	msgLen						[in]byte-length of Text
 * @param	output						[out]generated MAC
 * @param	outputLen					[out]byte-length of output
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 */
CRYPTOCORE_INTERNAL int SDRM_HMAC_getMAC(CryptoCoreContainer *crt, cc_u8 *Key, cc_u32 KeyLen, cc_u8 *msg, cc_u32 msgLen, cc_u8 *output, cc_u32 *outputLen)
{
	int result;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->hmacctx == NULL) || (Key == NULL) || (output == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	result = SDRM_HMAC_init(crt, Key, KeyLen);
	if (result != CRYPTO_SUCCESS)
	{
		return result;
	}

	result = SDRM_HMAC_update(crt, msg, msgLen);
	if (result != CRYPTO_SUCCESS)
	{
		return result;
	}

	return SDRM_HMAC_final(crt, output, outputLen);
}

CRYPTOCORE_INTERNAL int SDRM_getK0(cc_u8* k0, cc_u8* Key, cc_u32 KeyLen, cc_u32 Algorithm, cc_u32 B)
{
	SDRM_MD5Context  MD5ctx;
	SDRM_SHA1Context SHA1ctx;
	SDRM_SHA224Context SHA224ctx;
	SDRM_SHA256Context SHA256ctx;
#ifndef _OP64_NOTSUPPORTED
	SDRM_SHA384Context SHA384ctx;
	SDRM_SHA512Context SHA512ctx;
#endif //_OP64_NOTSUPPORTED

	int L;

	if (KeyLen == B)
	{
		//if the length of K = B : set K0 = K
		memcpy(k0, Key, B);
	}
	else if (KeyLen > B)
	{
		//if the length of K > B : get hask(K) and append (B - L) zeros

		//get hash(K)

		switch(Algorithm)
		{
			case ID_HMD5 :
				SDRM_MD5_Init(&MD5ctx);
				SDRM_MD5_Update(&MD5ctx, Key, KeyLen);
				SDRM_MD5_Final(&MD5ctx, k0);

				L = SDRM_MD5_BLOCK_SIZ;

				break;

			case ID_HSHA1 :
				SDRM_SHA1_Init(&SHA1ctx);
				SDRM_SHA1_Update(&SHA1ctx, Key, KeyLen);
				SDRM_SHA1_Final(&SHA1ctx, k0);
				
				L = SDRM_SHA1_BLOCK_SIZ;

				break;

			case ID_HSHA224 :
				SDRM_SHA224_Init(&SHA224ctx);
				SDRM_SHA224_Update(&SHA224ctx, Key, KeyLen);
				SDRM_SHA224_Final(&SHA224ctx, k0);
				
				L = SDRM_SHA224_BLOCK_SIZ;

				break;

			case ID_HSHA256 :
				SDRM_SHA256_Init(&SHA256ctx);
				SDRM_SHA256_Update(&SHA256ctx, Key, KeyLen);
				SDRM_SHA256_Final(&SHA256ctx, k0);
				
				L = SDRM_SHA256_BLOCK_SIZ;

				break;

#ifndef _OP64_NOTSUPPORTED
			case ID_HSHA384 :
				SDRM_SHA384_Init(&SHA384ctx);
				SDRM_SHA384_Update(&SHA384ctx, Key, KeyLen);
				SDRM_SHA384_Final(&SHA384ctx, k0);
				
				L = SDRM_SHA384_BLOCK_SIZ;

				break;

			case ID_HSHA512 :
				SDRM_SHA512_Init(&SHA512ctx);
				SDRM_SHA512_Update(&SHA512ctx, Key, KeyLen);
				SDRM_SHA512_Final(&SHA512ctx, k0);
				
				L = SDRM_SHA512_BLOCK_SIZ;

				break;
#endif

			default :
				return CRYPTO_INVALID_ARGUMENT;
		}

		//append zeros
		memset(k0 + L, 0x00, B - L);
	}
	else {
		//if the length of K < B : append zerots to the end of K
		memcpy(k0, Key, KeyLen);
		memset(k0 + KeyLen, 0x00, B - KeyLen);
	}

	return CRYPTO_SUCCESS;
}

/***************************** End of File *****************************/
