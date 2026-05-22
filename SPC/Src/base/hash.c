/**
 * \file	hash.c
 * @brief	hash API function
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/11/08
 */

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include "hash.h"
#include "sha1.h"
#include "sha2.h"
#include "md5.h"

////////////////////////////////////////////////////////////////////////////
// functions
////////////////////////////////////////////////////////////////////////////
/*
 * @fn		SDRM_SHA1_init
 * @brief	initialize CryptoCoreContainer context
 *
 * @param	crt					[out]CryptoCoreContainer context
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA1_init(CryptoCoreContainer *crt)
{
	if ((crt == NULL) || (crt->ctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_SHA1_Init(crt->ctx->sha1ctx);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_SHA1_update
 * @brief	process a message block
 *
 * @param	crt					[out]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]cc_u8-length of msg
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA1_update(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen)
{
	if ((crt == NULL) || (crt->ctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_SHA1_Update(crt->ctx->sha1ctx, msg, msglen);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_SHA1_final
 * @brief	get hashed message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA1_final(CryptoCoreContainer *crt, cc_u8 *output)
{
	if ((crt == NULL) || (crt->ctx == NULL) || (output == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_SHA1_Final(crt->ctx->sha1ctx, output);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_SHA1_hash
 * @brief	get hashed message from message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA1_hash(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen, cc_u8 *output)
{
	if ((crt == NULL) || (crt->ctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_SHA1_Init(crt->ctx->sha1ctx);
	SDRM_SHA1_Update(crt->ctx->sha1ctx, msg, msglen);
	SDRM_SHA1_Final(crt->ctx->sha1ctx, output);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_SHA224_init
 * @brief	initialize CryptoCoreContainer context
 *
 * @param	crt					[out]CryptoCoreContainer context
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA224_init(CryptoCoreContainer *crt)
{
	if ((crt == NULL) || (crt->ctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_SHA224_Init(crt->ctx->sha224ctx);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_SHA224_update
 * @brief	process a message block
 *
 * @param	crt					[out]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA224_update(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen)
{
	if ((crt == NULL) || (crt->ctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_SHA224_Update(crt->ctx->sha224ctx, msg, msglen);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_SHA224_final
 * @brief	get hashed message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA224_final(CryptoCoreContainer *crt, cc_u8 *output)
{
	if ((crt == NULL) || (crt->ctx == NULL) || (output == NULL)) {
		return CRYPTO_NULL_POINTER;
	}

	SDRM_SHA224_Final(crt->ctx->sha224ctx, output);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_SHA224_hash
 * @brief	get hashed message from message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA224_hash(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen, cc_u8 *output)
{
	if ((crt == NULL) || (crt->ctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_SHA224_Init(crt->ctx->sha224ctx);
	SDRM_SHA224_Update(crt->ctx->sha224ctx, msg, msglen);
	SDRM_SHA224_Final(crt->ctx->sha224ctx, output);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_SHA256_init
 * @brief	initialize CryptoCoreContainer context
 *
 * @param	crt					[out]CryptoCoreContainer context
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA256_init(CryptoCoreContainer *crt)
{
	if ((crt == NULL) || (crt->ctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_SHA256_Init(crt->ctx->sha256ctx);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_SHA256_update
 * @brief	process a message block
 *
 * @param	crt					[out]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA256_update(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen)
{
	if ((crt == NULL) || (crt->ctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_SHA256_Update(crt->ctx->sha256ctx, msg, msglen);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_SHA256_final
 * @brief	get hashed message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA256_final(CryptoCoreContainer *crt, cc_u8 *output)
{
	if ((crt == NULL) || (crt->ctx == NULL) || (output == NULL)) {
		return CRYPTO_NULL_POINTER;
	}

	SDRM_SHA256_Final(crt->ctx->sha256ctx, output);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_SHA256_hash
 * @brief	get hashed message from message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA256_hash(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen, cc_u8 *output)
{
	if ((crt == NULL) || (crt->ctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_SHA256_Init(crt->ctx->sha256ctx);
	SDRM_SHA256_Update(crt->ctx->sha256ctx, msg, msglen);
	SDRM_SHA256_Final(crt->ctx->sha256ctx, output);

	return CRYPTO_SUCCESS;
}

#ifndef _OP64_NOTSUPPORTED

/*
 * @fn		SDRM_SHA384_init
 * @brief	initialize CryptoCoreContainer context
 *
 * @param	crt					[out]CryptoCoreContainer context
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA384_init(CryptoCoreContainer *crt)
{
	if ((crt == NULL) || (crt->ctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_SHA384_Init(crt->ctx->sha384ctx);

	return CRYPTO_SUCCESS;
}

/*		
 * @fn		SDRM_SHA384_update
 * @brief	process a message block
 *
 * @param	crt					[out]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA384_update(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen)
{
	if ((crt == NULL) || (crt->ctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_SHA384_Update(crt->ctx->sha384ctx, msg, msglen);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_SHA384_final
 * @brief	get hashed message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA384_final(CryptoCoreContainer *crt, cc_u8 *output)
{
	if ((crt == NULL) || (crt->ctx == NULL) || (output == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_SHA384_Final(crt->ctx->sha384ctx, output);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_SHA384_hash
 * @brief	get hashed message from message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA384_hash(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen, cc_u8 *output)
{
	if ((crt == NULL) || (crt->ctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_SHA384_Init(crt->ctx->sha384ctx);
	SDRM_SHA384_Update(crt->ctx->sha384ctx, msg, msglen);
	SDRM_SHA384_Final(crt->ctx->sha384ctx, output);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_SHA512_init
 * @brief	initialize CryptoCoreContainer context
 *
 * @param	crt					[out]CryptoCoreContainer context
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA512_init(CryptoCoreContainer *crt)
{
	if ((crt == NULL) || (crt->ctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_SHA512_Init(crt->ctx->sha512ctx);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_SHA512_update
 * @brief	process a message block
 *
 * @param	crt					[out]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA512_update(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen)
{
	if ((crt == NULL) || (crt->ctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_SHA512_Update(crt->ctx->sha512ctx, msg, msglen);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_SHA512_final
 * @brief	get hashed message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA512_final(CryptoCoreContainer *crt, cc_u8 *output)
{
	if ((crt == NULL) || (crt->ctx == NULL) || (output == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_SHA512_Final(crt->ctx->sha512ctx, output);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_SHA512_hash
 * @brief	get hashed message from message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA512_hash(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen, cc_u8 *output)
{
	if ((crt == NULL) || (crt->ctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_SHA512_Init(crt->ctx->sha512ctx);
	SDRM_SHA512_Update(crt->ctx->sha512ctx, msg, msglen);
	SDRM_SHA512_Final(crt->ctx->sha512ctx, output);

	return CRYPTO_SUCCESS;
}

#endif //_OP64_NOTSUPPORTED

/*
 * @fn		SDRM_MD5_init
 * @brief	initialize CryptoCoreContainer context
 *
 * @param	crt					[out]CryptoCoreContainer context
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_MD5_init(CryptoCoreContainer *crt)
{
	if ((crt == NULL) || (crt->ctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_MD5_Init(crt->ctx->md5ctx);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_MD5_update
 * @brief	process a message block
 *
 * @param	crt					[out]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_MD5_update(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen)
{
	if ((crt == NULL) || (crt->ctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_MD5_Update(crt->ctx->md5ctx, msg, msglen);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_MD5_final
 * @brief	get hashed message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_MD5_final(CryptoCoreContainer *crt, cc_u8 *output)
{
	if ((crt == NULL) || (crt->ctx == NULL) || (output == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_MD5_Final(crt->ctx->md5ctx, output);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_MD5_hash
 * @brief	get hashed message from message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_MD5_hash(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen, cc_u8 *output)
{
	if ((crt == NULL) || (crt->ctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_MD5_Init(crt->ctx->md5ctx);
	SDRM_MD5_Update(crt->ctx->md5ctx, msg, msglen);
	SDRM_MD5_Final(crt->ctx->md5ctx, output);

	return CRYPTO_SUCCESS;
}

/***************************** End of File *****************************/
