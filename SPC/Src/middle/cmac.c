/**
 * \file	cmac.c
 * @brief	funciton for c-mac code generation by AES-128
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/11/20
 */


////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include "cmac.h"


////////////////////////////////////////////////////////////////////////////
// Constants
////////////////////////////////////////////////////////////////////////////
/*!	@brief	max block columns	*/
#define CMAC_MAXBC				(256/32)

/*!	@brief	max key columns		*/
#define CMAC_MAXKC				(256/32)

/*!	@brief	max rounds			*/
#define CMAC_MAXROUNDS			14

/*!	@brief	constant - defined in OMAC1a(One-Key CBC MAC1, submitted by Iwata and Kurosawa)	*/
static cc_u8 R_b[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87};


/*
 * @fn		int SDRM_CMAC_init(CryptoCoreContainer *crt, cc_u8 *Key, cc_u32 KeyLen)
 *
 * @brief	Parameter setting for mac code generation
 * @param	crt							[out]crypto parameter
 * @param	Key							[in]user key
 * @param	KeyLen						[in]byte-length of Key
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_NULL_POINTER			if Parameter is NULL
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 */
CRYPTOCORE_INTERNAL int SDRM_CMAC_init(CryptoCoreContainer *crt, cc_u8 *Key, cc_u32 KeyLen)
{
	cc_u8	*K1, *K2, temp[16] = {0};
	cc_u8	ZERO[16] = {0};
	int		i;
	cc_u32	*RoundKey;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->cmacctx == NULL) || (Key == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	if (KeyLen != 16)
	{
		return CRYPTO_INVALID_ARGUMENT;
	}

	memset(crt->ctx->cmacctx->IV, 0, SDRM_AES_BLOCK_SIZ);

	crt->ctx->cmacctx->BlockLen = 0;

	RoundKey = (cc_u32*)(void*)(crt->ctx->cmacctx->RoundKey);
	K1 = crt->ctx->cmacctx->K1;
	K2 = crt->ctx->cmacctx->K2;

	SDRM_rijndaelKeySetupEnc(RoundKey, Key, 128);

	SDRM_rijndaelEncrypt(RoundKey, 10, ZERO, temp);

	if((temp[0] >> 7) == 0x00)							// L << 1
	{
		for (i = 0; i < 15; i++)
		{
			K1[i] = (temp[i] << 1) | (temp[i+1] >> 7); 
		}
		K1[15] = temp[i] << 1; 
	}
	else if ((temp[0] >> 7) == 0x01)
	{
		for (i = 0; i < 15; i++)
		{
			K1[i] = (temp[i] << 1) | (temp[i+1] >> 7); 
		}
		K1[15] = temp[i] << 1; 
		BlockXor(K1, K1, R_b);
	}

	if((K1[0] >> 7) == 0x00)							// K1 << 1
	{
		for (i = 0; i < 15; i++)
		{
			K2[i] = (K1[i] << 1) | (K1[i+1] >> 7); 
		}
		K2[15] = K1[i] << 1; 
	}
	else if ((K1[0] >> 7) == 0x01)
	{
		for (i = 0; i < 15; i++)
		{
			K2[i] = (K1[i] << 1) | (K1[i+1] >> 7); 
		}
		K2[15] = K1[i] << 1; 
		BlockXor(K2, K2, R_b);
	}

//	LOG4DRM_BUFFER(&CryptoLogCTX), LOG_DEBUG, "K1", K1, 16); 
//	LOG4DRM_BUFFER(&CryptoLogCTX), LOG_DEBUG, "K2", K2, 16); 

	return CRYPTO_SUCCESS;
}


/*
 * @fn		int SDRM_CMAC_update(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msgLen)
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
CRYPTOCORE_INTERNAL int SDRM_CMAC_update(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msgLen)
{
	int		Loop;
	cc_u8	*ptr;

	if (msgLen == 0)
	{
		return CRYPTO_SUCCESS;
	}

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->cmacctx == NULL) || (msg == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	if (msgLen + crt->ctx->cmacctx->BlockLen <= SDRM_AES_BLOCK_SIZ)
	{
		memcpy(crt->ctx->cmacctx->Block + crt->ctx->cmacctx->BlockLen, msg, msgLen);
		crt->ctx->cmacctx->BlockLen += msgLen;
		return CRYPTO_SUCCESS;
	}

	memcpy(crt->ctx->cmacctx->Block + crt->ctx->cmacctx->BlockLen, msg, SDRM_AES_BLOCK_SIZ - crt->ctx->cmacctx->BlockLen);
	SDRM_CBC_Enc(ID_AES128, crt->ctx->cmacctx->IV, crt->ctx->cmacctx->Block, crt->ctx->cmacctx->RoundKey, crt->ctx->cmacctx->IV);

	Loop = (msgLen + crt->ctx->cmacctx->BlockLen - 1) / SDRM_AES_BLOCK_SIZ - 1;
	ptr = msg + SDRM_AES_BLOCK_SIZ - crt->ctx->cmacctx->BlockLen;
	crt->ctx->cmacctx->BlockLen = (cc_u32)(msg + msgLen - ptr) - Loop * SDRM_AES_BLOCK_SIZ;

	while (Loop > 0)
	{
		SDRM_CBC_Enc(ID_AES128, crt->ctx->cmacctx->IV, ptr, crt->ctx->cmacctx->RoundKey, crt->ctx->cmacctx->IV);
		Loop--;
		ptr += SDRM_AES_BLOCK_SIZ;
	}

//	LOG4DRM_BUFFER(&CryptoLogCTX), LOG_DEBUG, "Block", crt->ctx->cmacctx->IV, 16); 

	memcpy(crt->ctx->cmacctx->Block, ptr, crt->ctx->cmacctx->BlockLen);

	return CRYPTO_SUCCESS;
}


/*
 * @fn		int SDRM_CMAC_final(CryptoCoreContainer *crt, cc_u8 *output, cc_u32 *outputLen)
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
CRYPTOCORE_INTERNAL int SDRM_CMAC_final(CryptoCoreContainer *crt, cc_u8 *output, cc_u32 *outputLen)
{
	cc_u8 *K1, *K2;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->cmacctx == NULL) || (output == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	K1 = crt->ctx->cmacctx->K1;
	K2 = crt->ctx->cmacctx->K2;

	if (crt->ctx->cmacctx->BlockLen == SDRM_AES_BLOCK_SIZ)
	{
		BlockXor(crt->ctx->cmacctx->Block, crt->ctx->cmacctx->Block, K1);
	}
	else
	{
		crt->ctx->cmacctx->IV[crt->ctx->cmacctx->BlockLen] ^= 0x80;
		BlockXor(crt->ctx->cmacctx->IV, crt->ctx->cmacctx->IV, K2);							// input = input XOR K2
		memset(crt->ctx->cmacctx->Block + crt->ctx->cmacctx->BlockLen, 0, SDRM_AES_BLOCK_SIZ - crt->ctx->cmacctx->BlockLen);
	}

	SDRM_CBC_Enc(ID_AES128, output, crt->ctx->cmacctx->Block, crt->ctx->cmacctx->RoundKey, crt->ctx->cmacctx->IV);

	if (outputLen != NULL)
	{
		*outputLen = 16;
	}

	return CRYPTO_SUCCESS;
}


/*
 * @fn		int SDRM_CMAC_getMAC(CryptoCoreContainer *crt, cc_u8 *Key, cc_u32 KeyLen, cc_u8 *msg, cc_u32 msgLen, cc_u8 *output, cc_u32 *outputLen)
 * @brief	generate c-mac code
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
CRYPTOCORE_INTERNAL int SDRM_CMAC_getMAC(CryptoCoreContainer *crt, cc_u8 *Key, cc_u32 KeyLen, cc_u8 *msg, cc_u32 msgLen, cc_u8 *output, cc_u32 *outputLen)
{
	int result;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->cmacctx == NULL) || (Key == NULL) || (output == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	result = SDRM_CMAC_init(crt, Key, KeyLen);
	if (result != CRYPTO_SUCCESS)
	{
		return result;
	}

	result = SDRM_CMAC_update(crt, msg, msgLen);
	if (result != CRYPTO_SUCCESS)
	{
			return result;
	}

	return SDRM_CMAC_final(crt, output, outputLen);
}

/***************************** End of File *****************************/	
