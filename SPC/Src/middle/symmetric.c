/**
 * \file	symmetric.c
 * @brief	API for symmetric encryption
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon, Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/11/07
 */

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include "symmetric.h"
#include "moo.h"
#include "rc4.h"
#include "snow2.h"

////////////////////////////////////////////////////////////////////////////
// Functions
////////////////////////////////////////////////////////////////////////////
/*
 * @fn		SDRM_getEncRoundKey
 * @brief	get scheduled key for encryption
 *
 * @param	Algorithm				[in]cipher algorithm
 * @param	UserKey					[in]user key
 * @param	RoundKey				[out]round key
 *
 * @return	CRYPTO_SUCCESS			if success
 * \n		CRYPTO_NULL_POINTER		if given argument is a null pointer
 * \n		CRYPTO_INVALID_ARGUMENT if given argument is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_getEncRoundKey(int Algorithm, cc_u8* UserKey, cc_u8* RoundKey)
{
	if ((UserKey == NULL) || (RoundKey == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	switch (Algorithm)
	{
		case ID_AES128 : 
			SDRM_rijndaelKeySetupEnc((cc_u32*)(void*)RoundKey, UserKey, 128);
			return CRYPTO_SUCCESS;
		case ID_AES192 : 
			SDRM_rijndaelKeySetupEnc((cc_u32*)(void*)RoundKey, UserKey, 192);
			return CRYPTO_SUCCESS;
		case ID_AES256 : 
			SDRM_rijndaelKeySetupEnc((cc_u32*)(void*)RoundKey, UserKey, 256);
			return CRYPTO_SUCCESS;
		case ID_DES : 
			SDRM_DES_KeySched(RoundKey, UserKey, 0, 1);
			return CRYPTO_SUCCESS;
		case ID_TDES_EDE2 : 
			SDRM_TDES_KeySched(RoundKey, UserKey, 16, 1);
			return CRYPTO_SUCCESS;
		case ID_TDES_EDE3 : 
			SDRM_TDES_KeySched(RoundKey, UserKey, 24, 1);
			return CRYPTO_SUCCESS;
		default :
			break;
	}

	return CRYPTO_INVALID_ARGUMENT;
}

/*
 * @fn		SDRM_getDecRoundKey
 * @brief	get scheduled key for decryption
 *
 * @param	Algorithm				[in]cipher algorithm
 * @param	UserKey					[in]user key
 * @param	RoundKey				[out]round key
 *
 * @return	CRYPTO_SUCCESS			if success
 * \n		CRYPTO_NULL_POINTER		if given argument is a null pointer
 * \n		CRYPTO_INVALID_ARGUMENT if given argument is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_getDecRoundKey(int Algorithm, cc_u8* UserKey, cc_u8* RoundKey)
{
	if ((UserKey == NULL) || (RoundKey == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	switch (Algorithm)
	{
		case ID_AES128 : 
			SDRM_rijndaelKeySetupDec((cc_u32*)(void*)RoundKey, UserKey, 128);
			return CRYPTO_SUCCESS;
		case ID_AES192 : 
			SDRM_rijndaelKeySetupDec((cc_u32*)(void*)RoundKey, UserKey, 192);
			return CRYPTO_SUCCESS;
		case ID_AES256 : 
			SDRM_rijndaelKeySetupDec((cc_u32*)(void*)RoundKey, UserKey, 256);
			return CRYPTO_SUCCESS;
		case ID_DES : 
			SDRM_DES_KeySched(RoundKey, UserKey, 15, (cc_u32)-1);
			return CRYPTO_SUCCESS;
		case ID_TDES_EDE2 : 
			SDRM_TDES_KeySched(RoundKey, UserKey, 16, (cc_u32)-1);
			return CRYPTO_SUCCESS;
		case ID_TDES_EDE3 : 
			SDRM_TDES_KeySched(RoundKey, UserKey, 24, (cc_u32)-1);
			return CRYPTO_SUCCESS;
		default :
			break;
	}

	return CRYPTO_INVALID_ARGUMENT;
}

/*
 * @fn		SDRM_AES_init
 * @brief	intialize crypt context for aes
 *
 * @param	crt						[out]crypto env structure
 * @param	mode					[in]encryption|decryption and mode of operation
 * @param	PADDING					[in]padding method
 * @param	key						[in]user key
 * @param	keysize					[in]byte-length of key
 * @param	IV						[in]initial vector
 *
 * @return	CRYPTO_SUCCESS			if success
 * \n		CRYPTO_NULL_POINTER		if given argument is a null pointer
 * \n		CRYPTO_INVALID_ARGUMENT if given argument is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_AES_init(CryptoCoreContainer *crt, cc_u32 mode, cc_u32 PADDING, cc_u8 *key, cc_u32 keysize, cc_u8 *IV)
{
	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->aesctx == NULL) || (key == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	if (!(((mode >= 1111) && (mode <= 1115)) || ((mode >= 1121) && (mode <= 1125))))
	{
		return CRYPTO_INVALID_ARGUMENT;
	}

	if (!((crt->alg == ID_AES128) && (keysize == 16)) &&
		!((crt->alg == ID_AES192) && (keysize == 24)) &&
		!((crt->alg == ID_AES256) && (keysize == 32)))
	{
		return CRYPTO_INVALID_ARGUMENT;
	}

	if ((crt->alg != ID_AES128) && (crt->alg != ID_AES192) && (crt->alg != ID_AES256))
	{
		return CRYPTO_INVALID_ARGUMENT;
	}

	if ((PADDING != 0) && (PADDING != ID_PKCS5) && (PADDING != ID_SSL_PADDING) && (PADDING != ID_ZERO_PADDING) && (PADDING != ID_NO_PADDING))
	{
		return CRYPTO_INVALID_ARGUMENT;
	}

	crt->ctx->aesctx->moo = mode;

	crt->ctx->aesctx->padding = PADDING;

	if (mode != ID_DEC_ECB && mode != ID_DEC_CBC)
	{
		SDRM_getEncRoundKey(crt->alg, key, crt->ctx->aesctx->RoundKey);
	}
	else
	{
		SDRM_getDecRoundKey(crt->alg, key, crt->ctx->aesctx->RoundKey);
	}
	
	if (IV)
	{
		memcpy(crt->ctx->aesctx->IV, IV, SDRM_AES_BLOCK_SIZ);
	}
	else
	{
		memset(crt->ctx->aesctx->IV, 0x00, SDRM_AES_BLOCK_SIZ);
	}

	crt->ctx->aesctx->BlockLen = 0;

	GET_UINT32(crt->ctx->aesctx->CTR_Count, crt->ctx->aesctx->IV + 12, 0);

	return CRYPTO_SUCCESS;

}

/*
 * @fn		SDRM_AES_process
 * @brief	process message block
 *
 * @param	crt						[in]crypto env structure
 * @param	Text					[in]message block
 * @param	TextLen					[in]byte-length of Text
 * @param	output					[out]proecessed message
 * @param	outputLen				[out]byte-length of output
 *
 * @return	CRYPTO_SUCCESS			if success
 * \n		CRYPTO_NULL_POINTER		if given argument is a null pointer
 * \n		CRYPTO_INVALID_ARGUMENT if given argument is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_AES_process(CryptoCoreContainer *crt, cc_u8 *Text, cc_u32 TextLen, cc_u8 *output, cc_u32 *outputLen)
{
	int i, Temp;
	int retVal, BlockLen;
	cc_u8 *Block;
	cc_u32 tempLen = 0;

	if (outputLen != NULL)
	{
		*outputLen = 0;
	}

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->aesctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	Block = crt->ctx->aesctx->Block;
	BlockLen = crt->ctx->aesctx->BlockLen;

	if ((TextLen + BlockLen) < SDRM_AES_BLOCK_SIZ)
	{
		memcpy(Block + BlockLen, Text, TextLen);
		crt->ctx->aesctx->BlockLen += TextLen;
		return CRYPTO_SUCCESS;
	}

	if (BlockLen)
	{
		memcpy(Block + BlockLen, Text, SDRM_AES_BLOCK_SIZ - BlockLen);

		switch(crt->ctx->aesctx->moo)
		{
			case ID_ENC_ECB :
				retVal = SDRM_ECB_Enc(crt->alg, output, Block, crt->ctx->aesctx->RoundKey);
				tempLen += SDRM_AES_BLOCK_SIZ;
				break;
			case ID_ENC_CBC :
				retVal = SDRM_CBC_Enc(crt->alg, output, Block, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV);
				tempLen += SDRM_AES_BLOCK_SIZ;
				break;
			case ID_ENC_CFB :
				retVal = SDRM_CFB_Enc(crt->alg, output, Block, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV);
				tempLen += SDRM_AES_BLOCK_SIZ;
				break;
			case ID_ENC_OFB :
				retVal = SDRM_OFB_Enc(crt->alg, output, Block, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV);
				tempLen += SDRM_AES_BLOCK_SIZ;
				break;
			case ID_ENC_CTR :
				retVal = SDRM_CTR_Enc(crt->alg, output, Block, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV, crt->ctx->aesctx->CTR_Count++);
				tempLen += SDRM_AES_BLOCK_SIZ;
				break;
			case ID_DEC_ECB : 
				retVal = SDRM_ECB_Dec(crt->alg, output, Block, crt->ctx->aesctx->RoundKey);
				tempLen += SDRM_AES_BLOCK_SIZ;
				break;
			case ID_DEC_CBC :
				retVal = SDRM_CBC_Dec(crt->alg, output, Block, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV);
				tempLen += SDRM_AES_BLOCK_SIZ;
				break;
			case ID_DEC_CFB :
				retVal = SDRM_CFB_Dec(crt->alg, output, Block, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV);
				tempLen += SDRM_AES_BLOCK_SIZ;
				break;
			case ID_DEC_OFB :
				retVal = SDRM_OFB_Dec(crt->alg, output, Block, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV);
				tempLen += SDRM_AES_BLOCK_SIZ;
				break;
			case ID_DEC_CTR : 
				retVal = SDRM_CTR_Dec(crt->alg, output, Block, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV, crt->ctx->aesctx->CTR_Count++);
				tempLen += SDRM_AES_BLOCK_SIZ;
				break;
			default :
				return CRYPTO_INVALID_ARGUMENT;
		}

		if (retVal != CRYPTO_SUCCESS)
		{
			return retVal;
		}
	}

	Temp = TextLen - SDRM_AES_BLOCK_SIZ + 1;
	for (i = (SDRM_AES_BLOCK_SIZ - BlockLen) & 0x0f; i < Temp; i += SDRM_AES_BLOCK_SIZ)
	{
		switch(crt->ctx->aesctx->moo)
		{
			case ID_ENC_ECB : 
				retVal = SDRM_ECB_Enc(crt->alg, output + tempLen, Text + i, crt->ctx->aesctx->RoundKey);
				tempLen += SDRM_AES_BLOCK_SIZ;
				break;
			case ID_ENC_CBC :
				retVal = SDRM_CBC_Enc(crt->alg, output + tempLen, Text + i, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV);
				tempLen += SDRM_AES_BLOCK_SIZ;
				break;
			case ID_ENC_CFB :
				retVal = SDRM_CFB_Enc(crt->alg, output + tempLen, Text + i, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV);
				tempLen += SDRM_AES_BLOCK_SIZ;
				break;
			case ID_ENC_OFB :
				retVal = SDRM_OFB_Enc(crt->alg, output + tempLen, Text + i, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV);
				tempLen += SDRM_AES_BLOCK_SIZ;
				break;
			case ID_ENC_CTR : 
				retVal = SDRM_CTR_Enc(crt->alg, output + tempLen, Text + i, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV, crt->ctx->aesctx->CTR_Count++);
				tempLen += SDRM_AES_BLOCK_SIZ;
				break;
			case ID_DEC_ECB : 
				retVal = SDRM_ECB_Dec(crt->alg, output + tempLen, Text + i, crt->ctx->aesctx->RoundKey);
				tempLen += SDRM_AES_BLOCK_SIZ;
				break;
			case ID_DEC_CBC :
				retVal = SDRM_CBC_Dec(crt->alg, output + tempLen, Text + i, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV);
				tempLen += SDRM_AES_BLOCK_SIZ;
				break;
			case ID_DEC_CFB :
				retVal = SDRM_CFB_Dec(crt->alg, output + tempLen, Text + i, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV);
				tempLen += SDRM_AES_BLOCK_SIZ;
				break;
			case ID_DEC_OFB :
				retVal = SDRM_OFB_Dec(crt->alg, output + tempLen, Text + i, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV);
				tempLen += SDRM_AES_BLOCK_SIZ;
				break;
			case ID_DEC_CTR : 
				retVal = SDRM_CTR_Dec(crt->alg, output + tempLen, Text + i, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV, crt->ctx->aesctx->CTR_Count++);
				tempLen += SDRM_AES_BLOCK_SIZ;
				break;
			default :
				return CRYPTO_INVALID_ARGUMENT;
		}

		if (retVal != CRYPTO_SUCCESS)
		{
			return retVal;
		}
	}

	crt->ctx->aesctx->BlockLen = (SDRM_AES_BLOCK_SIZ + TextLen - i) & 0x0f;
	memcpy(Block, Text + TextLen - crt->ctx->aesctx->BlockLen, crt->ctx->aesctx->BlockLen);

	if (outputLen != 0)
	{
		*outputLen = tempLen;
	}

	return CRYPTO_SUCCESS;
}


/*
 * @fn		SDRM_AES_final
 * @brief	process final block and padding
 *
 * @param	crt						[in]crypto env structure
 * @param	input					[in]message block
 * @param	inputLen				[in]byte-length of Text
 * @param	output					[out]processed message
 * @param	outputLen				[out]byte-length of output
 *
 * @return	CRYPTO_SUCCESS			if success
 * \n		CRYPTO_NULL_POINTER		if given argument is a null pointer
 * \n		CRYPTO_INVALID_ARGUMENT if given argument is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_AES_final(CryptoCoreContainer *crt, cc_u8 *input, cc_u32 inputLen, cc_u8 *output, cc_u32 *outputLen)
{
	int retVal = CRYPTO_SUCCESS;
	cc_u8 *Block, PADDING[16];
	cc_u32 BlockLen;
	cc_u8 t;

	if (outputLen != NULL)
	{
		*outputLen = 0;
	}

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->aesctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	Block = crt->ctx->aesctx->Block;
	BlockLen = crt->ctx->aesctx->BlockLen;


	if (crt->ctx->aesctx->moo >= ID_DEC_ECB)
	{
		goto DECRYPTION;
	}

//ENCRYPTION:
	if (inputLen != 0)
	{
		unsigned int temp;
		retVal = SDRM_AES_process(crt, input, inputLen, output, &temp);

		if (retVal != CRYPTO_SUCCESS)
		{
			return retVal;
		}

		retVal = SDRM_AES_final(crt, NULL, 0, output + temp, outputLen);
		
		if (outputLen)
		{
			*outputLen += temp;
		}

		return retVal;
	}

	if (outputLen != NULL)
	{
		*outputLen = SDRM_AES_BLOCK_SIZ;
	}

	//padding
	switch(crt->ctx->aesctx->padding)
	{
		case 0 :
		case ID_PKCS5 :
			memset(Block + BlockLen, SDRM_AES_BLOCK_SIZ - BlockLen, SDRM_AES_BLOCK_SIZ - BlockLen);
			break;
		case ID_SSL_PADDING :
			memset(Block + BlockLen, SDRM_AES_BLOCK_SIZ - BlockLen - 1, SDRM_AES_BLOCK_SIZ - BlockLen);
			break;
		case ID_ZERO_PADDING :
			memset(Block + BlockLen, 0x00, SDRM_AES_BLOCK_SIZ - BlockLen);
			break;
		case ID_NO_PADDING :
			if (BlockLen == 0)
			{
				if (outputLen)
				{
					*outputLen = 0;
				}
				return CRYPTO_SUCCESS;
			}
			break;
		default :
			return CRYPTO_INVALID_ARGUMENT;
	}

	//encryption
	switch(crt->ctx->aesctx->moo)
	{
		case ID_ENC_ECB : 
			retVal = SDRM_ECB_Enc(crt->alg, output, Block, crt->ctx->aesctx->RoundKey);
			break;
		case ID_ENC_CBC :
			retVal = SDRM_CBC_Enc(crt->alg, output, Block, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV);
			break;
		case ID_ENC_CFB :
			retVal = SDRM_CFB_Enc(crt->alg, output, Block, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV);
			break;
		case ID_ENC_OFB :
			retVal = SDRM_OFB_Enc(crt->alg, output, Block, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV);
			break;
		case ID_ENC_CTR : 
			retVal = SDRM_CTR_Enc(crt->alg, Block, Block, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV, crt->ctx->aesctx->CTR_Count++);
			memcpy(output, Block, BlockLen);
			if(outputLen != NULL)
			{
				*outputLen = BlockLen;
			}
			break;
		default :
			retVal = CRYPTO_INVALID_ARGUMENT;
			break;
	}

	return retVal;

DECRYPTION:
	if (outputLen != NULL)
	{
		*outputLen = 0;
	}

	if ((inputLen == 0) && (crt->ctx->aesctx->padding == ID_NO_PADDING) && (crt->ctx->aesctx->moo != ID_DEC_CTR))
	{
		return CRYPTO_SUCCESS;
	}

	if (((BlockLen + inputLen) != SDRM_AES_BLOCK_SIZ) && (crt->ctx->aesctx->moo != ID_DEC_CTR))
	{
		return CRYPTO_INVALID_ARGUMENT;
	}

	if (inputLen != 0)
	{
		memcpy(Block + BlockLen, input, inputLen);
	}

	switch(crt->ctx->aesctx->moo)
	{
		case ID_DEC_ECB : 
			retVal = SDRM_ECB_Dec(crt->alg, Block, Block, crt->ctx->aesctx->RoundKey);
			break;
		case ID_DEC_CBC :
			retVal = SDRM_CBC_Dec(crt->alg, Block, Block, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV);
			break;
		case ID_DEC_CFB :
			retVal = SDRM_CFB_Dec(crt->alg, Block, Block, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV);
			break;
		case ID_DEC_OFB :
			retVal = SDRM_OFB_Dec(crt->alg, Block, Block, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV);
			break;
		case ID_DEC_CTR : 
			retVal = SDRM_CTR_Dec(crt->alg, Block, Block, crt->ctx->aesctx->RoundKey, crt->ctx->aesctx->IV, crt->ctx->aesctx->CTR_Count++);
			break;
		default :
			return CRYPTO_INVALID_ARGUMENT;
	}

	if (retVal != CRYPTO_SUCCESS)
	{
		return retVal;
	}

	//de-padding

	t = Block[SDRM_AES_BLOCK_SIZ - 1];

	switch(crt->ctx->aesctx->padding)
	{
		case 0 :
		case ID_PKCS5 :
			if ((t > SDRM_AES_BLOCK_SIZ) || (t < 1))
			{
				return CRYPTO_INVALID_ARGUMENT;
			}
			memset(PADDING, t, t);
			break;
		case ID_SSL_PADDING :
			++t;
			if ((t > SDRM_AES_BLOCK_SIZ) || (t < 1))
			{
				return CRYPTO_INVALID_ARGUMENT;
			}
			memset(PADDING, t - 1, t);
			break;
		case ID_ZERO_PADDING :
			{
				cc_u32 tmpLen;
				tmpLen = SDRM_AES_BLOCK_SIZ;
				while((tmpLen != 0x00) && (Block[tmpLen - 1] == 0x00))
				{
					tmpLen--;
				}

				memcpy(output, Block, tmpLen);

				if (outputLen != NULL)
				{
					*outputLen = tmpLen;
				}
			}
			return CRYPTO_SUCCESS;
		case ID_NO_PADDING :
			{
				cc_u32 tmpLen;
				tmpLen = SDRM_AES_BLOCK_SIZ;

				if (crt->ctx->aesctx->moo == ID_DEC_CTR)
				{
					tmpLen = BlockLen + inputLen;
				}
				else
				{
					tmpLen = SDRM_AES_BLOCK_SIZ;
				}

				memcpy(output, Block, tmpLen);

				if (outputLen != NULL)
				{
					*outputLen = tmpLen;
				}
			}
			return CRYPTO_SUCCESS;
		default :
			if (outputLen != NULL)
			{
				*outputLen = 0;
			}
			return CRYPTO_INVALID_ARGUMENT;
	}

	if (memcmp(PADDING, Block + SDRM_AES_BLOCK_SIZ - t, t) != 0)
	{
		return CRYPTO_INVALID_ARGUMENT;
	}

	size_t tmp = (size_t)SDRM_AES_BLOCK_SIZ - (size_t)t;
	memcpy(output, Block, tmp);

	if (outputLen != NULL)
	{
		*outputLen = SDRM_AES_BLOCK_SIZ - t;
	}

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_RC4_init
 * @brief	intialize crypt context for RC4
 *
 * @param	crt						[out]crypto env structure
 * @param	mode					[in]encryption|decryption and mode of operation
 * @param	PADDING					[in]padding method, not needed
 * @param	key						[in]user key
 * @param	keysize					[in]byte-length of key
 * @param	IV						[in]initial vector, not needed
 *
 * @return	CRYPTO_SUCCESS			if success
 * \n		CRYPTO_NULL_POINTER		if given argument is a null pointer
 * \n		CRYPTO_INVALID_ARGUMENT if given argument is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_RC4_init(CryptoCoreContainer *crt, cc_u32 mode, cc_u32 PADDING, cc_u8 *key, cc_u32 keysize, cc_u8 *IV)
{
	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->rc4ctx == NULL) || (key == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	if (keysize > 32)
	{
		return CRYPTO_INVALID_ARGUMENT;
	}

	SDRM_RC4_Setup(crt->ctx->rc4ctx, key, keysize);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_RC4_process
 * @brief	process message block
 *
 * @param	crt						[in]crypto env structure
 * @param	in						[in]message block
 * @param	inLen					[in]byte-length of Text
 * @param	out						[out]processed message
 * @param	outLen					[out]byte-length of output
 *
 * @return	CRYPTO_SUCCESS			if success
 * \n		CRYPTO_NULL_POINTER		if given argument is a null pointer
 * \n		CRYPTO_INVALID_ARGUMENT if given argument is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_RC4_process(CryptoCoreContainer *crt, cc_u8 *in, cc_u32 inLen, cc_u8 *out, cc_u32 *outLen)
{
	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->rc4ctx == NULL) || (in == NULL) || (out == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}


	SDRM_RC4_PRNG(crt->ctx->rc4ctx, in, inLen, out);

	if (outLen != NULL)
	{
		*outLen = inLen;
	}
	
	return CRYPTO_SUCCESS;
}


/*
 * @fn		SDRM_SNOW2_init
 * @brief	intialize crypt context for SNOW2
 *
 * @param	crt						[out]crypto env structure
 * @param	mode					[in]encryption|decryption and mode of operation
 * @param	PADDING					[in]padding method, not needed
 * @param	key						[in]user key
 * @param	keysize					[in]byte-length of key
 * @param	IV						[in]initial vector
 *
 * @return	CRYPTO_SUCCESS			if success
 * \n		CRYPTO_NULL_POINTER		if given argument is a null pointer
 * \n		CRYPTO_INVALID_ARGUMENT if given argument is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_SNOW2_init(CryptoCoreContainer *crt, cc_u32 mode, cc_u32 PADDING, cc_u8 *key, cc_u32 keysize, cc_u8 *IV)
{
	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->snow2ctx == NULL) || (key == NULL) || (IV == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	if ((keysize != 16) && (keysize != 32))
	{
		return CRYPTO_INVALID_ARGUMENT;
	}

	SDRM_SNOW2_Setup(crt->ctx->snow2ctx, key, keysize, IV);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_SNOW2_process
 * @brief	process message block
 *
 * @param	crt						[in]crypto env structure
 * @param	in						[in]message block	
 * @param	inLen					[in]byte-length of Text
 * @param	out						[out]processed message
 * @param	outLen					[out]byte-length of output
 *
 * @return	CRYPTO_SUCCESS			if success
 * \n		CRYPTO_NULL_POINTER		if given argument is a null pointer
 * \n		CRYPTO_INVALID_ARGUMENT if given argument is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_SNOW2_process(CryptoCoreContainer *crt, cc_u8 *in, cc_u32 inLen, cc_u8 *out, cc_u32 *outLen)
{
	cc_u32 i, j, BlockLen, rpt, loc;
	cc_u32 keyStream64[16], keyStream;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->snow2ctx == NULL) || (in == NULL) || (out == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	if ((inLen & 0x03) != 0)
	{
		return CRYPTO_INVALID_ARGUMENT;
	}

	BlockLen = inLen / 64;

	if (crt->ctx->snow2ctx->endian == CRYPTO_LITTLE_ENDIAN)
	{				//little endian machine
		for (i = 0; i < BlockLen; i++)
		{
			SDRM_SNOW2_getKeyStream64(crt->ctx->snow2ctx, keyStream64);

			for (j = 0; j < 16; j++)
			{
				loc = i * 64 + j * 4;
				out[loc    ] = (cc_u8)(in[loc    ] ^ ((keyStream64[j] >> 24) & 0xff));
				out[loc + 1] = (cc_u8)(in[loc + 1] ^ ((keyStream64[j] >> 16) & 0xff));
				out[loc + 2] = (cc_u8)(in[loc + 2] ^ ((keyStream64[j] >>  8) & 0xff));
				out[loc + 3] = (cc_u8)(in[loc + 3] ^ ((keyStream64[j]      ) & 0xff));
			}
		}
	} 
	else
	{				//big endian machine
		for (i = 0; i < BlockLen; i++)
		{
			SDRM_SNOW2_getKeyStream64(crt->ctx->snow2ctx, keyStream64);
			
			for (j = 0; j < 16; j++)
			{
				((cc_u32*)(void*)out)[j] = ((cc_u32*)(void*)in)[j] ^ keyStream64[j];
			}
		}
	}

	in += BlockLen * 64;
	out += BlockLen * 64;

	rpt = (inLen - (BlockLen * 64)) / 4;

	if (crt->ctx->snow2ctx->endian == CRYPTO_LITTLE_ENDIAN)
	{				//little endian machine
		for (i = 0; i < rpt; i++)
		{
			SDRM_SNOW2_getKeyStream(crt->ctx->snow2ctx, &keyStream);
			loc = i * 4;
			out[loc    ] = (cc_u8)(in[loc    ] ^ ((keyStream >> 24) & 0xff));
			out[loc + 1] = (cc_u8)(in[loc + 1] ^ ((keyStream >> 16) & 0xff));
			out[loc + 2] = (cc_u8)(in[loc + 2] ^ ((keyStream >>  8) & 0xff));
			out[loc + 3] = (cc_u8)(in[loc + 3] ^ ((keyStream	  ) & 0xff));
		}
	}
	else
	{				//big endian machine
		for (i = 0; i < rpt; i++)
		{
			SDRM_SNOW2_getKeyStream(crt->ctx->snow2ctx, &keyStream);
			((cc_u32*)(void*)out)[i] = ((cc_u32*)(void*)in)[i] ^ keyStream;
		}
	}

	if (outLen != NULL)
	{
		*outLen = inLen;
	}

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_DES_init
 * @brief	intialize crypt context for des
 *
 * @param	crt						[out]crypto env structure
 * @param	mode					[in]encryption|decryption and mode of operation
 * @param	PADDING					[in]padding method
 * @param	key						[in]user key
 * @param	keysize					[in]byte-length of key
 * @param	IV						[in]initial vector
 *
 * @return	CRYPTO_SUCCESS			if success
 * \n		CRYPTO_NULL_POINTER		if given argument is a null pointer
 * \n		CRYPTO_INVALID_ARGUMENT if given argument is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_DES_init(CryptoCoreContainer *crt, cc_u32 mode, cc_u32 PADDING, cc_u8 *key, cc_u32 keysize, cc_u8 *IV)
{
	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->desctx == NULL) || (key == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	if ((keysize != 8) || !(((mode >= 1111) && (mode <= 1115)) || ((mode >= 1121) && (mode <= 1125))))
	{
		return CRYPTO_INVALID_ARGUMENT;
	}

	crt->ctx->desctx->moo = mode;

	if ((PADDING != 0) && (PADDING != ID_PKCS5) && (PADDING != ID_SSL_PADDING) && (PADDING != ID_ZERO_PADDING) && (PADDING != ID_NO_PADDING))
	{
		return CRYPTO_INVALID_ARGUMENT;
	}

	crt->ctx->desctx->padding = PADDING;


	if (mode != ID_DEC_ECB && mode != ID_DEC_CBC)
	{
		SDRM_getEncRoundKey(ID_DES, key, (cc_u8*)(crt->ctx->desctx->RoundKey));
	}
	else
	{
		SDRM_getDecRoundKey(ID_DES, key, (cc_u8*)(crt->ctx->desctx->RoundKey));
	}
	
	crt->ctx->desctx->BlockLen = 0;
	crt->ctx->desctx->CTR_Count = 0;

	memcpy(crt->ctx->desctx->UserKey, key, SDRM_DES_BLOCK_SIZ);

	if (IV)
	{
		memcpy(crt->ctx->desctx->IV, IV, SDRM_DES_BLOCK_SIZ);
	}
	else
	{
		memset(crt->ctx->desctx->IV, 0x00, SDRM_DES_BLOCK_SIZ);
	}

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_DES_process
 * @brief	process message block
 *
 * @param	crt						[in]crypto env structure
 * @param	Text					[in]message block
 * @param	TextLen					[in]byte-length of Text
 * @param	output					[out]proecessed message
 * @param	outputLen				[out]byte-length of output
 *
 * @return	CRYPTO_SUCCESS			if success
 * \n		CRYPTO_NULL_POINTER		if given argument is a null pointer
 * \n		CRYPTO_INVALID_ARGUMENT if given argument is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_DES_process(CryptoCoreContainer *crt, cc_u8 *Text, cc_u32 TextLen, cc_u8 *output, cc_u32 *outputLen)
{
	int		i, Temp;
	int		retVal, BlockLen;
	cc_u8	*Block;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->desctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	Block = crt->ctx->desctx->Block;
	BlockLen = crt->ctx->desctx->BlockLen;

	*outputLen = 0;

	if ((TextLen + BlockLen) < SDRM_DES_BLOCK_SIZ)
	{
		memcpy(Block + BlockLen, Text, TextLen);
		crt->ctx->desctx->BlockLen += TextLen;
		return CRYPTO_SUCCESS;
	}

	if (BlockLen)
	{
		memcpy(Block + BlockLen, Text, SDRM_DES_BLOCK_SIZ - BlockLen);

		switch(crt->ctx->desctx->moo)
		{
			case ID_ENC_ECB :
				retVal = SDRM_ECB_Enc(ID_DES, output, Block, (cc_u8*)crt->ctx->desctx->RoundKey);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_ENC_CBC :
				retVal = SDRM_CBC_Enc(ID_DES, output, Block, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_ENC_CFB :
				retVal = SDRM_CFB_Enc(ID_DES, output, Block, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_ENC_OFB :
				retVal = SDRM_OFB_Enc(ID_DES, output, Block, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_ENC_CTR :
				retVal = SDRM_CTR_Enc(ID_DES, output, Block, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV, crt->ctx->desctx->CTR_Count++);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_DEC_ECB : 
				retVal = SDRM_ECB_Dec(ID_DES, output, Block, (cc_u8*)crt->ctx->desctx->RoundKey);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_DEC_CBC :
				retVal = SDRM_CBC_Dec(ID_DES, output, Block, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_DEC_CFB :
				retVal = SDRM_CFB_Dec(ID_DES, output, Block, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_DEC_OFB :
				retVal = SDRM_OFB_Dec(ID_DES, output, Block, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_DEC_CTR : 
				retVal = SDRM_CTR_Dec(ID_DES, output, Block, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV, crt->ctx->desctx->CTR_Count++);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			default :
				return CRYPTO_INVALID_ARGUMENT;
		}

		if (retVal != CRYPTO_SUCCESS)
		{
			return retVal;
		}
	}

	Temp = TextLen + BlockLen - SDRM_DES_BLOCK_SIZ + 1;
	for (i = (SDRM_DES_BLOCK_SIZ - BlockLen) & 0x07; i < Temp; i += SDRM_DES_BLOCK_SIZ)
	{
		switch(crt->ctx->desctx->moo)
		{
			case ID_ENC_ECB : 
				retVal = SDRM_ECB_Enc(ID_DES, output + *outputLen, Text + i, (cc_u8*)crt->ctx->desctx->RoundKey);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_ENC_CBC :
				retVal = SDRM_CBC_Enc(ID_DES, output + *outputLen, Text + i, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_ENC_CFB :
				retVal = SDRM_CFB_Enc(ID_DES, output + *outputLen, Text + i, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_ENC_OFB :
				retVal = SDRM_OFB_Enc(ID_DES, output + *outputLen, Text + i, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_ENC_CTR : 
				retVal = SDRM_CTR_Enc(ID_DES, output + *outputLen, Text + i, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV, crt->ctx->desctx->CTR_Count++);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_DEC_ECB : 
				retVal = SDRM_ECB_Dec(ID_DES, output + *outputLen, Text + i, (cc_u8*)crt->ctx->desctx->RoundKey);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_DEC_CBC :
				retVal = SDRM_CBC_Dec(ID_DES, output + *outputLen, Text + i, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_DEC_CFB :
				retVal = SDRM_CFB_Dec(ID_DES, output + *outputLen, Text + i, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_DEC_OFB :
				retVal = SDRM_OFB_Dec(ID_DES, output + *outputLen, Text + i, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_DEC_CTR : 
				retVal = SDRM_CTR_Dec(ID_DES, output + *outputLen, Text + i, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV, crt->ctx->desctx->CTR_Count++);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			default :
				return CRYPTO_INVALID_ARGUMENT;
		}

		if (retVal != CRYPTO_SUCCESS)
		{
			return retVal;
		}
	}

	crt->ctx->desctx->BlockLen = (SDRM_DES_BLOCK_SIZ + TextLen - i) & 0x07;
	memcpy(Block, Text + TextLen - crt->ctx->desctx->BlockLen, crt->ctx->desctx->BlockLen);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_DES_final
 * @brief	process final block and padding
 *
 * @param	crt						[in]crypto env structure
 * @param	input					[in]message block
 * @param	inputLen				[in]byte-length of Text
 * @param	output					[out]processed message
 * @param	outputLen				[out]byte-length of output
 *
 * @return	CRYPTO_SUCCESS			if success
 * \n		CRYPTO_NULL_POINTER		if given argument is a null pointer
 * \n		CRYPTO_INVALID_ARGUMENT if given argument is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_DES_final(CryptoCoreContainer *crt, cc_u8 *input, cc_u32 inputLen, cc_u8 *output, cc_u32 *outputLen)
{
	int		retVal = CRYPTO_SUCCESS;
	cc_u8	*Block, PADDING[16];
	cc_u32	BlockLen, t;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->desctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	Block = crt->ctx->desctx->Block;
	BlockLen = crt->ctx->desctx->BlockLen;

	if (crt->ctx->desctx->moo >= ID_DEC_ECB)
	{
		goto DECRYPTION;
	}

//ENCRYPTION:
	if (inputLen != 0)
	{
		retVal = SDRM_DES_process(crt, input, inputLen, output, outputLen);

		if (retVal != CRYPTO_SUCCESS)
		{
			return retVal;
		}

		retVal = SDRM_DES_final(crt, NULL, 0, output + *outputLen, &t);
		*outputLen += t;

		return retVal;
	}

	if (outputLen != NULL)
	{
		*outputLen = SDRM_DES_BLOCK_SIZ;
	}

	//padding
	switch(crt->ctx->desctx->padding)
	{
		case 0 :
		case ID_PKCS5 :
			memset(Block + BlockLen, SDRM_DES_BLOCK_SIZ - BlockLen, SDRM_DES_BLOCK_SIZ - BlockLen);
			break;
		case ID_SSL_PADDING :
			memset(Block + BlockLen, SDRM_DES_BLOCK_SIZ - BlockLen - 1, SDRM_DES_BLOCK_SIZ - BlockLen);
			break;
		case ID_ZERO_PADDING :
			memset(Block + BlockLen, 0x00, SDRM_DES_BLOCK_SIZ - BlockLen);
			break;
		case ID_NO_PADDING :
			if (BlockLen == 0)
			{
				if (outputLen)
				{
					*outputLen = 0;
				}
				return CRYPTO_SUCCESS;
			}
			break;
		default :
			return CRYPTO_INVALID_ARGUMENT;
	}


	//encryption
	switch(crt->ctx->desctx->moo)
	{
		case ID_ENC_ECB : 
			retVal = SDRM_ECB_Enc(ID_DES, output, Block, (cc_u8*)crt->ctx->desctx->RoundKey);
			break;
		case ID_ENC_CBC :
			retVal = SDRM_CBC_Enc(ID_DES, output, Block, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV);
			break;
		case ID_ENC_CFB :
			retVal = SDRM_CFB_Enc(ID_DES, output, Block, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV);
			break;
		case ID_ENC_OFB :
			retVal = SDRM_OFB_Enc(ID_DES, output, Block, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV);
			break;
		case ID_ENC_CTR : 
			retVal = SDRM_CTR_Enc(ID_DES, output, Block, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV, crt->ctx->desctx->CTR_Count++);
			break;
		default :
			retVal = CRYPTO_INVALID_ARGUMENT;
			break;
	}

	return retVal;

DECRYPTION:
	if (outputLen != NULL)
	{
		*outputLen = 0;
	}

	if ((inputLen == 0) && (crt->ctx->desctx->padding == ID_NO_PADDING))
	{
		return CRYPTO_SUCCESS;
	}

	if ((BlockLen + inputLen) != SDRM_DES_BLOCK_SIZ)
	{
		return CRYPTO_INVALID_ARGUMENT;
	}

	if (inputLen != 0)
	{
		memcpy(Block + BlockLen, input, inputLen);
	}

	switch(crt->ctx->desctx->moo)
	{
		case ID_DEC_ECB : 
			retVal = SDRM_ECB_Dec(ID_DES, output, Block, (cc_u8*)crt->ctx->desctx->RoundKey);
			break;
		case ID_DEC_CBC :
			retVal = SDRM_CBC_Dec(ID_DES, output, Block, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV);
			break;
		case ID_DEC_CFB :
			retVal = SDRM_CFB_Dec(ID_DES, output, Block, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV);
			break;
		case ID_DEC_OFB :
			retVal = SDRM_OFB_Dec(ID_DES, output, Block, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV);
			break;
		case ID_DEC_CTR : 
			retVal = SDRM_CTR_Dec(ID_DES, output, Block, (cc_u8*)crt->ctx->desctx->RoundKey, crt->ctx->desctx->IV, crt->ctx->desctx->CTR_Count++);
			break;
		default :
			return CRYPTO_INVALID_ARGUMENT;
	}

	if (retVal != CRYPTO_SUCCESS)
	{
		return retVal;
	}

	//de-padding
	t = output[SDRM_DES_BLOCK_SIZ - 1];

	switch(crt->ctx->desctx->padding)
	{
		case 0 :
		case ID_PKCS5 :
			if ((t > SDRM_DES_BLOCK_SIZ) || (t < 1))
			{
				return CRYPTO_INVALID_ARGUMENT;
			}
			memset(PADDING, t, t);
			break;
		case ID_SSL_PADDING :
			++t;
			if ((t > SDRM_DES_BLOCK_SIZ) || (t < 1))
			{
				return CRYPTO_INVALID_ARGUMENT;
			}
			memset(PADDING, t - 1, t);
			break;
		case ID_ZERO_PADDING :
			{
				cc_u32 tmpLen;
				tmpLen = SDRM_DES_BLOCK_SIZ;
				while((tmpLen != 0x00) && (output[tmpLen - 1] == 0x00))
				{
					tmpLen--;
				}

				if (outputLen != NULL)
				{
					*outputLen = tmpLen;
				}
			}
			return CRYPTO_SUCCESS;
		case ID_NO_PADDING :
			if (outputLen != NULL)
			{
				*outputLen = SDRM_DES_BLOCK_SIZ;
			}
			return CRYPTO_SUCCESS;
		default :
			if (outputLen != NULL)
			{
				*outputLen = 0;
			}
			return CRYPTO_INVALID_ARGUMENT;
	}

	if (memcmp(PADDING, output + SDRM_DES_BLOCK_SIZ - t, t) != 0)
	{
		return CRYPTO_INVALID_ARGUMENT;
	}

	if (outputLen != NULL)
	{
		*outputLen = SDRM_DES_BLOCK_SIZ - t;
	}

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_TDES_init
 * @brief	intialize crypt context for triple des
 *
 * @param	crt						[out]crypto env structure
 * @param	mode					[in]encryption|decryption and mode of operation
 * @param	PADDING					[in]padding method
 * @param	key						[in]user key
 * @param	keysize					[in]byte-length of key
 * @param	IV						[in]initial vector
 *
 * @return	CRYPTO_SUCCESS			if success
 * \n		CRYPTO_NULL_POINTER		if given argument is a null pointer
 * \n		CRYPTO_INVALID_ARGUMENT if given argument is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_TDES_init(CryptoCoreContainer *crt, cc_u32 mode, cc_u32 PADDING, cc_u8 *key, cc_u32 keysize, cc_u8 *IV)
{
	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->tdesctx == NULL) || (key == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	if (((keysize != 16) && (keysize != 24)) || !(((mode >= 1111) && (mode <= 1115)) || ((mode >= 1121) && (mode <= 1125))))
	{
		return CRYPTO_INVALID_ARGUMENT;
	}

	crt->ctx->tdesctx->moo = mode;

	if ((PADDING != 0) && (PADDING != ID_PKCS5) && (PADDING != ID_SSL_PADDING) && (PADDING != ID_ZERO_PADDING) && (PADDING != ID_NO_PADDING))
	{
		return CRYPTO_INVALID_ARGUMENT;
	}

	crt->ctx->tdesctx->padding = PADDING;

	if ((mode != ID_DEC_ECB) && (mode != ID_DEC_CBC))
	{
		if (keysize == 16)
		{
			SDRM_getEncRoundKey(ID_TDES_EDE2, key, (cc_u8*)(crt->ctx->tdesctx->RoundKey));
		}
		else
		{
			SDRM_getEncRoundKey(ID_TDES_EDE3, key, (cc_u8*)(crt->ctx->tdesctx->RoundKey));
		}
	} else
	{
		if (keysize == 16)
		{
			SDRM_getDecRoundKey(ID_TDES_EDE2, key, (cc_u8*)(crt->ctx->tdesctx->RoundKey));
		}
		else
		{
			SDRM_getDecRoundKey(ID_TDES_EDE3, key, (cc_u8*)(crt->ctx->tdesctx->RoundKey));
		}
	}
	
	crt->ctx->tdesctx->BlockLen = 0;
	crt->ctx->tdesctx->CTR_Count = 0;

	memcpy(crt->ctx->tdesctx->UserKey, key, SDRM_DES_BLOCK_SIZ);

	if (IV)
	{
		memcpy(crt->ctx->tdesctx->IV, IV, SDRM_DES_BLOCK_SIZ);
	}
	else
	{
		memset(crt->ctx->tdesctx->IV, 0x00, SDRM_DES_BLOCK_SIZ);
	}

	return CRYPTO_SUCCESS;
}

/*
 * @fn		int SDRM_TDES_process(CryptoCoreContainer *crt, cc_u8 *Text, cc_u32 TextLen, cc_u8 *output, cc_u32 *outputLen)
 * @brief	process message block
 *
 * @param	crt						[in]crypto env structure
 * @param	Text					[in]message block
 * @param	TextLen					[in]byte-length of Text
 * @param	output					[out]proecessed message
 * @param	outputLen				[out]byte-length of output
 *
 * @return	CRYPTO_SUCCESS			if success
 * \n		CRYPTO_NULL_POINTER		if given argument is a null pointer
 * \n		CRYPTO_INVALID_ARGUMENT if given argument is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_TDES_process(CryptoCoreContainer *crt, cc_u8 *Text, cc_u32 TextLen, cc_u8 *output, cc_u32 *outputLen)
{
	int		i, Temp;
	int		retVal, BlockLen;
	cc_u8	*Block;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->tdesctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	Block = crt->ctx->tdesctx->Block;
	BlockLen = crt->ctx->tdesctx->BlockLen;

	*outputLen = 0;

	if ((TextLen + BlockLen) < SDRM_DES_BLOCK_SIZ)
	{
		memcpy(Block + BlockLen, Text, TextLen);
		crt->ctx->tdesctx->BlockLen += TextLen;
		return CRYPTO_SUCCESS;
	}

	if (BlockLen)
	{
		memcpy(Block + BlockLen, Text, SDRM_DES_BLOCK_SIZ - BlockLen);

		switch(crt->ctx->tdesctx->moo)
		{
			case ID_ENC_ECB :
				retVal = SDRM_ECB_Enc(ID_TDES, output, Block, (cc_u8*)crt->ctx->tdesctx->RoundKey);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_ENC_CBC :
				retVal = SDRM_CBC_Enc(ID_TDES, output, Block, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_ENC_CFB :
				retVal = SDRM_CFB_Enc(ID_TDES, output, Block, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_ENC_OFB :
				retVal = SDRM_OFB_Enc(ID_TDES, output, Block, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_ENC_CTR :
				retVal = SDRM_CTR_Enc(ID_TDES, output, Block, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV, crt->ctx->tdesctx->CTR_Count++);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_DEC_ECB : 
				retVal = SDRM_ECB_Dec(ID_TDES, output, Block, (cc_u8*)crt->ctx->tdesctx->RoundKey);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_DEC_CBC :
				retVal = SDRM_CBC_Dec(ID_TDES, output, Block, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_DEC_CFB :
				retVal = SDRM_CFB_Dec(ID_TDES, output, Block, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_DEC_OFB :
				retVal = SDRM_OFB_Dec(ID_TDES, output, Block, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_DEC_CTR : 
				retVal = SDRM_CTR_Dec(ID_TDES, output, Block, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV, crt->ctx->tdesctx->CTR_Count++);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			default :
				return CRYPTO_INVALID_ARGUMENT;
		}

		if (retVal != CRYPTO_SUCCESS)
		{
			return retVal;
		}
	}

	Temp = TextLen + BlockLen - SDRM_DES_BLOCK_SIZ + 1;
	for (i = (SDRM_DES_BLOCK_SIZ - BlockLen) & 0x07; i < Temp; i += SDRM_DES_BLOCK_SIZ)
	{
		switch(crt->ctx->tdesctx->moo)
		{
			case ID_ENC_ECB : 
				retVal = SDRM_ECB_Enc(ID_TDES, output + *outputLen, Text + i, (cc_u8*)crt->ctx->tdesctx->RoundKey);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_ENC_CBC :
				retVal = SDRM_CBC_Enc(ID_TDES, output + *outputLen, Text + i, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_ENC_CFB :
				retVal = SDRM_CFB_Enc(ID_TDES, output + *outputLen, Text + i, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_ENC_OFB :
				retVal = SDRM_OFB_Enc(ID_TDES, output + *outputLen, Text + i, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_ENC_CTR : 
				retVal = SDRM_CTR_Enc(ID_TDES, output + *outputLen, Text + i, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV, crt->ctx->tdesctx->CTR_Count++);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_DEC_ECB : 
				retVal = SDRM_ECB_Dec(ID_TDES, output + *outputLen, Text + i, (cc_u8*)crt->ctx->tdesctx->RoundKey);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_DEC_CBC :
				retVal = SDRM_CBC_Dec(ID_TDES, output + *outputLen, Text + i, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_DEC_CFB :
				retVal = SDRM_CFB_Dec(ID_TDES, output + *outputLen, Text + i, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_DEC_OFB :
				retVal = SDRM_OFB_Dec(ID_TDES, output + *outputLen, Text + i, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			case ID_DEC_CTR : 
				retVal = SDRM_CTR_Dec(ID_TDES, output + *outputLen, Text + i, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV, crt->ctx->tdesctx->CTR_Count++);
				*outputLen += SDRM_DES_BLOCK_SIZ;
				break;
			default :
				return CRYPTO_INVALID_ARGUMENT;
		}

		if (retVal != CRYPTO_SUCCESS)
		{
			return retVal;
		}
	}

	crt->ctx->tdesctx->BlockLen = (SDRM_DES_BLOCK_SIZ + TextLen - i) & 0x07;
	memcpy(Block, Text + TextLen - crt->ctx->tdesctx->BlockLen, crt->ctx->tdesctx->BlockLen);

	return CRYPTO_SUCCESS;
}


/*
 * @fn		int SDRM_TDES_final(CryptoCoreContainer *crt, cc_u8 *input, cc_u32 inputLen, cc_u8 *output, cc_u32 *outputLen)
 * @brief	process final block and padding
 *
 * @param	crt						[in]crypto env structure
 * @param	input					[in]message block
 * @param	inputLen				[in]byte-length of Text
 * @param	output					[out]processed message
 * @param	outputLen				[out]byte-length of output
 *
 * @return	CRYPTO_SUCCESS			if success
 * \n		CRYPTO_NULL_POINTER		if given argument is a null pointer
 * \n		CRYPTO_INVALID_ARGUMENT if given argument is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_TDES_final(CryptoCoreContainer *crt, cc_u8 *input, cc_u32 inputLen, cc_u8 *output, cc_u32 *outputLen)
{
	int		retVal = CRYPTO_SUCCESS;
	cc_u8	*Block, PADDING[16];
	cc_u32	BlockLen, t;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->tdesctx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	Block = crt->ctx->tdesctx->Block;
	BlockLen = crt->ctx->tdesctx->BlockLen;


	if (crt->ctx->tdesctx->moo >= ID_DEC_ECB)
	{
		goto DECRYPTION;
	}

//ENCRYPTION:
	if (inputLen != 0)
	{
		retVal = SDRM_TDES_process(crt, input, inputLen, output, outputLen);

		if (retVal != CRYPTO_SUCCESS)
		{
			return retVal;
		}

		retVal = SDRM_TDES_final(crt, NULL, 0, output + *outputLen, &t);
		*outputLen += t;

		return retVal;
	}

	if (outputLen != NULL)
	{
		*outputLen = SDRM_DES_BLOCK_SIZ;
	}

	//padding
	switch(crt->ctx->tdesctx->padding)
	{
		case 0 :
		case ID_PKCS5 :
			memset(Block + BlockLen, SDRM_DES_BLOCK_SIZ - BlockLen, SDRM_DES_BLOCK_SIZ - BlockLen);
			break;
		case ID_SSL_PADDING :
			memset(Block + BlockLen, SDRM_DES_BLOCK_SIZ - BlockLen - 1, SDRM_DES_BLOCK_SIZ - BlockLen);
			break;
		case ID_ZERO_PADDING :
			memset(Block + BlockLen, 0x00, SDRM_DES_BLOCK_SIZ - BlockLen);
			break;
		case ID_NO_PADDING :
			if (BlockLen == 0)
			{
				if (outputLen)
				{
					*outputLen = 0;
				}
				return CRYPTO_SUCCESS;
			}
			break;
		default :
			return CRYPTO_INVALID_ARGUMENT;
	}

	//encryption
	switch(crt->ctx->tdesctx->moo)
	{
		case ID_ENC_ECB : 
			retVal = SDRM_ECB_Enc(ID_TDES, output, Block, (cc_u8*)crt->ctx->tdesctx->RoundKey);
			break;
		case ID_ENC_CBC :
			retVal = SDRM_CBC_Enc(ID_TDES, output, Block, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV);
			break;
		case ID_ENC_CFB :
			retVal = SDRM_CFB_Enc(ID_TDES, output, Block, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV);
			break;
		case ID_ENC_OFB :
			retVal = SDRM_OFB_Enc(ID_TDES, output, Block, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV);
			break;
		case ID_ENC_CTR : 
			retVal = SDRM_CTR_Enc(ID_TDES, output, Block, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV, crt->ctx->tdesctx->CTR_Count++);
			break;
		default :
			retVal = CRYPTO_INVALID_ARGUMENT;
			break;
	}

	return retVal;

DECRYPTION:
	if (outputLen != NULL)
	{
		*outputLen = 0;
	}

	if ((inputLen == 0) && (crt->ctx->tdesctx->padding == ID_NO_PADDING))
	{
		return CRYPTO_SUCCESS;
	}

	if ((BlockLen + inputLen) != SDRM_DES_BLOCK_SIZ)
	{
		return CRYPTO_INVALID_ARGUMENT;
	}

	if (inputLen != 0)
	{
		memcpy(Block + BlockLen, input, inputLen);
	}

	switch(crt->ctx->tdesctx->moo)
	{
		case ID_DEC_ECB : 
			retVal = SDRM_ECB_Dec(ID_TDES, output, Block, (cc_u8*)crt->ctx->tdesctx->RoundKey);
			break;
		case ID_DEC_CBC :
			retVal = SDRM_CBC_Dec(ID_TDES, output, Block, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV);
			break;
		case ID_DEC_CFB :
			retVal = SDRM_CFB_Dec(ID_TDES, output, Block, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV);
			break;
		case ID_DEC_OFB :
			retVal = SDRM_OFB_Dec(ID_TDES, output, Block, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV);
			break;
		case ID_DEC_CTR : 
			retVal = SDRM_CTR_Dec(ID_TDES, output, Block, (cc_u8*)crt->ctx->tdesctx->RoundKey, crt->ctx->tdesctx->IV, crt->ctx->tdesctx->CTR_Count++);
			break;
		default :
			return CRYPTO_INVALID_ARGUMENT;
	}

	if (retVal != CRYPTO_SUCCESS)
	{
		return retVal;
	}

	//de-padding
	t = output[SDRM_DES_BLOCK_SIZ - 1];

	switch(crt->ctx->tdesctx->padding)
	{
		case 0 :
		case ID_PKCS5 :
			if ((t > SDRM_DES_BLOCK_SIZ) || (t < 1))
			{
				return CRYPTO_INVALID_ARGUMENT;
			}
			memset(PADDING, t, t);
			break;
		case ID_SSL_PADDING :
			++t;
			if ((t > SDRM_DES_BLOCK_SIZ) || (t < 1))
			{
				return CRYPTO_INVALID_ARGUMENT;
			}
			memset(PADDING, t - 1, t);
			break;
		case ID_ZERO_PADDING :
			{
				cc_u32 tmpLen;
				tmpLen = SDRM_TDES_BLOCK_SIZ;
				while((tmpLen != 0x00) && (output[tmpLen - 1] == 0x00))
				{
					tmpLen--;
				}

				if (outputLen != NULL)
				{
					*outputLen = tmpLen;
				}
			}
			return CRYPTO_SUCCESS;
		case ID_NO_PADDING :
			if (outputLen != NULL)
			{
				*outputLen = SDRM_TDES_BLOCK_SIZ;
			}
			return CRYPTO_SUCCESS;
		default :
			if (outputLen != NULL)
			{
				*outputLen = 0;
			}
			return CRYPTO_INVALID_ARGUMENT;
	}

	if (memcmp(PADDING, output + SDRM_TDES_BLOCK_SIZ - t, t) != 0)
	{
		return CRYPTO_INVALID_ARGUMENT;
	}

	if (outputLen != NULL)
	{
		*outputLen = SDRM_DES_BLOCK_SIZ - t;
	}

	return CRYPTO_SUCCESS;

}

/***************************** End of File *****************************/
