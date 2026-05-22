/**
 * \file	moo.c
 * @brief	implementation of mode of operations
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/08/04
 */

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include "moo.h"

////////////////////////////////////////////////////////////////////////////
// Functions
////////////////////////////////////////////////////////////////////////////
/*
 * @fn		SDRM_ECB_Enc
 * @brief	Encrypt a block with ECB mode
 *
 * @param	Algorithm				[in]algorithm
 * @param	out						[out]cipher text block
 * @param	in						[in]plain text block
 * @param	key						[in]user key
 *
 * @return	CRYPTO_SUCCESS			if no error is occured
 * \n		CRYPTO_INVALID_ARGUMENT if parameter is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_ECB_Enc(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key)
{
	switch(Algorithm)
	{
		case ID_AES128 :
			SDRM_rijndaelEncrypt((cc_u32*)(void*)key, 10, in, out);
			return CRYPTO_SUCCESS;
		case ID_AES192 :
			SDRM_rijndaelEncrypt((cc_u32*)(void*)key, 12, in, out);
			return CRYPTO_SUCCESS;
		case ID_AES256 :
			SDRM_rijndaelEncrypt((cc_u32*)(void*)key, 14, in, out);
			return CRYPTO_SUCCESS;
		case ID_DES :
			return SDRM_DES_Encryption((cc_u32(*)[2])(void*)key, in, out);
		case ID_TDES :
			return SDRM_TDES_Encryption((cc_u32(*)[2])(void*)key, in, out);
		default :
			break;
	}

	return CRYPTO_INVALID_ARGUMENT;
}

/*
 * @fn		SDRM_ECB_Dec
 * @brief	Decrypt a block with ECB mode
 *
 * @param	Algorithm				[in]algorithm
 * @param	out						[out]plain text block
 * @param	in						[in]cipher text block
 * @param	key						[in]user key
 *
 * @return	CRYPTO_SUCCESS			if no error is occured
 * \n		CRYPTO_INVALID_ARGUMENT if parameter is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_ECB_Dec(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key)
{
	switch(Algorithm)
	{
		case ID_AES128 :
			SDRM_rijndaelDecrypt((const cc_u32*)(void*)key, 10, in, out);
			return CRYPTO_SUCCESS;
		case ID_AES192 :
			SDRM_rijndaelDecrypt((const cc_u32*)(void*)key, 12, in, out);
			return CRYPTO_SUCCESS;
		case ID_AES256 :
			SDRM_rijndaelDecrypt((const cc_u32*)(void*)key, 14, in, out);
			return CRYPTO_SUCCESS;
		case ID_DES :
			return SDRM_DES_Encryption((cc_u32(*)[2])(void*)key, in, out);
		case ID_TDES :
			return SDRM_TDES_Encryption((cc_u32(*)[2])(void*)key, in, out);
		default :
			break;
	}

	return CRYPTO_INVALID_ARGUMENT;
}

/*
 * @fn		SDRM_CBC_Enc
 * @brief	Encrypt a block with CBC mode
 *
 * @param	Algorithm				[in]algorithm
 * @param	out						[out]cipher text block
 * @param	in						[in]plain text block
 * @param	key						[in]user key
 * @param	IV						[in]initial vector
 *
 * @return	CRYPTO_SUCCESS			if no error is occured
 * \n		CRYPTO_INVALID_ARGUMENT if parameter is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_CBC_Enc(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key, cc_u8 *IV)
{
	int i;

	switch(Algorithm) 
	{
		case ID_AES128 : 
			for (i = 0; i < 16; i++)
			{
				IV[i] ^= in[i];
			}

			SDRM_rijndaelEncrypt((const cc_u32*)(void*)key, 10, IV, out);

			memcpy(IV, out, 16);

			break;
		case ID_AES192 : 
			for (i = 0; i < 16; i++)
			{
				IV[i] ^= in[i];
			}

			SDRM_rijndaelEncrypt((const cc_u32*)(void*)key, 12, IV, out);

			memcpy(IV, out, 16);

			break;
		case ID_AES256 : 
			for (i = 0; i < 16; i++)
			{
				IV[i] ^= in[i];
			}

			SDRM_rijndaelEncrypt((const cc_u32*)(void*)key, 14, IV, out);

			memcpy(IV, out, 16);

			break;
		case ID_DES :
			for (i = 0; i < 8; i++)
			{
				IV[i] ^= in[i];
			}

			SDRM_DES_Encryption((cc_u32(*)[2])(void*)key, IV, out);

			memcpy(IV, out, 8);

			break;
		case ID_TDES :
			for (i = 0; i < 8; i++)
			{
				IV[i] ^= in[i];
			}

			SDRM_TDES_Encryption((cc_u32(*)[2])(void*)key, IV, out);

			memcpy(IV, out, 8);

			break;
		default :
			return CRYPTO_INVALID_ARGUMENT;
	}

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_CBC_Dec
 * @brief	Decrypt a block with CBC mode
 *
 * @param	Algorithm				[in]algorithm
 * @param	out						[out]plain text block
 * @param	in						[in]cipher text block
 * @param	key						[in]user key
 * @param	IV						[in]initial vector
 *
 * @return	CRYPTO_SUCCESS			if no error is occured
 * \n		CRYPTO_INVALID_ARGUMENT if parameter is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_CBC_Dec(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key, cc_u8 *IV){
	int i, BlockLen;
	cc_u8 buf[16];

	switch(Algorithm)
	{
		case ID_AES128 : 
			BlockLen = 16;
			memcpy(buf, in, BlockLen);
			SDRM_rijndaelDecrypt((const cc_u32*)(void*)key, 10, in, out);
			break;
		case ID_AES192 : 
			BlockLen = 16;
			memcpy(buf, in, BlockLen);
			SDRM_rijndaelDecrypt((const cc_u32*)(void*)key, 12, in, out);
			break;
		case ID_AES256 : 
			BlockLen = 16;
			memcpy(buf, in, BlockLen);
			SDRM_rijndaelDecrypt((const cc_u32*)(void*)key, 14, in, out);
			break;
		case ID_DES :
			BlockLen = 8;
			memcpy(buf, in, BlockLen);
			SDRM_DES_Encryption((cc_u32(*)[2])(void*)key, in, out);
			break;
		case ID_TDES :
			BlockLen = 8;
			memcpy(buf, in, BlockLen);
			SDRM_TDES_Encryption((cc_u32(*)[2])(void*)key, in, out);
			break;
		default :
			return CRYPTO_INVALID_ARGUMENT;
	}

	for (i = 0; i < BlockLen; i++)
	{
		out[i] ^= IV[i];
	}

	memcpy(IV, buf, BlockLen);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_CFB_Enc
 * @brief	Encrypt a block with CFB mode
 *
 * @param	Algorithm				[in]algorithm
 * @param	out						[out]cipher text block
 * @param	in						[in]plain text block
 * @param	key						[in]user key
 * @param	IV						[in]initial vector
 *
 * @return	CRYPTO_SUCCESS			if no error is occured
 * \n		CRYPTO_INVALID_ARGUMENT if parameter is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_CFB_Enc(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key, cc_u8 *IV)
{
	int i, BlockLen;
	cc_u8 buf[16];

	switch(Algorithm)
	{
		case ID_AES128 : 
			BlockLen = 16;
			memcpy(buf, in, BlockLen);
			SDRM_rijndaelEncrypt((const cc_u32*)(void*)key, 10, IV, out);
			break;
		case ID_AES192 : 
			BlockLen = 16;
			memcpy(buf, in, BlockLen);
			SDRM_rijndaelEncrypt((const cc_u32*)(void*)key, 12, IV, out);
			break;
		case ID_AES256 : 
			BlockLen = 16;
			memcpy(buf, in, BlockLen);
			SDRM_rijndaelEncrypt((const cc_u32*)(void*)key, 14, IV, out);
			break;
		case ID_DES :
			BlockLen = 8;
			memcpy(buf, in, BlockLen);
			SDRM_DES_Encryption((cc_u32(*)[2])(void*)key, IV, out);
			break;
		case ID_TDES :
			BlockLen = 8;
			memcpy(buf, in, BlockLen);
			SDRM_TDES_Encryption((cc_u32(*)[2])(void*)key, IV, out);
			break;
		default :
			return CRYPTO_INVALID_ARGUMENT;
	}
	
	for (i = 0; i < BlockLen; i++)
	{
		out[i] ^= buf[i];
	}

	memcpy(IV, out, BlockLen);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_CFB_Dec
 * @brief	Decrypt a block with CFB mode
 *
 * @param	Algorithm				[in]algorithm
 * @param	out						[out]plain text block
 * @param	in						[in]cipher text block
 * @param	key						[in]user key
 * @param	IV						[in]initial vector
 *
 * @return	CRYPTO_SUCCESS			if no error is occured
 * \n		CRYPTO_INVALID_ARGUMENT if parameter is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_CFB_Dec(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key, cc_u8 *IV)
{
	int i, BlockLen;
	cc_u8 buf[16];

	switch(Algorithm)
	{
		case ID_AES128 : 
			BlockLen = 16;
			memcpy(buf, in, BlockLen);
			SDRM_rijndaelEncrypt((const cc_u32*)(void*)key, 10, IV, out);
			break;
		case ID_AES192 : 
			BlockLen = 16;
			memcpy(buf, in, BlockLen);
			SDRM_rijndaelEncrypt((const cc_u32*)(void*)key, 12, IV, out);
			break;
		case ID_AES256 : 
			BlockLen = 16;
			memcpy(buf, in, BlockLen);
			SDRM_rijndaelEncrypt((const cc_u32*)(void*)key, 14, IV, out);
			break;
		case ID_DES :
			BlockLen = 8;
			memcpy(buf, in, BlockLen);
			SDRM_DES_Encryption((cc_u32(*)[2])(void*)key, IV, out);
			break;
		case ID_TDES :
			BlockLen = 8;
			memcpy(buf, in, BlockLen);
			SDRM_TDES_Encryption((cc_u32(*)[2])(void*)key, IV, out);
			break;
		default :
			return CRYPTO_INVALID_ARGUMENT;
	}
	
	for (i = 0; i < BlockLen; i++)
	{
		out[i] ^= buf[i];
	}

	memcpy(IV, buf, BlockLen);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_OFB_Enc
 * @brief	Encrypt a block with OFB mode
 *
 * @param	Algorithm				[in]algorithm
 * @param	out						[out]cipher text block
 * @param	in						[in]plain text block
 * @param	key						[in]user key
 * @param	IV						[in]initial vector
 *
 * @return	CRYPTO_SUCCESS			if no error is occured
 * \n		CRYPTO_INVALID_ARGUMENT if parameter is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_OFB_Enc(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key, cc_u8 *IV)
{
	int i, BlockLen;
	cc_u8 buf[16];

	switch(Algorithm)
	{
		case ID_AES128 : 
			BlockLen = 16;
			memcpy(buf, in, BlockLen);
			SDRM_rijndaelEncrypt((const cc_u32*)(void*)key, 10, IV, out);
			break;
		case ID_AES192 : 
			BlockLen = 16;
			memcpy(buf, in, BlockLen);
			SDRM_rijndaelEncrypt((const cc_u32*)(void*)key, 12, IV, out);
			break;
		case ID_AES256 : 
			BlockLen = 16;
			memcpy(buf, in, BlockLen);
			SDRM_rijndaelEncrypt((const cc_u32*)(void*)key, 14, IV, out);
			break;
		case ID_DES :
			BlockLen = 8;
			memcpy(buf, in, BlockLen);
			SDRM_DES_Encryption((cc_u32(*)[2])(void*)key, IV, out);
			break;
		case ID_TDES :
			BlockLen = 8;
			memcpy(buf, in, BlockLen);
			SDRM_TDES_Encryption((cc_u32(*)[2])(void*)key, IV, out);
			break;
		default :
			return CRYPTO_INVALID_ARGUMENT;
	}

	memcpy(IV, out, BlockLen);

	for (i = 0; i < BlockLen; i++)
	{
		out[i] ^= buf[i];
	}

	return CRYPTO_SUCCESS;
}

/*	
 * @fn		SDRM_CTR_Enc
 * @brief	Encrypt a block with CTR mode
 *
 * @param	Algorithm				[in]algorithm
 * @param	out						[out]cipher text block
 * @param	in						[in]plain text block
 * @param	key						[in]user key
 * @param	IV						[in]initial vector
 * @param	counter					[in]
 *
 * @return	CRYPTO_SUCCESS			if no error is occured
 * \n		CRYPTO_INVALID_ARGUMENT if parameter is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_CTR_Enc(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key, cc_u8 *IV, cc_u32 counter)
{
	int i, BlockLen;
	cc_u8 buf[16];

	switch(Algorithm)
	{
		case ID_AES128 : 
			BlockLen = 16;
			IV[12] = (cc_u8)(0xff & (counter >> 24));
			IV[13] = (cc_u8)(0xff & (counter >> 16));
			IV[14] = (cc_u8)(0xff & (counter >> 8 ));
			IV[15] = (cc_u8)(0xff & (counter      ));
			memcpy(buf, in, BlockLen);
			SDRM_rijndaelEncrypt((const cc_u32*)(void*)key, 10, IV, out);
			break;
		case ID_AES192 : 
			BlockLen = 16;
			IV[12] = (cc_u8)(0xff & (counter >> 24));
			IV[13] = (cc_u8)(0xff & (counter >> 16));
			IV[14] = (cc_u8)(0xff & (counter >> 8 ));
			IV[15] = (cc_u8)(0xff & (counter      ));
			memcpy(buf, in, BlockLen);
			SDRM_rijndaelEncrypt((const cc_u32*)(void*)key, 12, IV, out);
			break;
		case ID_AES256 : 
			BlockLen = 16;
			IV[12] = (cc_u8)(0xff & (counter >> 24));
			IV[13] = (cc_u8)(0xff & (counter >> 16));
			IV[14] = (cc_u8)(0xff & (counter >> 8 ));
			IV[15] = (cc_u8)(0xff & (counter      ));
			memcpy(buf, in, BlockLen);
			SDRM_rijndaelEncrypt((const cc_u32*)(void*)key, 14, IV, out);
			break;
		case ID_DES :
			BlockLen = 8;
			IV[4] = (cc_u8)(0xff & (counter >> 24));
			IV[5] = (cc_u8)(0xff & (counter >> 16));
			IV[6] = (cc_u8)(0xff & (counter >> 8 ));
			IV[7] = (cc_u8)(0xff & (counter      ));
			memcpy(buf, in, BlockLen);
			SDRM_DES_Encryption((cc_u32(*)[2])(void*)key, IV, out);
			break;
		case ID_TDES :
			BlockLen = 8;
			IV[4] = (cc_u8)(0xff & (counter >> 24));
			IV[5] = (cc_u8)(0xff & (counter >> 16));
			IV[6] = (cc_u8)(0xff & (counter >> 8 ));
			IV[7] = (cc_u8)(0xff & (counter      ));
			memcpy(buf, in, BlockLen);
			SDRM_TDES_Encryption((cc_u32(*)[2])(void*)key, IV, out);
			break;
		default :
			return CRYPTO_INVALID_ARGUMENT;
	}

	for (i = 0; i < BlockLen; i++)
	{
		out[i] ^= buf[i];
	}

	return CRYPTO_SUCCESS;
}

/***************************** End of File *****************************/
