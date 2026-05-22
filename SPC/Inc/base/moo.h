/**
 * \file	moo.h
 * @brief	implementation of mode of operations
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/08/04
 */


#ifndef _MOO_H
#define _MOO_H


////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include "CryptoCore.h"
#include "aes.h"
#include "des.h"
#include "tdes.h"


////////////////////////////////////////////////////////////////////////////
// Macros for Mode of operation
////////////////////////////////////////////////////////////////////////////
#ifndef SDRM_CheckByteUINT32
/*!	@brief	get k-th byte from cc_u32 array A	*/
#define SDRM_CheckByteUINT32(A, k)		(cc_u8)(0xff & (A[(k) >> 2] >> (((k) & 3 ) << 3)))
#endif


////////////////////////////////////////////////////////////////////////////
// Function Prototypes
////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @fn		int SDRM_ECB_Enc(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key)
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
CRYPTOCORE_INTERNAL int SDRM_ECB_Enc(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key);


/*
 * @fn		int SDRM_ECB_Dec(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key)
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
CRYPTOCORE_INTERNAL int SDRM_ECB_Dec(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key);


/*
 * @fn		int SDRM_CBC_Enc(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key, cc_u8 *IV)
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
CRYPTOCORE_INTERNAL int SDRM_CBC_Enc(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key, cc_u8 *IV);


/*
 * @fn		int SDRM_CBC_Dec(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key, cc_u8 *IV)
 * @brief	Decrypt a block with CBC mode
 *
 * @param	Algorithm				[in]algorithm
 * @param	out					[out]plain text block
 * @param	in					[in]cipher text block
 * @param	key					[in]user key
 * @param	IV					[in]initial vector
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_INVALID_ARGUMENT if parameter is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_CBC_Dec(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key, cc_u8 *IV);


/*	
 * @fn		int SDRM_CFB_Enc(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key, cc_u8 *IV)
 * @brief	Encrypt a block with CFB mode
 *
 * @param	Algorithm				[in]algorithm
 * @param	out					[out]cipher text block
 * @param	in					[in]plain text block
 * @param	key					[in]user key
 * @param	IV					[in]initial vector
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_INVALID_ARGUMENT if parameter is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_CFB_Enc(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key, cc_u8 *IV);


/*
 * @fn		int SDRM_CFB_Dec(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key, cc_u8 *IV)
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
CRYPTOCORE_INTERNAL int SDRM_CFB_Dec(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key, cc_u8 *IV);


/*
 * @fn		int SDRM_OFB_Enc(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key, cc_u8 *IV)
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
CRYPTOCORE_INTERNAL int SDRM_OFB_Enc(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key, cc_u8 *IV);


/*
 * @fn		SDRM_OFB_Dec(ALG, OUT, IN, KEY, IV)
 * @brief	Decrypt a block with OFB mode
 *
 * \n	ALG						[in]algorithm
 * \n	OUT						[out]plain text block
 * \n	IN						[in]cipher text block
 * \n	KEY						[in]user key
 * \n	IV						[in]initial vector
 */
#define SDRM_OFB_Dec(ALG, OUT, IN, KEY, IV)	SDRM_OFB_Enc(ALG, OUT, IN, KEY, IV)

/*
 * @fn		int SDRM_CTR_Enc(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key, cc_u8 *IV, cc_u32 counter)
 * @brief	Encrypt a block with CTR mode
 *
 * @param	Algorithm				[in]algorithm
 * @param	out						[out]cipher text block
 * @param	in						[in]plain text block
 * @param	key						[in]user key
 * @param	IV						[in]initial vector
 * @param	counter					[in]counter
 *
 * @return	CRYPTO_SUCCESS			if no error is occured
 * \n		CRYPTO_INVALID_ARGUMENT if parameter is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_CTR_Enc(int Algorithm, cc_u8 *out, cc_u8 *in, cc_u8 *key, cc_u8 *IV, cc_u32 counter);


/*
 * @fn		SDRM_CTR_Dec(ALG, OUT, IN, KEY, IV, CTR)
 * @brief	Decrypt a block with CTR mode
 *
 * \n	ALG						[in]algorithm
 * \n	OUT						[out]plain text block
 * \n	IN						[in]cipher text block
 * \n	KEY						[in]user key
 * \n	IV						[in]initial vector
 * \n	CTR						[in]counter
 *
 * @return	CRYPTO_SUCCESS			if no error is occured
 * \n		CRYPTO_INVALID_ARGUMENT if parameter is invalid
 */
#define SDRM_CTR_Dec(ALG, OUT, IN, KEY, IV, CTR)	SDRM_CTR_Enc(ALG, OUT, IN, KEY, IV, CTR)


#ifdef __cplusplus
}
#endif

#endif // _MOO_H

/***************************** End of File *****************************/
