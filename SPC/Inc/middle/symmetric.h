/**
 * \file	symmetric.h
 * @brief	API for symmetric encryption
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon, Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/11/07
 */

#ifndef _SYMMETRIC_H
#define _SYMMETRIC_H

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include "CC_API.h"

////////////////////////////////////////////////////////////////////////////
// Function Prototypes
////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

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
CRYPTOCORE_INTERNAL int SDRM_AES_init(CryptoCoreContainer *crt, cc_u32 mode, cc_u32 PADDING, cc_u8 *key, cc_u32 keysize, cc_u8 *IV);

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
CRYPTOCORE_INTERNAL int SDRM_AES_process(CryptoCoreContainer *crt, cc_u8 *Text, cc_u32 TextLen, cc_u8 *output, cc_u32 *outputLen);

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
CRYPTOCORE_INTERNAL int SDRM_AES_final(CryptoCoreContainer *crt, cc_u8 *input, cc_u32 inputLen, cc_u8 *output, cc_u32 *outputLen);

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
CRYPTOCORE_INTERNAL int SDRM_RC4_init(CryptoCoreContainer *crt, cc_u32 mode, cc_u32 PADDING, cc_u8 *key, cc_u32 keysize, cc_u8 *IV);

/*
 * @fn		SDRM_RC4_process
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
CRYPTOCORE_INTERNAL int SDRM_RC4_process(CryptoCoreContainer *crt, cc_u8 *in, cc_u32 inLen, cc_u8 *out, cc_u32 *outLen);

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
CRYPTOCORE_INTERNAL int SDRM_SNOW2_init(CryptoCoreContainer *crt, cc_u32 mode, cc_u32 PADDING, cc_u8 *key, cc_u32 keysize, cc_u8 *IV);

/*
 * @fn
 * @brief	process message block
 * @param	crt						[in]crypto env structure
 * @param	in						[in]message block
 * @param	inLen					[in]byte-length of Text
 * @param	out						[out]processed message
 * @param	outLen					[out]byte-length of output
 * @return	CRYPTO_SUCCESS			if success
 * \n		CRYPTO_NULL_POINTER		if given argument is a null pointer
 * \n		CRYPTO_INVALID_ARGUMENT if given argument is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_SNOW2_process(CryptoCoreContainer *crt, cc_u8 *in, cc_u32 inLen, cc_u8 *out, cc_u32 *outLen);

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
CRYPTOCORE_INTERNAL int SDRM_DES_init(CryptoCoreContainer *crt, cc_u32 mode, cc_u32 PADDING, cc_u8 *key, cc_u32 keysize, cc_u8 *IV);

/*
 * @fn		SDRM_DES_process
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
CRYPTOCORE_INTERNAL int SDRM_DES_process(CryptoCoreContainer *crt, cc_u8 *Text, cc_u32 TextLen, cc_u8 *output, cc_u32 *outputLen);

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
CRYPTOCORE_INTERNAL int SDRM_DES_final(CryptoCoreContainer *crt, cc_u8 *input, cc_u32 inputLen, cc_u8 *output, cc_u32 *outputLen);

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
CRYPTOCORE_INTERNAL int SDRM_TDES_init(CryptoCoreContainer *crt, cc_u32 mode, cc_u32 PADDING, cc_u8 *key, cc_u32 keysize, cc_u8 *IV);

/*
 * @fn		SDRM_TDES_process
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
CRYPTOCORE_INTERNAL int SDRM_TDES_process(CryptoCoreContainer *crt, cc_u8 *Text, cc_u32 TextLen, cc_u8 *output, cc_u32 *outputLen);

/*
 * @fn		SDRM_TDES_final
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
CRYPTOCORE_INTERNAL int SDRM_TDES_final(CryptoCoreContainer *crt, cc_u8 *input, cc_u32 inputLen, cc_u8 *output, cc_u32 *outputLen);

#ifdef __cplusplus
}
#endif

#endif

/***************************** End of File *****************************/
