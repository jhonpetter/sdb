/**
 * \file	hmac.h
 * @brief	funciton for c-mac code generation by SHA1 and MD5
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/12/19
 */

#ifndef _HMAC_H
#define _HMAC_H

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
CRYPTOCORE_INTERNAL int SDRM_HMAC_init(CryptoCoreContainer *crt, cc_u8 *Key, cc_u32 KeyLen);

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
CRYPTOCORE_INTERNAL int SDRM_HMAC_update(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msgLen);

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
CRYPTOCORE_INTERNAL int SDRM_HMAC_final(CryptoCoreContainer *crt, cc_u8 *output, cc_u32 *outputLen);

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
CRYPTOCORE_INTERNAL int SDRM_HMAC_getMAC(CryptoCoreContainer *crt, cc_u8 *Key, cc_u32 KeyLen, cc_u8 *msg, cc_u32 msgLen, cc_u8 *output, cc_u32 *outputLen);

#ifdef __cplusplus
}
#endif

#endif // _HMAC_H

/***************************** End of File *****************************/
