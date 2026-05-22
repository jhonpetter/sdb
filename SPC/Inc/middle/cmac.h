/**
 * \file	cmac.h
 * @brief	funciton for c-mac code generation by AES-128
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/11/20
 */

#ifndef _CMAC_H
#define _CMAC_H

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include "CC_API.h"
#include "moo.h"
#include "aes.h"

////////////////////////////////////////////////////////////////////////////
// Function Prototypes
////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @fn		int SDRM_CMAC_init(CryptoCoreContainer *crt, cc_u8 *Key, cc_u32 KeyLen)
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
CRYPTOCORE_INTERNAL int SDRM_CMAC_init(CryptoCoreContainer *crt, cc_u8 *Key, cc_u32 KeyLen);

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
CRYPTOCORE_INTERNAL int SDRM_CMAC_update(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msgLen);

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
CRYPTOCORE_INTERNAL int SDRM_CMAC_final(CryptoCoreContainer *crt, cc_u8 *output, cc_u32 *outputLen);

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
CRYPTOCORE_INTERNAL int SDRM_CMAC_getMAC(CryptoCoreContainer *crt, cc_u8 *Key, cc_u32 KeyLen, cc_u8 *msg, cc_u32 msgLen, cc_u8 *output, cc_u32 *outputLen);

#ifdef __cplusplus
}
#endif

#endif // _CMAC_H

/***************************** End of File *****************************/
