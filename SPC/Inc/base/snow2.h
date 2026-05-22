/**
 * \file	snow2.h
 * @brief	implementation of SNOW 2.0 encryption scheme
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/12/02
 */


#ifndef _SNOW2_H
#define _SNOW2_H


////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include "CryptoCore.h"


////////////////////////////////////////////////////////////////////////////
// Function Prototypes
////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @fn		int SDRM_SNOW2_Setup(SDRM_SNOW2Context *ctx, cc_u8 *UserKey, cc_u32 keyLen, cc_u8 *IV)
 * @brief	Setup FSM and s values
 * @param	ctx				[out]crypto context
 * @param	UserKey			[in]User Key, 128 or 256 bit
 * @param	keyLen			[in]byte-size of User Key, 16 or 32
 * @param	IV				[in]16 byte initial vector
 * @return	CRYPTO_SUCCESS	if no error is occured
 */
CRYPTOCORE_INTERNAL int SDRM_SNOW2_Setup(SDRM_SNOW2Context *ctx, cc_u8 *UserKey, cc_u32 keyLen, cc_u8 *IV);

/*
 * @fn		int SDRM_SNOW2_getKeyStream64(SDRM_SNOW2Context *ctx, cc_u32 *keyStream64)
 * @brief	get 64 byte key stream
 * @param	ctx				[out]crypto context
 * @param	keyStream64		[in]generated key stream
 * @return	CRYPTO_SUCCESS	if no error is occured
 */
CRYPTOCORE_INTERNAL int SDRM_SNOW2_getKeyStream64(SDRM_SNOW2Context *ctx, cc_u32 *keyStream64);

/*
 * @fn		int SDRM_SNOW2_getKeyStream(SDRM_SNOW2Context *ctx, cc_u32 *keyStream)
 * @brief	get 4 byte key stream
 * @param	ctx				[out]crypto context
 * @param	keyStream		[in]generated key stream
 * @return	CRYPTO_SUCCESS	if no error is occured
 */
CRYPTOCORE_INTERNAL int SDRM_SNOW2_getKeyStream(SDRM_SNOW2Context *ctx, cc_u32 *keyStream);


#ifdef __cplusplus
}
#endif

#endif	//	_SNOW2_H

/***************************** End of File *****************************/
