/**
 * \file	rc4.h
 * @brief	implementation of RC4 encryption scheme
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/12/01
 */

#ifndef _RC4_H
#define _RC4_H

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
 * @fn		int SDRM_RC4_Setup(SDRM_RC4Context *ctx, cc_u8 *UserKey, cc_u32 keyLen)
 * @brief	intialize s
 *
 * @param	ctx					[in]crypto context
 * @param	UserKey				[in]user key
 * @param	keyLen				[out]byte-length of UserKey
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 */
CRYPTOCORE_INTERNAL int SDRM_RC4_Setup(SDRM_RC4Context *ctx, cc_u8 *UserKey, cc_u32 keyLen);

/*
 * @fn		int SDRM_RC4_PRNG(SDRM_RC4Context *ctx, cc_u8 *in, cc_u32 inLen, cc_u8 *out)
 * @brief	process stream data
 *
 * @param	ctx					[in]crypto context
 * @param	in					[in]plaintext
 * @param	inLen				[in]byte-length of in
 * @param	out					[out]cipher text
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 */
CRYPTOCORE_INTERNAL int SDRM_RC4_PRNG(SDRM_RC4Context *ctx, cc_u8 *in, cc_u32 inLen, cc_u8 *out);

#ifdef __cplusplus
}
#endif

#endif

/***************************** End of File *****************************/
