/**
 * \file	tdes.h
 * @brief	high-speed implementation of Triple DES-EDE
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/12/06
 */

#ifndef _TDES_H
#define _TDES_H

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
 * @fn		int SDRM_TDES_KeySched(cc_u8 *RoundKey, cc_u8 *UserKey, cc_u32 KeyLen, cc_u32 RKStep)
 * @brief	Expand the cipher key into the encryption key schedule
 *
 * @param	RoundKey			[out]generated round key
 * @param	UserKey				[in]user key, 16 or 24 byte
 * @param	KeyLen				[in]byte-length of UserKey
 * @param	RKStep				[in]operation mode
 *
 * @return	the number of rounds for the given cipher key size
 */
CRYPTOCORE_INTERNAL int SDRM_TDES_KeySched(cc_u8 *RoundKey, cc_u8 *UserKey, cc_u32 KeyLen, cc_u32 RKStep);

/*
 * @fn		int SDRM_TDES_Encryption(cc_u32 RoundKey[][2], cc_u8 *msg, cc_u8 *out)
 * @brief	Triple DES processing for one block
 *
 * @param	RoundKey			[in]expanded round key
 * @param	msg					[in]8 byte plaintext
 * @param	out					[out]8 byte ciphertext
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 */
CRYPTOCORE_INTERNAL int SDRM_TDES_Encryption(cc_u32 RoundKey[][2], cc_u8 *msg, cc_u8 *out);

/*
 * @fn		int SDRM_TDES64_Encryption(cc_u8 *cipherText, cc_u8 *plainText, cc_u8 *UserKey)
 * @brief	one block Triple DES Encryption
 *
 * @param	cipherText	[out]encrypted text
 * @param	plainText	[in]plain text
 * @param	UserKey		[in]user key
 *
 * @return	CRYPTO_SUCCESS if success
 */
CRYPTOCORE_INTERNAL int SDRM_TDES64_Encryption(cc_u8 *cipherText, cc_u8 *plainText, cc_u8 *UserKey);

/*
 * @fn		int SDRM_TDES64_Decryption(cc_u8 *plainText, cc_u8 *cipherText, cc_u8 *UserKey)
 * @brief	one block Triple DES Decryption
 *
 * @param	plainText	[out]decrypted text
 * @param	cipherText	[in]cipher text
 * @param	UserKey		[in]user key
 *
 * @return	CRYPTO_SUCCESS if success
 */
CRYPTOCORE_INTERNAL int SDRM_TDES64_Decryption(cc_u8 *plainText, cc_u8 *cipherText, cc_u8 *UserKey);

#ifdef __cplusplus
}
#endif

#endif

/***************************** End of File *****************************/
