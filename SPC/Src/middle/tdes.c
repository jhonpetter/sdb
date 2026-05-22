/**
 * \file	tdes.c
 * @brief	high-speed implementation of Triple DES-EDE
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/12/06
 */

//////////////////////////////////////////////////////////////////////////
// Include Header Files
//////////////////////////////////////////////////////////////////////////
#include "tdes.h"
#include "des.h"

////////////////////////////////////////////////////////////////////////////
// Functions
////////////////////////////////////////////////////////////////////////////
/*
 * @fn		SDRM_TDES_KeySched
 * @brief	Expand the cipher key into the encryption key schedule
 *
 * @param	RoundKey			[out]generated round key
 * @param	UserKey				[in]user key, 16 or 24 byte
 * @param	KeyLen				[in]byte-length of UserKey
 * @param	RKStep				[in]operation mode
 *
 * @return	the number of rounds for the given cipher key size
 */
CRYPTOCORE_INTERNAL int SDRM_TDES_KeySched(cc_u8 *RoundKey, cc_u8 *UserKey, cc_u32 KeyLen, cc_u32 RKStep)
{

	if (RKStep == 1)
	{
		SDRM_DES_KeySched(RoundKey, UserKey, 0, 1);
		SDRM_DES_KeySched(RoundKey + 128, UserKey + 8, 15, (cc_u32)-1);

		if (KeyLen == 16)
		{											//2-key des
			memcpy(RoundKey + 256, RoundKey, 128);
		}
		else
		{											//3-key des
			SDRM_DES_KeySched(RoundKey + 256, UserKey + 16, 0, 1);
		}
	}
	else {
		SDRM_DES_KeySched(RoundKey + 256, UserKey, 15, (cc_u32)-1);
		SDRM_DES_KeySched(RoundKey + 128, UserKey + 8, 0, 1);

		if (KeyLen == 16)
		{											//2-key des
			memcpy(RoundKey, RoundKey + 256, 128);
		}
		else
		{											//3-key des
			SDRM_DES_KeySched(RoundKey, UserKey + 16, 15, (cc_u32)-1);
		}
	}

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_TDES_Encryption
 * @brief	Triple DES processing for one block
 *
 * @param	RoundKey			[in]expanded round key
 * @param	msg					[in]8 byte plaintext
 * @param	out					[out]8 byte ciphertext
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 */
CRYPTOCORE_INTERNAL int SDRM_TDES_Encryption(cc_u32 RoundKey[][2], cc_u8 *msg, cc_u8 *out)
{
	cc_u8 buf[8];

	SDRM_DES_Encryption(RoundKey	 , msg, buf);
	SDRM_DES_Encryption(RoundKey + 16, buf, buf);
	SDRM_DES_Encryption(RoundKey + 32, buf, out);

	return CRYPTO_SUCCESS;
}


/*
 * @fn		SDRM_TDES64_Encryption
 * @brief	one block Triple DES Encryption
 *
 * @param	cipherText	[out]encrypted text
 * @param	plainText	[in]plain text
 * @param	UserKey		[in]user key
 *
 * @return	CRYPTO_SUCCESS if success
 */
CRYPTOCORE_INTERNAL int SDRM_TDES64_Encryption(cc_u8 *cipherText, cc_u8 *plainText, cc_u8 *UserKey)
{
	cc_u32 RoundKey[48][2];

	SDRM_TDES_KeySched((cc_u8*)RoundKey, UserKey, 16, 1);

	SDRM_TDES_Encryption(RoundKey, plainText, cipherText);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_TDES64_Decryption
 * @brief	one block Triple DES Decryption
 *
 * @param	plainText	[out]decrypted text
 * @param	cipherText	[in]cipher text
 * @param	UserKey		[in]user key
 *
 * @return	CRYPTO_SUCCESS if success
 */
CRYPTOCORE_INTERNAL int SDRM_TDES64_Decryption(cc_u8 *plainText, cc_u8 *cipherText, cc_u8 *UserKey)
{
	cc_u32 RoundKey[48][2];

	SDRM_TDES_KeySched((cc_u8*)RoundKey, UserKey, 16, (cc_u32)-1);

	SDRM_TDES_Encryption(RoundKey, cipherText, plainText);

	return CRYPTO_SUCCESS;
}

/***************************** End of File *****************************/
