/**
 * \file	des.c
 * @brief	high-speed implementation of DES
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
#include "des.h"

////////////////////////////////////////////////////////////////////////////
// Functions
////////////////////////////////////////////////////////////////////////////
/*
 * @fn		SDRM_DES_KeySched
 * @brief	Expand the cipher key into the encryption key schedule
 *
 * @param	RoundKey			[out]generated round key
 * @param	UserKey				[in]user key, 8 byte
 * @param	RKPos				[in]index of round key starts
 * @param	RKStep				[in]step for index
 *
 * @return	the number of rounds for the given cipher key size
 */
CRYPTOCORE_INTERNAL int SDRM_DES_KeySched(cc_u8 *RoundKey, cc_u8 *UserKey, cc_u32 RKPos, cc_u32 RKStep)
{
	cc_u32	round, i, s, t, t2;
	cc_u32	roundkey[16][2];
	cc_u32	c = 0, d = 0;

	//process Permuted Choice 1
	for (i = 0; i < 28; i++)
	{
		t = SDRM_DES_KS_PC1[i];
		c |= (UserKey[t >> 3] & SDRM_DES_BitMask[t & 0x07]) ? (1 << i) : 0;
	}

	for (i = 28; i < 56; i++)
	{
		t = SDRM_DES_KS_PC1[i];
		d |= (UserKey[t >> 3] & SDRM_DES_BitMask[t & 0x07]) ? (1 << (i - 28)) : 0;
	}

	//get round key
	for (round = 0; round < SDRM_DES_NUM_OF_ROUNDS; round++)
	{
		//shift left operation
		c = (c >> SDRM_DES_KS_SHIFT[round]) | (c << (28 - SDRM_DES_KS_SHIFT[round]));
		d = (d >> SDRM_DES_KS_SHIFT[round]) | (d << (28 - SDRM_DES_KS_SHIFT[round]));

		s =	SDRM_des_skb[0][((c)	  ) & 0x3f] | 
			SDRM_des_skb[1][((c >>  6L) & 0x03) | ((c >>  7L) & 0x3c)] |
			SDRM_des_skb[2][((c >> 13L) & 0x0f) | ((c >> 14L) & 0x30)] |
			SDRM_des_skb[3][((c >> 20L) & 0x01) | ((c >> 21L) & 0x06)  | ((c>>22L)&0x38)];
		t =	SDRM_des_skb[4][((d)	  ) & 0x3f] |
			SDRM_des_skb[5][((d >>  7L) & 0x03) | ((d >>  8L) & 0x3c)] |
			SDRM_des_skb[6][ (d >> 15L) & 0x3f] |
			SDRM_des_skb[7][((d >> 21L) & 0x0f) | ((d >> 22L) & 0x30)];

		t2 = (t << 16L) | (s & 0x0000ffffL);
		roundkey[RKPos][0] = SDRM_rotr32(t2, 30);

		t2 = ((s >> 16L) | (t & 0xffff0000L));
		roundkey[RKPos][1] = SDRM_rotr32(t2, 26);

		RKPos += RKStep;
	}

	memcpy(RoundKey, roundkey, 128);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_DES_Encryption
 * @brief	DES processing for one block
 *
 * @param	RoundKey			[in]expanded round key
 * @param	msg					[in]8 byte plaintext
 * @param	out					[out]8 byte ciphertext
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 */
CRYPTOCORE_INTERNAL int SDRM_DES_Encryption(cc_u32 RoundKey[][2], cc_u8 *msg, cc_u8 *out)
{
	cc_u32	l, r, i, t, u;

	r = *(cc_u32*)(void*)(msg);
	l = *(cc_u32*)(void*)(msg + 4);

	SDRM_IP(r,l);

	r = SDRM_rotr32(r, 29);
	l = SDRM_rotr32(l, 29);

	for (i = 0; i < SDRM_DES_NUM_OF_ROUNDS; i++)
	{
		if (i & 0x01)
		{
			SDRM_D_ENCRYPT(r, l);
		}
		else
		{
			SDRM_D_ENCRYPT(l, r);
		}
	}

	r = SDRM_rotr32(r, 3);
	l = SDRM_rotr32(l, 3);

	SDRM_INV_IP(r, l);

	memcpy(out	  , &l, 4);
	memcpy(out + 4, &r, 4);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_DES64_Encryption
 * @brief	one block DES Encryption
 *
 * @param	cipherText	[out]encrypted text
 * @param	plainText	[in]plain text
 * @param	UserKey		[in]user key
 *
 * @return	CRYPTO_SUCCESS if success
 */
CRYPTOCORE_INTERNAL int SDRM_DES64_Encryption(cc_u8 *cipherText, cc_u8 *plainText, cc_u8 *UserKey)
{
	cc_u32 RoundKey[16][2];

	SDRM_DES_KeySched((cc_u8*)RoundKey, UserKey, 0, 1);

	SDRM_DES_Encryption(RoundKey, plainText, cipherText);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_DES64_Decryption
 * @brief	one block DES Decryption
 *
 * @param	plainText	[out]decrypted text
 * @param	cipherText	[in]cipher text
 * @param	UserKey		[in]user key
 *
 * @return	CRYPTO_SUCCESS if success
 */
CRYPTOCORE_INTERNAL int SDRM_DES64_Decryption(cc_u8 *plainText, cc_u8 *cipherText, cc_u8 *UserKey)
{
	cc_u32 RoundKey[16][2];

	SDRM_DES_KeySched((cc_u8*)RoundKey, UserKey, 15, (cc_u32)-1);

	SDRM_DES_Encryption(RoundKey, cipherText, plainText);

	return CRYPTO_SUCCESS;
}

/***************************** End of File *****************************/
