/**
 * \file	ecdsa.h
 * @brief	implementation of public key signature algorithm
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/11/13
 */

#ifndef _ECDSA_H
#define _ECDSA_H

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include "CC_API.h"
#include "ecc.h"

////////////////////////////////////////////////////////////////////////////
// Function Prototypes
////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @fn		int SDRM_ECDSA_sign(CryptoCoreContainer *crt, cc_u8 *hash, cc_u32 hashLen, cc_u8 *signature, cc_u32 *signLen)
 * @brief	generate signature for given value
 *
 * @param	crt					[in]crypto env structure
 * @param	hash				[in]hash value
 * @param	hashLen				[in]byte-length of hash
 * @param	signature			[out]generated signature
 * @param	signLen				[out]byte-length of signature
 *
 * @return	CRYPTO_SUCCESS		if success
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_ECDSA_sign(CryptoCoreContainer *crt, cc_u8 *hash, cc_u32 hashLen, cc_u8 *signature, cc_u32 *signLen);

/*
 * @fn		int SDRM_ECDSA_verify(CryptoCoreContainer *crt, cc_u8 *hash, cc_u32 hashLen, cc_u8 *signature, cc_u32 signLen, int *result)
 * @brief	generate signature for given value
 *
 * @param	crt						[in]crypto env structure
 * @param	hash					[in]hash value
 * @param	hashLen					[in]byte-length of hash
 * @param	signature				[in]signature
 * @param	signLen					[in]byte-length of signature
 * @param	result					[in]result of veryfing signature
 *
 * @return	CRYPTO_SUCCESS			if success
 * \n		CRYPTO_NULL_POINTER		if given argument is a null pointer
 * \n		CRYPTO_INVALID_ARGUMENT	if the length of signature is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_ECDSA_verify(CryptoCoreContainer *crt, cc_u8 *hash, cc_u32 hashLen, cc_u8 *signature, cc_u32 signLen, int *result);

/*
 * @fn		SDRM_ECC_Set_CTX
 * @brief	Set parameters for ECC
 *
 * @param	crt					[out]crypto env structure
 * @param	Dimension			[in]dimension
 * @param	ECC_P_Data			[in]represents p
 * @param	ECC_P_Len			[in]byte-length of p
 * @param	ECC_A_Data			[in]represents a
 * @param	ECC_A_Len			[in]byte-length of a
 * @param	ECC_B_Data			[in]represents b
 * @param	ECC_B_Len			[in]byte-length of b
 * @param	ECC_G_X_Data		[in]represents x coordinate of g
 * @param	ECC_G_X_Len			[in]byte-length of x coordinate of g
 * @param	ECC_G_Y_Data		[in]represents y coordinate of g
 * @param	ECC_G_Y_Len			[in]byte-length of y coordinate of g
 * @param	ECC_R_Data			[in]represents r
 * @param	ECC_R_Len			[in]byte-length of r
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if argument is null
 */
CRYPTOCORE_INTERNAL int SDRM_ECC_Set_CTX(
	struct _CryptoCoreContainer *crt, cc_u16 Dimension, 
	cc_u8* ECC_P_Data,   cc_u32 ECC_P_Len,
	cc_u8* ECC_A_Data,   cc_u32 ECC_A_Len,
	cc_u8* ECC_B_Data,   cc_u32 ECC_B_Len,
	cc_u8* ECC_G_X_Data, cc_u32 ECC_G_X_Len,
	cc_u8* ECC_G_Y_Data, cc_u32 ECC_G_Y_Len,
	cc_u8* ECC_R_Data,   cc_u32 ECC_R_Len
);

/*
 * @fn		SDRM_ECC_genKeypair
 * @brief	Generate Private Key and Generate Key Pair for ECC Signature
 *
 * @param	crt					[out]crypto env structure
 * @param	PrivateKey			[in]represents x coordinate of public key
 * @param	PrivateKeyLen		[in]byte-length of x coordinate of public key
 * @param	PublicKey_X			[in]represents x coordinate of public key
 * @param	PublicKey_XLen		[in]byte-length of x coordinate of public key
 * @param	PublicKey_Y			[in]represents y coordinate of public key
 * @param	PublicKey_YLen		[in]byte-length of y coordinate of public key
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if argument is null
 */
CRYPTOCORE_INTERNAL int SDRM_ECC_genKeypair(
	CryptoCoreContainer *crt,
	cc_u8 *PrivateKey,  cc_u32 *PrivateKeyLen, 
	cc_u8 *PublicKey_X, cc_u32 *PublicKey_XLen,
	cc_u8 *PublicKey_Y, cc_u32 *PublicKey_YLen
);
												
/*
 * @fn		SDRM_ECC_setKeypair
 * @brief	Set key data for ECC
 *
 * @param	crt					[out]crypto env structure
 * @param	PRIV_Data			[in]represents private key
 * @param	PRIV_Len			[in]byte-length of private key
 * @param	PUB_X_Data			[in]represents x coordinate of public key
 * @param	PUB_X_Len			[in]byte-length of x coordinate of public key
 * @param	PUB_Y_Data			[in]represents y coordinate of public key
 * @param	PUB_Y_Len			[in]byte-length of y coordinate of public key
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if argument is null
 */
CRYPTOCORE_INTERNAL int SDRM_ECC_setKeypair(
	CryptoCoreContainer *crt,
	cc_u8* PRIV_Data,  cc_u32 PRIV_Len,
	cc_u8* PUB_X_Data, cc_u32 PUB_X_Len,
	cc_u8* PUB_Y_Data, cc_u32 PUB_Y_Len
);

#ifdef __cplusplus
}
#endif

#endif

/***************************** End of File *****************************/
