/**
 * \file	dsa.h
 * @brief	implementation of dsa signature/verifycation
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/11/23
 */

#ifndef _DSA_H
#define _DSA_H

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include "CC_API.h"

////////////////////////////////////////////////////////////////////////////
// Function Prototypes
////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @fn		SDRM_DSAContext *SDRM_DSA_InitCrt(void)
 * @brief	generate DSA Context
 *
 * @return	pointer to the generated context
 * \n		NULL	if memory allocation is failed
 */
CRYPTOCORE_INTERNAL SDRM_DSAContext *SDRM_DSA_InitCrt(void);

/*
 * @fn		int SDRM_DSA_SetParam(CryptoCoreContainer *crt, cc_u8 *DSA_P_Data,	cc_u32 DSA_P_Len, cc_u8 *DSA_Q_Data,	cc_u32 DSA_Q_Len, cc_u8 *DSA_G_Data,	cc_u32 DSA_G_Len)
 * @brief	set DSA parameters
 *
 * @param	crt							[out]dsa context
 * @param	DSA_P_Data					[in]octet string of p value
 * @param	DSA_P_Len					[in]legnth of p_val
 * @param	DSA_Q_Data					[in]octet string of q value
 * @param	DSA_Q_Len					[in]legnth of q_val
 * @param	DSA_G_Data					[in]octet string of al value
 * @param	DSA_G_Len					[in]legnth of al_val
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_NULL_POINTER			if input parameter pointer is null
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 * \n		CRYPTO_ERROR				if conversion is failed
 */
CRYPTOCORE_INTERNAL int SDRM_DSA_SetParam(
	CryptoCoreContainer *crt, 
	cc_u8 *DSA_P_Data,	cc_u32 DSA_P_Len, 
	cc_u8 *DSA_Q_Data,	cc_u32 DSA_Q_Len, 
	cc_u8 *DSA_G_Data,	cc_u32 DSA_G_Len);

/*
 * @fn		int SDRM_DSA_SetKeyPair(CryptoCoreContainer *crt, cc_u8 *DSA_Y_Data, cc_u32 DSA_Y_Len, cc_u8 *DSA_X_Data, cc_u32 DSA_X_Len)
 * @brief	set DSA parameters
 *
 * @param	crt							[out]dsa context
 * @param	DSA_Y_Data					[in]octet string of y value
 * @param	DSA_Y_Len					[in]legnth of y_val
 * @param	DSA_X_Data					[in]octet string of a value
 * @param	DSA_X_Len					[in]legnth of a_val
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_NULL_POINTER			if input parameter pointer is null
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 * \n		CRYPTO_ERROR				if conversion is failed
 */
CRYPTOCORE_INTERNAL int SDRM_DSA_SetKeyPair(
	CryptoCoreContainer *crt, 
	cc_u8 *DSA_Y_Data, cc_u32 DSA_Y_Len, 
	cc_u8 *DSA_X_Data, cc_u32 DSA_X_Len);

/*
 * @fn		int SDRM_DSA_GenParam(CryptoCoreContainer *crt, cc_u32 T_Siz, cc_u8 *DSA_P_Data, cc_u32 *DSA_P_Len, cc_u8 *DSA_Q_Data, cc_u32 *DSA_Q_Len, cc_u8 *DSA_G_Data, cc_u32 *DSA_G_Len)
 * @brief	generate and set DSA parameters
 *
 * @param	crt							[out]dsa context
 * @param	T_Siz						[in]fix the length of p to 512 + 64t bit (0 <= T_Siz <= 8)
 * @param	DSA_P_Data					[out]octet string of p value
 * @param	DSA_P_Len					[out]legnth of p_val
 * @param	DSA_Q_Data					[out]octet string of q value
 * @param	DSA_Q_Len					[out]legnth of q_val
 * @param	DSA_G_Data					[out]octet string of al value
 * @param	DSA_G_Len					[out]legnth of al_val
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_NULL_POINTER			if input parameter pointer is null
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 * \n		CRYPTO_ERROR				if conversion is failed
 */
CRYPTOCORE_INTERNAL int SDRM_DSA_GenParam(
	CryptoCoreContainer *crt, 
	cc_u32 T_Siz, cc_u8 *DSA_P_Data, cc_u32 *DSA_P_Len, 
	cc_u8 *DSA_Q_Data, cc_u32 *DSA_Q_Len, 
	cc_u8 *DSA_G_Data, cc_u32 *DSA_G_Len);

/*
 * @fn		int SDRM_DSA_GenKeypair(CryptoCoreContainer *crt, cc_u8 *DSA_Y_Data, cc_u32 *DSA_Y_Len, cc_u8 *DSA_X_Data, cc_u32 *DSA_X_Len)
 * @brief	generate and set DSA parameters
 *
 * @param	crt							[out]dsa context
 * @param	DSA_Y_Data					[out]octet string of y value
 * @param	DSA_Y_Len					[out]legnth of y_val
 * @param	DSA_X_Data					[out]octet string of a value
 * @param	DSA_X_Len					[out]legnth of a_val
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_NULL_POINTER			if input parameter pointer is null
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 * \n		CRYPTO_ERROR				if conversion is failed
 */
CRYPTOCORE_INTERNAL int SDRM_DSA_GenKeypair(
	CryptoCoreContainer *crt, 
	cc_u8 *DSA_Y_Data, cc_u32 *DSA_Y_Len, 
	cc_u8 *DSA_X_Data, cc_u32 *DSA_X_Len);

/*
 * @fn		int SDRM_DSA_sign(CryptoCoreContainer *crt, cc_u8 *hash, cc_u32 hashLen, cc_u8 *signature, cc_u32 *signLen)
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
CRYPTOCORE_INTERNAL int SDRM_DSA_sign(
	CryptoCoreContainer *crt,
	cc_u8 *hash, cc_u32 hashLen,
	cc_u8 *signature, cc_u32 *signLen);

/*
 * @fn		int SDRM_DSA_verify(CryptoCoreContainer *crt,cc_u8 *hash, cc_u32 hashLen,cc_u8 *signature, cc_u32 signLen,int *result)
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
CRYPTOCORE_INTERNAL int SDRM_DSA_verify(
	CryptoCoreContainer *crt,
	cc_u8 *hash, cc_u32 hashLen,
	cc_u8 *signature, cc_u32 signLen,
	int *result);

#ifdef __cplusplus
}
#endif

#endif // _DSA_H

/***************************** End of File *****************************/
