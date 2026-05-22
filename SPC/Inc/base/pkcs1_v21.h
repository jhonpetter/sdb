/**
 * \file	pkcs1_v21.h
 * @brief	PKCS#1 V1.5, V2.0(RSAES-OAEP), V2.1(RSASSA-PSS) Implemetation
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/11/20
 */

#ifndef _PKCS1_V21_H
#define _PKCS1_V21_H

//////////////////////////////////////////////////////////////////////////
// Include Header Files
//////////////////////////////////////////////////////////////////////////
#include <stdlib.h>
#include "CryptoCore.h"
#include "bignum.h"

//////////////////////////////////////////////////////////////////////////
// Define Constants
//////////////////////////////////////////////////////////////////////////
/*!	@brief	padding mode - enpadding	*/
#define SDRM_ENPADDING		11111
/*!	@brief	padding mode - depadding	*/
#define SDRM_DEPADDING		11112

/*!	@brief	DER message	*/
#define SDRM_DIGESTINFO_MD5_VALUE			{0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x40, 0x10}
#define SDRM_DIGESTINFO_SHA1_VALUE			{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}
#define SDRM_DIGESTINFO_SHA256_VALUE		{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
#define SDRM_DIGESTINFO_SHA384_VALUE		{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30}
#define SDRM_DIGESTINFO_SHA512_VALUE		{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40}

/*!	@brief	byte-length of DER message	*/
#define SDRM_DIGESTINFO_MD5_LEN				18
#define SDRM_DIGESTINFO_SHA1_LEN			15
#define SDRM_DIGESTINFO_SHA256_LEN			19
#define SDRM_DIGESTINFO_SHA384_LEN			19
#define SDRM_DIGESTINFO_SHA512_LEN			19

#define SDRM_EMSA_PSS_SALT_LEN				4

//////////////////////////////////////////////////////////////////////////
// Function Prototypes
//////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @fn		int SDRM_Padding_Rsaes_pkcs15(SDRM_BIG_NUM* BN_Dest, SDRM_BIG_NUM* BN_Src, int MODE, cc_u32 k)
 * @brief	RSAES PKCS#1 v1.5
 *
 * @param	BN_Dest					[out]Padded msg if MODE is ENPADDING, Depadded msg if MODE is DEPADDING
 * @param	BN_Src					[in]Message to pad if MODE is ENPADDING, Message to depad if MODE is DEPADDING
 * @param	MODE					[in]ENPADDING or DEPADDING
 * @param	k						[in]byte-size of n
 *
 * @return	CRYPTO_SUCCESS			if no error is occured
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if malloc is failed
 * \n		CRYPTO_MSG_TOO_LONG		if message is longer then key
 * \n		CRYPTO_NULL_POINTER		if argument is null
 */
CRYPTOCORE_INTERNAL int SDRM_Padding_Rsaes_pkcs15(SDRM_BIG_NUM* BN_Dest, SDRM_BIG_NUM* BN_Src, int MODE, cc_u32 k);

/*
 * @fn		int SDRM_Padding_Rsaes_oaep(SDRM_BIG_NUM* BN_Dest, SDRM_BIG_NUM* BN_Src, int MODE, int HASH_Algorithm, cc_u32 k)
 * @brief	RSAES OAEP
 *
 * @param	BN_Dest					[out]Padded msg if MODE is ENPADDING, Depadded msg if MODE is DEPADDING
 * @param	BN_Src					[in]Message to pad if MODE is ENPADDING, Message to depad if MODE is DEPADDING
 * @param	MODE					[in]ENPADDING or DEPADDING
 * @param	k						[in]byte-size of n
 *
 * @return	CRYPTO_SUCCESS			if no error is occured
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if malloc is failed
 * \n		CRYPTO_MSG_TOO_LONG		if message is longer then key
 * \n		CRYPTO_NULL_POINTER		if argument is null
 */
CRYPTOCORE_INTERNAL int SDRM_Padding_Rsaes_oaep(SDRM_BIG_NUM* BN_Dest, SDRM_BIG_NUM* BN_Src, int MODE, int HASH_Algorithm, cc_u32 k);

/*
 * @fn		int SDRM_Padding_Rsassa_pkcs15(SDRM_BIG_NUM* BN_Dest, SDRM_BIG_NUM* BN_Src, cc_u8 *pszHash, int MODE, int HASH_Algorithm, cc_u32 k);
 * @brief	RSASSA PKCS#1 v1.5
 *
 * @param	BN_Dest					[out]Padded msg if MODE is ENPADDING, Depadded msg if MODE is DEPADDING
 * @param	BN_Src					[in]Message to pad if MODE is ENPADDING, Message to depad if MODE is DEPADDING
 * @param	pszHash					[in]hash of BN_Src
 * @param	MODE					[in]ENPADDING or DEPADDING
 * @param	k						[in]byte-size of n
 *
 * @return	CRYPTO_SUCCESS			if no error is occured
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if malloc is failed
 * \n		CRYPTO_MSG_TOO_LONG		if message is longer then key
 * \n		CRYPTO_INVALID_ARGUMENT	if source is not in the right form
 */
CRYPTOCORE_INTERNAL int SDRM_Padding_Rsassa_pkcs15(SDRM_BIG_NUM* BN_Dest, SDRM_BIG_NUM* BN_Src, cc_u8 *pszHash, int MODE, int HASH_Algorithm, cc_u32 k);

/*
 * @fn		int SDRM_Padding_Rsassa_pss(SDRM_BIG_NUM* BN_Dest, SDRM_BIG_NUM* BN_Src, cc_u8 *pszHash, cc_u32 emBits, int MODE, int HASH_Algorithm, cc_u32 MaxByte)
 * @brief	RSASSA PSS
 *
 * @param	BN_Dest					[out]Padded msg if MODE is ENPADDING, Depadded msg if MODE is DEPADDING
 * @param	BN_Src					[in]Message to pad if MODE is ENPADDING, Message to depad if MODE is DEPADDING
 * @param	pszHash					[in]hash of BN_Src
 * @param	emBits					[in]bit-length of EM
 * @param	MODE					[in]ENPADDING or DEPADDING
 * @param	MaxByte					[in]max byte-length for MGF function
 *
 * @return	CRYPTO_SUCCESS			if no error is occured
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if malloc is failed
 * \n		CRYPTO_MSG_TOO_LONG		if message is longer then key
 * \n		CRYPTO_INVALID_ARGUMENT	if source is not in the right form
 */
CRYPTOCORE_INTERNAL int SDRM_Padding_Rsassa_pss(SDRM_BIG_NUM* BN_Dest, SDRM_BIG_NUM* BN_Src, cc_u8 *pszHash, cc_u32 emBits, int MODE, int HASH_Algorithm, cc_u32 MaxByte);

/*
 * @fn		int SDRM_MGF1(int HASH_Algorithm, cc_u8* mask, cc_u8* pbSeed, cc_u32 SeedLen, cc_u32 dMaskLen)
 * @brief	MGF1 Function (Mask Generation Function based on a hash function)
 *
 * @param	mask					[out]byte-length of generated mask
 * @param	pbSeed					[in]seed for MGF
 * @param	SeedLen					[in]byte-length of pbSeed
 * @param	dMaskLen				[in]byte-length of mask
 *
 * @return	CRYPTO_SUCCESS			if no error is occured
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if malloc is failed
 */
CRYPTOCORE_INTERNAL int SDRM_MGF1(int HASH_Algorithm, cc_u8* mask, cc_u8* pbSeed, cc_u32 SeedLen, cc_u32 dMaskLen);

#ifdef __cplusplus
}
#endif

#endif

/***************************** End of File *****************************/
