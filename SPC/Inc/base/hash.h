/**
 * \file	hash.h
 * @brief	hash API function
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/11/08
 */

#ifndef _HASH_H
#define _HASH_H

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
 * @fn		SDRM_SHA1_init
 * @brief	initialize CryptoCoreContainer context
 *
 * @param	crt					[out]CryptoCoreContainer context
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA1_init(CryptoCoreContainer *crt);

/*
 * @fn		SDRM_SHA1_update
 * @brief	process a message block
 *
 * @param	crt					[out]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA1_update(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen);

/*
 * @fn		SDRM_SHA1_final
 * @brief	get hashed message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA1_final(CryptoCoreContainer *crt, cc_u8 *output);

/*
 * @fn		SDRM_SHA1_hash
 * @brief	get hashed message from message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA1_hash(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen, cc_u8 *output);

/*
 * @fn		SDRM_SHA224_init
 * @brief	initialize CryptoCoreContainer context
 *
 * @param	crt					[out]CryptoCoreContainer context
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA224_init(CryptoCoreContainer *crt);


/*
 * @fn		SDRM_SHA224_update
 * @brief	process a message block
 *
 * @param	crt					[out]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA224_update(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen);

/*
 * @fn		SDRM_SHA224_final
 * @brief	get hashed message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA224_final(CryptoCoreContainer *crt, cc_u8 *output);

/*
 * @fn		SDRM_SHA224_hash
 * @brief	get hashed message from message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA224_hash(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen, cc_u8 *output);

/*
 * @fn		SDRM_SHA256_init
 * @brief	initialize CryptoCoreContainer context
 *
 * @param	crt					[out]CryptoCoreContainer context
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA256_init(CryptoCoreContainer *crt);


/*
 * @fn		SDRM_SHA256_update
 * @brief	process a message block
 *
 * @param	crt					[out]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA256_update(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen);

/*
 * @fn		SDRM_SHA256_final
 * @brief	get hashed message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA256_final(CryptoCoreContainer *crt, cc_u8 *output);

/*
 * @fn		SDRM_SHA256_hash
 * @brief	get hashed message from message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA256_hash(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen, cc_u8 *output);

/*
 * @fn		SDRM_SHA384_init
 * @brief	initialize CryptoCoreContainer context
 *
 * @param	crt					[out]CryptoCoreContainer context
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA384_init(CryptoCoreContainer *crt);

/*
 * @fn		SDRM_SHA384_update
 * @brief	process a message block
 *
 * @param	crt					[out]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA384_update(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen);

/*
 * @fn		SDRM_SHA384_final
 * @brief	get hashed message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA384_final(CryptoCoreContainer *crt, cc_u8 *output);

/*
 * @fn		SDRM_SHA384_hash
 * @brief	get hashed message from message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA384_hash(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen, cc_u8 *output);

/*
 * @fn		SDRM_SHA512_init
 * @brief	initialize CryptoCoreContainer context
 *
 * @param	crt					[out]CryptoCoreContainer context
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA512_init(CryptoCoreContainer *crt);

/*
 * @fn		SDRM_SHA512_update
 * @brief	process a message block
 *
 * @param	crt					[out]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA512_update(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen);

/*
 * @fn		SDRM_SHA512_final
 * @brief	get hashed message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA512_final(CryptoCoreContainer *crt, cc_u8 *output);

/*
 * @fn		SDRM_SHA512_hash
 * @brief	get hashed message from message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_SHA512_hash(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen, cc_u8 *output);

/*
 * @fn		SDRM_MD5_init
 * @brief	initialize CryptoCoreContainer context
 *
 * @param	crt					[out]CryptoCoreContainer context
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_MD5_init(CryptoCoreContainer *crt);

/*
 * @fn		SDRM_MD5_update
 * @brief	process a message block
 *
 * @param	crt					[out]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_MD5_update(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen);

/*	
 * @fn		SDRM_MD5_final
 * @brief	get hashed message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_MD5_final(CryptoCoreContainer *crt, cc_u8 *output);

/*
 * @fn		SDRM_MD5_hash
 * @brief	get hashed message from message
 *
 * @param	crt					[in]CryptoCoreContainer context
 * @param	msg					[in]message
 * @param	msglen				[in]byte-length of msg
 * @param	output				[out]hashed message
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if given argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_MD5_hash(CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen, cc_u8 *output);

#ifdef __cplusplus
}
#endif

#endif

/***************************** End of File *****************************/
