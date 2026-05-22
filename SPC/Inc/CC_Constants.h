/**
 * \file	CC_Constants.h
 * @brief	define constants for crypto library
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon, Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/09/28
 * $Id$
 */

#ifndef _DRM_CONSTANTS_H
#define _DRM_CONSTANTS_H

#define SDRM_SHIFT_HALF		16			/**<	common value at both of 32-bit and 64-bit machine	*/
#define SDRM_HIGH_HALF(A)	((A) >> SDRM_SHIFT_HALF)
#define SDRM_LOW_HALF(A)	((A) & ((1 << SDRM_SHIFT_HALF) - 1))

////////////////////////////////////////////////////////////////////////////
// Algorithm Identifier
////////////////////////////////////////////////////////////////////////////
enum CryptoAlgorithm {
	/*!	@brief	RNG Module	*/
	ID_X931								= 1011,

	/*!	@brief	Hash Algorithms	*/
	ID_MD5								= 1021,
	ID_SHA1								= 1022,
	ID_SHA160							= 1022,
	ID_SHA256							= 1023,
#ifndef _OP64_NOTSUPPORTED
	ID_SHA384							= 1024,
	ID_SHA512							= 1025,
#endif //_OP64_NOTSUPPORTED
	ID_SHA224							= 1026,

	/*!	@brief	MAC Algorithms	*/
	ID_CMAC								= 1031,
	ID_HMD5								= 1032,
	ID_HSHA1							= 1033,
	ID_HSHA160							= 1033,
	ID_HSHA256							= 1034,
#ifndef _OP64_NOTSUPPORTED
	ID_HSHA384							= 1035,
	ID_HSHA512							= 1036,
#endif //_OP64_NOTSUPPORTED
	ID_HSHA224							= 1037,

	/*!	@brief	Symmetric Encryption Algorithms	*/
	ID_AES								= 1041,
	ID_AES128							= 1041,
	ID_AES192							= 1047,
	ID_AES256							= 1048,
	ID_DES								= 1042,
	ID_TDES								= 1043,
	ID_TDES_EDE2						= 1043,
	ID_TDES_EDE3						= 1044,
	ID_RC4								= 1045,
	ID_SNOW2							= 1046,

	/*!	@brief	Asymmetric Encryption Algorithms	*/
	ID_RSA								= 1051,
	ID_RSA512							= 1057,
	ID_RSA1024							= 1054,
	ID_RSA2048							= 1055,
	ID_RSA3072							= 1056,
	ID_ELGAMAL							= 1052,
	ID_ECELGAMAL						= 1053,

	/*!	@brief	Signature Algorithms	*/
	ID_DSA								= 1061,
	ID_ECDSA							= 1062,

	/*!	@brief	Key Exchange Algorithms	*/
	ID_DH								= 1071,
	ID_ECDH								= 1072,

	/*!	@brief	Encryption/Decryption Mode of Operations	*/
	ID_ENC_ECB							= 1111,
	ID_ENC_CBC							= 1112,
	ID_ENC_CFB							= 1113,
	ID_ENC_OFB							= 1114,
	ID_ENC_CTR							= 1115,

	ID_DEC_ECB							= 1121,
	ID_DEC_CBC							= 1122,
	ID_DEC_CFB							= 1123,
	ID_DEC_OFB							= 1124,
	ID_DEC_CTR							= 1125,

	/*!	@brief	Symmetric Encryption/Decryption Padding Methods		*/
	ID_PKCS5							= 1201,
	ID_SSL_PADDING						= 1202,
	ID_ZERO_PADDING						= 1203,
	ID_NO_PADDING						= 1204,

	/*!	@brief	Asymmetric Encryption/Decryption Padding Methods	*/
	ID_RSAES_PKCS15						= 1131,

	ID_RSAES_OAEP						= 1132,
	ID_RSAES_OAEP_MD5					= ID_RSAES_OAEP + (ID_MD5 << SDRM_SHIFT_HALF),
	ID_RSAES_OAEP_SHA1					= ID_RSAES_OAEP + (ID_SHA1 << SDRM_SHIFT_HALF),
	ID_RSAES_OAEP_SHA160				= ID_RSAES_OAEP + (ID_SHA160 << SDRM_SHIFT_HALF),
	ID_RSAES_OAEP_SHA256				= ID_RSAES_OAEP + (ID_SHA256 << SDRM_SHIFT_HALF),
#ifndef _OP64_NOTSUPPORTED
	ID_RSAES_OAEP_SHA384				= ID_RSAES_OAEP + (ID_SHA384 << SDRM_SHIFT_HALF),
	ID_RSAES_OAEP_SHA512				= ID_RSAES_OAEP + (ID_SHA512 << SDRM_SHIFT_HALF),
#endif

	ID_RSASSA_PKCS15					= 1133,
	ID_RSASSA_PKCS15_MD5				= ID_RSASSA_PKCS15 + (ID_MD5 << SDRM_SHIFT_HALF),
	ID_RSASSA_PKCS15_SHA1				= ID_RSASSA_PKCS15 + (ID_SHA1 << SDRM_SHIFT_HALF),
	ID_RSASSA_PKCS15_SHA160				= ID_RSASSA_PKCS15 + (ID_SHA160 << SDRM_SHIFT_HALF),
	ID_RSASSA_PKCS15_SHA256				= ID_RSASSA_PKCS15 + (ID_SHA256 << SDRM_SHIFT_HALF),
#ifndef _OP64_NOTSUPPORTED
	ID_RSASSA_PKCS15_SHA384				= ID_RSASSA_PKCS15 + (ID_SHA384 << SDRM_SHIFT_HALF),
	ID_RSASSA_PKCS15_SHA512				= ID_RSASSA_PKCS15 + (ID_SHA512 << SDRM_SHIFT_HALF),
#endif

	ID_RSASSA_PSS						= 1134,
	ID_RSASSA_PSS_MD5					= ID_RSASSA_PSS + (ID_MD5 << SDRM_SHIFT_HALF),
	ID_RSASSA_PSS_SHA1					= ID_RSASSA_PSS + (ID_SHA1 << SDRM_SHIFT_HALF),
	ID_RSASSA_PSS_SHA160				= ID_RSASSA_PSS + (ID_SHA160 << SDRM_SHIFT_HALF),
	ID_RSASSA_PSS_SHA256				= ID_RSASSA_PSS + (ID_SHA256 << SDRM_SHIFT_HALF),
#ifndef _OP64_NOTSUPPORTED
	ID_RSASSA_PSS_SHA384				= ID_RSASSA_PSS + (ID_SHA384 << SDRM_SHIFT_HALF),
	ID_RSASSA_PSS_SHA512				= ID_RSASSA_PSS + (ID_SHA512 << SDRM_SHIFT_HALF)
#endif
};

////////////////////////////////////////////////////////////////////////////
// Constants Definitions
////////////////////////////////////////////////////////////////////////////
/*!	@brief	Endianness	*/
#define CRYPTO_LITTLE_ENDIAN			0
#define CRYPTO_BIG_ENDIAN				1

////////////////////////////////////////////////////////////////////////////
// Crypto Error Code
////////////////////////////////////////////////////////////////////////////
#define CRYPTO_SUCCESS					0				/**<	no error is occured	*/
#define CRYPTO_ERROR					-3000			/**<	error is occured	*/
#define CRYPTO_MEMORY_ALLOC_FAIL		-3001			/**<	malloc is failed	*/
#define CRYPTO_NULL_POINTER				-3002			/**<	parameter is null pointer	*/
#define CRYPTO_INVALID_ARGUMENT			-3003			/**<	argument is not correct	*/
#define CRYPTO_MSG_TOO_LONG				-3004			/**<	length of input message is too long	*/
#define CRYPTO_VALID_SIGN				CRYPTO_SUCCESS	/**<	valid sign	*/
#define CRYPTO_INVALID_SIGN				-3011			/**<	invalid sign	*/
#define CRYPTO_ISPRIME					CRYPTO_SUCCESS	/**<	prime number	*/
#define CRYPTO_INVERSE_NOT_EXIST		-3012			/**<	inverse is no exists	*/
#define CRYPTO_NEGATIVE_INPUT			-3013			/**<	argument is negative	*/
#define CRYPTO_INFINITY_INPUT			-3014			/**<	input is infinity	*/
#define CRYPTO_BUFFER_TOO_SMALL			-3015			/**<	buffer to small	*/

#endif

/***************************** End of File *****************************/
