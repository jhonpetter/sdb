/**
 * \file	CC_API.h
 * @brief	API of samsung Crypto Library
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jae Heung Lee
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/11/06
 */

#ifndef _CRYPTOCORE_API_H
#define _CRYPTOCORE_API_H

#include "CryptoCore.h"


typedef union
{
	SDRM_X931Context	*x931ctx;				//RNG : ANSI X9.31 Context
	SDRM_MD5Context		*md5ctx;				//Hash : MD5 Hash Context
	SDRM_SHA1Context	*sha1ctx;				//Hash : SHA1 Hash Context
	SDRM_SHA224Context	*sha224ctx;				//Hash : SHA224 Hash Context
	SDRM_SHA256Context	*sha256ctx;				//Hash : SHA256 Hash Context
#ifndef _OP64_NOTSUPPORTED
	SDRM_SHA384Context	*sha384ctx;				//Hash : SHA384 Hash Context
	SDRM_SHA512Context	*sha512ctx;				//Hash : SHA512 Hash Context
#endif //_OP64_NOTSUPPORTED
	SDRM_CMACContext	*cmacctx;				//MAC : C-MAC Context
	SDRM_HMACContext	*hmacctx;				//MAC : Hash MAC
	SDRM_DHContext		*dhctx;					//Key Exchange : DH Key Exchange Protocol
	SDRM_ECDHContext	*ecdhctx;				//Key Exchange : EC-DH Key Exchange Protocol
	SDRM_AESContext		*aesctx;				//Symmetric Encryption : AES Encryption Context
	SDRM_DESContext		*desctx;				//Symmetric Encryption : DES Encryption Context
	SDRM_TDESContext	*tdesctx;				//Symmetric Encryption : Triple DES Encryption Context
	SDRM_RC4Context		*rc4ctx;				//Symmetric Encryption : RC4 Encryption Context
	SDRM_SNOW2Context	*snow2ctx;				//Symmetric Encryption : SNOW2 Encryption Context
	SDRM_RSAContext		*rsactx;				//Asymmetric Encryption and Signature : RSA Context
	SDRM_DSAContext		*dsactx;				//Digital Signature : DSA Signature Context
	SDRM_ECDSAContext	*ecdsactx;				//Digital Signature : EC-DSA Signature Context
} CryptoCoreCTX;


/**
 * @brief	Parameter sturcture
 *
 * Crypto Library를 쉽게 사용하기 위해  사용하는 Parameter structure
 */
typedef struct _CryptoCoreContainer
{
	int alg;																				/**<	Algorithm	*/
	CryptoCoreCTX *ctx;																		/**<	Algorithm	*/
	
	// Pseudo Random Number Generation (ANSI X9.17)
	int (*PRNG_seed)  (struct _CryptoCoreContainer *crt, cc_u8 *seed);
	int (*PRNG_get)   (struct _CryptoCoreContainer *crt, cc_u32 bitlength, cc_u8 *data);
	
	// Message Digest (MD5, SHA-1)
	int (*MD_init)    (struct _CryptoCoreContainer *crt);
	int (*MD_update)  (struct _CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen);
	int (*MD_final)   (struct _CryptoCoreContainer *crt, cc_u8 *output);
	int (*MD_getHASH) (struct _CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msglen, cc_u8 *output);
	
	// Message Authentication Code (CMAC, HMAC MD5, HMAC SHA-1)
	int (*MAC_init)   (struct _CryptoCoreContainer *crt, cc_u8 *Key, cc_u32 KeyLen);
	int (*MAC_update) (struct _CryptoCoreContainer *crt, cc_u8 *msg, cc_u32 msgLen);
	int (*MAC_final)  (struct _CryptoCoreContainer *crt, cc_u8 *output, cc_u32 *outputLen);
	int (*MAC_getMAC) (struct _CryptoCoreContainer *crt, cc_u8 *Key, cc_u32 KeyLen, cc_u8 *msg, cc_u32 msgLen, cc_u8 *output, cc_u32 *outputLen);

	// Key Exchange (DH, ECDH)
	int (*DH_GenerateParam)		(struct _CryptoCoreContainer *crt, cc_u8* pPrime, cc_u32 nPrimeLen, cc_u8* pGenerator);
	int (*DH_SetParam)			(struct _CryptoCoreContainer *crt, cc_u8* pPrime, cc_u32 nPrimeLen, cc_u8* nGenerator, cc_u32 nGeneratorLen);
	int (*DH_Gen1stPhaseKey)	(struct _CryptoCoreContainer *crt, cc_u8* pPriv, cc_u8* pPub);
	int (*DH_GenAuthKey)		(struct _CryptoCoreContainer *crt, cc_u8* pPriv, cc_u8* pPub, cc_u8* pSharedSecret);
	int (*ECDH_Gen1stPhaseKey)	(struct _CryptoCoreContainer *crt, cc_u8* pDH_Xk, cc_u8* pDH1stPhaseKey);
	int (*ECDH_GenAuthKey)		(struct _CryptoCoreContainer *crt, cc_u8* pchXk, cc_u8* pchYv, cc_u8* pchKauth);
	
	// Symmetric Encryption (DES, 3DES, AES, RC4, SNOW)
	// mode example : ENC_ECB, DEC_ECB, ENC_CBC, DEC_CBC, ...
	int (*SE_init)    (struct _CryptoCoreContainer *crt, cc_u32 mode, cc_u32 PADDING, cc_u8 *key, cc_u32 keysize, cc_u8 *IV);
	int (*SE_process) (struct _CryptoCoreContainer *crt, cc_u8 *in, cc_u32 inLen, cc_u8 *out, cc_u32 *outLen);
	int (*SE_final)   (struct _CryptoCoreContainer *crt, cc_u8 *input, cc_u32 inputLen, cc_u8 *output, cc_u32 *outputLen);
	// Simple AES Function
	int (*SE_EncryptOneBlock)  (cc_u8 *cipherText, cc_u8 *plainText,	cc_u8 *UserKey);
	int (*SE_DecryptOneBlock)  (cc_u8 *plainText, cc_u8 *cipherText,	cc_u8 *UserKey);

	// Asymmetric Encryption (RSA, Elgamal, EC-Elgamal)
	int (*AE_encrypt) (struct _CryptoCoreContainer *crt, cc_u8 *in, cc_u32 inLen, cc_u8 *out, cc_u32 *outLen);
	int (*AE_decrypt) (struct _CryptoCoreContainer *crt, cc_u8 *in, cc_u32 inLen, cc_u8 *out, cc_u32 *outLen);
	int (*AE_decryptByCRT) (struct _CryptoCoreContainer *crt, cc_u8 *in, cc_u32 inLen, cc_u8 *out, cc_u32 *outLen);
	
	// Digital Signature (DSA, EC-DSA)
	int (*DS_sign)    (struct _CryptoCoreContainer *crt, cc_u8 *hash, cc_u32 hashLen, cc_u8 *signature, cc_u32 *signLen);
	int (*DS_verify)  (struct _CryptoCoreContainer *crt, cc_u8 *hash, cc_u32 hashLen, cc_u8 *signature, cc_u32 signLen, int *result);
	int (*DSA_genParam)(
		struct _CryptoCoreContainer *crt, cc_u32 T_Siz,
		cc_u8 *DSA_P_Data, cc_u32 *DSA_P_Len,
		cc_u8 *DSA_Q_Data, cc_u32 *DSA_Q_Len,
		cc_u8 *DSA_G_Data, cc_u32 *DSA_G_Len
	);
	int (*DSA_setParam)(
		struct _CryptoCoreContainer *crt,
		cc_u8 *DSA_P_Data,	cc_u32 DSA_P_Len,
		cc_u8 *DSA_Q_Data,	cc_u32 DSA_Q_Len,
		cc_u8 *DSA_G_Data,	cc_u32 DSA_G_Len
	);
	int (*DSA_genKeypair)(
		struct _CryptoCoreContainer *crt,
		cc_u8 *DSA_Y_Data, cc_u32 *DSA_Y_Len,
		cc_u8 *DSA_X_Data, cc_u32 *DSA_X_Len
	);
	int (*DSA_setKeyPair)(
		struct _CryptoCoreContainer *crt,
		cc_u8 *DSA_Y_Data,	cc_u32 DSA_Y_Len,
		cc_u8 *DSA_X_Data,	cc_u32 DSA_X_Len
	);

	// RSA Support Functions
	int (*RSA_genKeypair)(
		struct _CryptoCoreContainer *crt, cc_u32 PaddingMethod,
		cc_u8* RSA_N_Data,   cc_u32 *RSA_N_Len,
		cc_u8* RSA_E_Data,   cc_u32 *RSA_E_Len,
		cc_u8* RSA_D_Data,   cc_u32 *RSA_D_Len
	);
	int (*RSA_genKeypairWithE)(
		struct _CryptoCoreContainer *crt, cc_u32 PaddingMethod,
		cc_u8* RSA_E_Data,   cc_u32 RSA_E_Len,
		cc_u8* RSA_N_Data,   cc_u32 *RSA_N_Len,
		cc_u8* RSA_D_Data,   cc_u32 *RSA_D_Len
	);
	int (*RSA_genKeyDWithPQE)(
		struct _CryptoCoreContainer *crt, cc_u32 PaddingMethod,
		cc_u8* RSA_E_Data,   cc_u32 RSA_E_Len,
		cc_u8* RSA_P_Data,   cc_u32 RSA_P_Len,
		cc_u8* RSA_Q_Data,   cc_u32 RSA_Q_Len,
		cc_u8* RSA_N_Data,   cc_u32 *RSA_N_Len,
		cc_u8* RSA_D_Data,   cc_u32 *RSA_D_Len
	);
	int (*RSA_setKeypair)(
		struct _CryptoCoreContainer *crt, cc_u32 PaddingMethod,
		cc_u8* RSA_N_Data,   cc_u32 RSA_N_Len,
		cc_u8* RSA_E_Data,   cc_u32 RSA_E_Len,
		cc_u8* RSA_D_Data,   cc_u32 RSA_D_Len
	);
	int (*RSA_setKeypairForCRT)(
		struct _CryptoCoreContainer *crt, cc_u32 PaddingMethod,
		cc_u8* RSA_N_Data,   cc_u32 RSA_N_Len,
		cc_u8* RSA_E_Data,   cc_u32 RSA_E_Len,
		cc_u8* RSA_D_Data,   cc_u32 RSA_D_Len,
		cc_u8* RSA_P_Data,   cc_u32 RSA_P_Len,
		cc_u8* RSA_Q_Data,   cc_u32 RSA_Q_Len,
		cc_u8* RSA_DmodP1_Data,   cc_u32 RSA_DmodP1_Len,
		cc_u8* RSA_DmodQ1_Data,   cc_u32 RSA_DmodQ1_Len,
		cc_u8* RSA_iQmodP_Data,   cc_u32 RSA_iQmodP_Len
	);

	// ECC Support Functions (EC-DSA, EC-Dlgamal)
	int (*EC_setCurve)(
		struct _CryptoCoreContainer *crt, cc_u16 Dimension, 
		cc_u8* ECC_P_Data,   cc_u32 ECC_P_Len,
		cc_u8* ECC_A_Data,   cc_u32 ECC_A_Len,
		cc_u8* ECC_B_Data,   cc_u32 ECC_B_Len,
		cc_u8* ECC_G_X_Data, cc_u32 ECC_G_X_Len,
		cc_u8* ECC_G_Y_Data, cc_u32 ECC_G_Y_Len,
		cc_u8* ECC_R_Data,   cc_u32 ECC_R_Len
	);
	int (*EC_genKeypair)(
		struct _CryptoCoreContainer *crt,
		cc_u8 *PrivateKey,  cc_u32 *PrivateKeyLen, 
		cc_u8 *PublicKey_X, cc_u32 *PublicKey_XLen,
		cc_u8 *PublicKey_Y, cc_u32 *PublicKey_YLen
	);
	int (*EC_setKeypair)(
		struct _CryptoCoreContainer *crt,
		cc_u8* PRIV_Data,  cc_u32 PRIV_Len,
		cc_u8* PUB_X_Data, cc_u32 PUB_X_Len,
		cc_u8* PUB_Y_Data, cc_u32 PUB_Y_Len
	);

} CryptoCoreContainer;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @fn		create_CryptoCoreContainer
 * @brief	memory allocation and initialize the CryptoCoreContainer sturcture
 *
 * @param	algorithm	[in]algorithm want to use
 *
 * @return	address of created sturcture
 */
CRYPTOCORE_INTERNAL CryptoCoreContainer ECRYPTO_API *create_CryptoCoreContainer(cc_u32 algorithm);

/*
 * @fn		destroy_CryptoCoreContainer
 * @brief	free allocated memory
 *
 * @param	crt		[in]CryptoCoreContainer context
 *
 * @return	void
 */
CRYPTOCORE_INTERNAL void ECRYPTO_API destroy_CryptoCoreContainer(CryptoCoreContainer* crt);

/*
 * @fn		CCMalloc
 * @brief	memory allocation and initialize for CryptoCore
 *
 * @param	crt		[in]size
 */
CRYPTOCORE_INTERNAL void ECRYPTO_API *CCMalloc(int siz);

#ifdef __cplusplus
}
#endif

#endif

/***************************** End of File *****************************/
