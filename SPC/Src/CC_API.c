/**
 * \file	CC_API.c
 * @brief	API of samsung Crypto Library
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jae Heung Lee
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/10/24
 * Note : modified for implementation, by Jisoon, Park, 06/11/06
 */

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include <stdlib.h>
#include "CryptoCore.h"
#include "rng.h"
#include "symmetric.h"
#include "hash.h"
#include "ecdsa.h"
#include "cmac.h"
#include "rsa.h"
#include "dsa.h"
#include "ecdh.h"
#include "hmac.h"
#include "dh.h"

////////////////////////////////////////////////////////////////////////////
// functions
////////////////////////////////////////////////////////////////////////////
CRYPTOCORE_INTERNAL void *CCMalloc(int siz)
{
	cc_u8 *pbBuf = (cc_u8*)malloc(siz);

	if (pbBuf == NULL)
	{
		return NULL;
	}
	else
	{
		memset(pbBuf, 0, siz);
		return (void*)pbBuf;
	}
}

CRYPTOCORE_INTERNAL void CCFree(void *ptr)
{
	if (ptr != NULL)
	{
		free(ptr);
	}
}

/*
 * @fn		CryptoCoreContainer *create_CryptoCoreContainer(cc_u32 algorithm)
 * @brief	memory allocation and initialize the crypt sturcture
 *
 * @param	algorithm	[in]algorithm want to use
 *
 * @return	address of created sturcture
 */
CRYPTOCORE_INTERNAL CryptoCoreContainer *create_CryptoCoreContainer(cc_u32 algorithm)
{
	CryptoCoreContainer *crt;
	srand((unsigned int)time(NULL));

	// allocate memory for crypt data structure (by using CCMalloc)
	crt = (CryptoCoreContainer *)CCMalloc(sizeof(CryptoCoreContainer));
	if (crt == NULL)
	{
		return NULL;
	}

	crt->ctx = (CryptoCoreCTX *)CCMalloc(sizeof(CryptoCoreCTX));
	if (crt->ctx == NULL)
	{
		free(crt);
		return NULL;
	}
	
	crt->PRNG_seed			= NULL;
	crt->PRNG_get			= NULL;
	crt->MD_init				= NULL;
	crt->MD_update			= NULL;
	crt->MD_final			= NULL;
	crt->MD_getHASH			= NULL;
	crt->MAC_init			= NULL;
	crt->MAC_update			= NULL;
	crt->MAC_final			= NULL;
	crt->MAC_getMAC			= NULL;
	crt->SE_init				= NULL;
	crt->SE_process			= NULL;
	crt->SE_final			= NULL;
	crt->AE_encrypt			= NULL;
	crt->AE_decrypt			= NULL;
	crt->DS_sign				= NULL;
	crt->DS_verify			= NULL;
	crt->DSA_genParam		= NULL;
	crt->DSA_setParam		= NULL;
	crt->DSA_genKeypair		= NULL;
	crt->DSA_setKeyPair		= NULL;
	crt->RSA_genKeypair		= NULL;
	crt->RSA_genKeypairWithE= NULL;
	crt->RSA_genKeyDWithPQE = NULL;
	crt->RSA_setKeypair		= NULL;
	crt->EC_setCurve			= NULL;
	crt->EC_genKeypair		= NULL;
	crt->EC_setKeypair		= NULL;
	crt->DH_GenerateParam	= NULL;
	crt->DH_SetParam			= NULL;
	crt->DH_Gen1stPhaseKey	= NULL;
	crt->DH_GenAuthKey		= NULL;
	crt->ECDH_Gen1stPhaseKey= NULL;
	crt->ECDH_GenAuthKey		= NULL;

	// allocate memory for context data structure
	// and set up the member functions according to the algorithm
	crt->alg = algorithm;
	switch(algorithm)
	{
		case ID_X931:
			crt->ctx->x931ctx			= (SDRM_X931Context*)CCMalloc(sizeof(SDRM_X931Context));
			crt->PRNG_seed				= SDRM_X931_seed;
			crt->PRNG_get				= SDRM_X931_get;
			break;
		case ID_MD5:
			crt->ctx->md5ctx				= (SDRM_MD5Context*)CCMalloc(sizeof(SDRM_MD5Context));
			crt->MD_init					= SDRM_MD5_init;
			crt->MD_update				= SDRM_MD5_update;
			crt->MD_final				= SDRM_MD5_final;
			crt->MD_getHASH				= SDRM_MD5_hash;
			break;	
		case ID_SHA1:
			crt->ctx->sha1ctx			= (SDRM_SHA1Context*)CCMalloc(sizeof(SDRM_SHA1Context));
			crt->MD_init					= SDRM_SHA1_init;
			crt->MD_update				= SDRM_SHA1_update;
			crt->MD_final				= SDRM_SHA1_final;
			crt->MD_getHASH				= SDRM_SHA1_hash;
			break;
		case ID_SHA224:
			crt->ctx->sha224ctx			= (SDRM_SHA224Context*)CCMalloc(sizeof(SDRM_SHA224Context));
			crt->MD_init					= SDRM_SHA224_init;
			crt->MD_update				= SDRM_SHA224_update;
			crt->MD_final				= SDRM_SHA224_final;
			crt->MD_getHASH				= SDRM_SHA224_hash;
			break;
		case ID_SHA256:
			crt->ctx->sha256ctx			= (SDRM_SHA256Context*)CCMalloc(sizeof(SDRM_SHA256Context));
			crt->MD_init					= SDRM_SHA256_init;
			crt->MD_update				= SDRM_SHA256_update;
			crt->MD_final				= SDRM_SHA256_final;
			crt->MD_getHASH				= SDRM_SHA256_hash;
			break;
#ifndef _OP64_NOTSUPPORTED
		case ID_SHA384:
			crt->ctx->sha384ctx			= (SDRM_SHA384Context*)CCMalloc(sizeof(SDRM_SHA384Context));
			crt->MD_init					= SDRM_SHA384_init;
			crt->MD_update				= SDRM_SHA384_update;
			crt->MD_final				= SDRM_SHA384_final;
			crt->MD_getHASH				= SDRM_SHA384_hash;
			break;
		case ID_SHA512:
			crt->ctx->sha512ctx			= (SDRM_SHA512Context*)CCMalloc(sizeof(SDRM_SHA512Context));
			crt->MD_init					= SDRM_SHA512_init;
			crt->MD_update				= SDRM_SHA512_update;
			crt->MD_final				= SDRM_SHA512_final;
			crt->MD_getHASH				= SDRM_SHA512_hash;
			break;
#endif
		case ID_CMAC:
			crt->ctx->cmacctx			= (SDRM_CMACContext*)CCMalloc(sizeof(SDRM_CMACContext));
			crt->MAC_init				= SDRM_CMAC_init;
			crt->MAC_update				= SDRM_CMAC_update;
			crt->MAC_final				= SDRM_CMAC_final;
			crt->MAC_getMAC				= SDRM_CMAC_getMAC;
			break;
		case ID_HMD5:
		case ID_HSHA1:
		case ID_HSHA224:
		case ID_HSHA256:
#ifndef _OP64_NOTSUPPORTED
		case ID_HSHA384:
		case ID_HSHA512:
#endif //_OP64_NOTSUPPORTED
			crt->ctx->hmacctx			= (SDRM_HMACContext*)CCMalloc(sizeof(SDRM_HMACContext));
			crt->MAC_init				= SDRM_HMAC_init;
			crt->MAC_update				= SDRM_HMAC_update;
			crt->MAC_final				= SDRM_HMAC_final;
			crt->MAC_getMAC				= SDRM_HMAC_getMAC;
			break;
		case ID_DH :
			crt->ctx->dhctx				= (SDRM_DHContext*)CCMalloc(sizeof(SDRM_DHContext));
			crt->DH_GenerateParam		= SDRM_GenerateDHParam;
			crt->DH_SetParam				= SDRM_SetDHParam;
			crt->DH_Gen1stPhaseKey		= SDRM_GenerateDHPrivate;
			crt->DH_GenAuthKey			= SDRM_GetDHSharedSecret;
			break;
		case ID_ECDH : 
			crt->ctx->ecdhctx			= (SDRM_ECDHContext*)SDRM_CURVE_Init();
			crt->EC_setCurve				= SDRM_ECC_Set_CTX;
			crt->EC_genKeypair			= SDRM_ECC_genKeypair;
			crt->EC_setKeypair			= SDRM_ECC_setKeypair;
			crt->ECDH_Gen1stPhaseKey		= SDRM_generateDH1stPhaseKey;
			crt->ECDH_GenAuthKey			= SDRM_generateDHKey;
			break;
		case ID_AES128:
			crt->ctx->aesctx				= (SDRM_AESContext*)CCMalloc(sizeof(SDRM_AESContext));
			crt->SE_init					= SDRM_AES_init;
			crt->SE_process				= SDRM_AES_process;
			crt->SE_final				= SDRM_AES_final;
			crt->SE_EncryptOneBlock		= SDRM_AES128_Encryption;
			crt->SE_DecryptOneBlock		= SDRM_AES128_Decryption;
			break;
		case ID_AES192:
			crt->ctx->aesctx				= (SDRM_AESContext*)CCMalloc(sizeof(SDRM_AESContext));
			crt->SE_init					= SDRM_AES_init;
			crt->SE_process				= SDRM_AES_process;
			crt->SE_final				= SDRM_AES_final;
			crt->SE_EncryptOneBlock		= SDRM_AES192_Encryption;
			crt->SE_DecryptOneBlock		= SDRM_AES192_Decryption;
			break;
		case ID_AES256:
			crt->ctx->aesctx				= (SDRM_AESContext*)CCMalloc(sizeof(SDRM_AESContext));
			crt->SE_init					= SDRM_AES_init;
			crt->SE_process				= SDRM_AES_process;
			crt->SE_final				= SDRM_AES_final;
			crt->SE_EncryptOneBlock		= SDRM_AES256_Encryption;
			crt->SE_DecryptOneBlock		= SDRM_AES256_Decryption;
			break;
		case ID_DES:
			crt->ctx->desctx				= (SDRM_DESContext*)CCMalloc(sizeof(SDRM_DESContext));
			crt->SE_init					= SDRM_DES_init;
			crt->SE_process				= SDRM_DES_process;
			crt->SE_final				= SDRM_DES_final;
			crt->SE_EncryptOneBlock		= SDRM_DES64_Encryption;
			crt->SE_DecryptOneBlock		= SDRM_DES64_Decryption;
			break;
		case ID_TDES:
			crt->ctx->tdesctx			= (SDRM_TDESContext*)CCMalloc(sizeof(SDRM_TDESContext));
			crt->SE_init					= SDRM_TDES_init;
			crt->SE_process				= SDRM_TDES_process;
			crt->SE_final				= SDRM_TDES_final;
			crt->SE_EncryptOneBlock		= SDRM_TDES64_Encryption;
			crt->SE_DecryptOneBlock		= SDRM_TDES64_Decryption;
			break;
		case ID_RC4:
			crt->ctx->rc4ctx				= (SDRM_RC4Context*)CCMalloc(sizeof(SDRM_RC4Context));
			crt->SE_init					= SDRM_RC4_init;
			crt->SE_process				= SDRM_RC4_process;
			break;
		case ID_SNOW2:
			crt->ctx->snow2ctx			= (SDRM_SNOW2Context*)CCMalloc(sizeof(SDRM_SNOW2Context));
			crt->SE_init					= SDRM_SNOW2_init;
			crt->SE_process				= SDRM_SNOW2_process;
			break;
		case ID_RSA512:
			crt->ctx->rsactx				= SDRM_RSA_InitCrt(64);
			crt->RSA_genKeypair			= SDRM_RSA_GenerateKey;
			crt->RSA_genKeypairWithE		= SDRM_RSA_GenerateND;
			crt->RSA_genKeyDWithPQE		= SDRM_RSA_GenerateDwithPQE;
			crt->RSA_setKeypair			= SDRM_RSA_setNED;
			crt->RSA_setKeypairForCRT	= SDRM_RSA_setNEDPQ;
			crt->AE_encrypt				= SDRM_RSA_encrypt;
			crt->AE_decrypt				= SDRM_RSA_decrypt;
			crt->AE_decryptByCRT			= SDRM_RSA_decryptByCRT;
			crt->DS_sign					= SDRM_RSA_sign;
			crt->DS_verify				= SDRM_RSA_verify;
			break;
		case ID_RSA:
		case ID_RSA1024:
			crt->ctx->rsactx				= SDRM_RSA_InitCrt(128);
			crt->RSA_genKeypair			= SDRM_RSA_GenerateKey;
			crt->RSA_genKeypairWithE		= SDRM_RSA_GenerateND;
			crt->RSA_genKeyDWithPQE		= SDRM_RSA_GenerateDwithPQE;
			crt->RSA_setKeypair			= SDRM_RSA_setNED;
			crt->RSA_setKeypairForCRT	= SDRM_RSA_setNEDPQ;
			crt->AE_encrypt				= SDRM_RSA_encrypt;
			crt->AE_decrypt				= SDRM_RSA_decrypt;
			crt->AE_decryptByCRT			= SDRM_RSA_decryptByCRT;
			crt->DS_sign					= SDRM_RSA_sign;
			crt->DS_verify				= SDRM_RSA_verify;
			break;
		case ID_RSA2048:
			crt->ctx->rsactx				= SDRM_RSA_InitCrt(256);
			crt->RSA_genKeypair			= SDRM_RSA_GenerateKey;
			crt->RSA_genKeypairWithE		= SDRM_RSA_GenerateND;
			crt->RSA_genKeyDWithPQE		= SDRM_RSA_GenerateDwithPQE;
			crt->RSA_setKeypair			= SDRM_RSA_setNED;
			crt->RSA_setKeypairForCRT	= SDRM_RSA_setNEDPQ;
			crt->AE_encrypt				= SDRM_RSA_encrypt;
			crt->AE_decrypt				= SDRM_RSA_decrypt;
			crt->AE_decryptByCRT			= SDRM_RSA_decryptByCRT;
			crt->DS_sign					= SDRM_RSA_sign;
			crt->DS_verify				= SDRM_RSA_verify;
			break;
		case ID_RSA3072:
			crt->ctx->rsactx				= SDRM_RSA_InitCrt(384);
			crt->RSA_genKeypair			= SDRM_RSA_GenerateKey;
			crt->RSA_genKeypairWithE		= SDRM_RSA_GenerateND;
			crt->RSA_genKeyDWithPQE		= SDRM_RSA_GenerateDwithPQE;
			crt->RSA_setKeypair			= SDRM_RSA_setNED;
			crt->RSA_setKeypairForCRT	= SDRM_RSA_setNEDPQ;
			crt->AE_encrypt				= SDRM_RSA_encrypt;
			crt->AE_decrypt				= SDRM_RSA_decrypt;
			crt->AE_decryptByCRT			= SDRM_RSA_decryptByCRT;
			crt->DS_sign					= SDRM_RSA_sign;
			crt->DS_verify				= SDRM_RSA_verify;
			break;
		case ID_DSA:
			crt->ctx->dsactx				= (SDRM_DSAContext*)SDRM_DSA_InitCrt();
			crt->DSA_genParam			= SDRM_DSA_GenParam;
			crt->DSA_setParam			= SDRM_DSA_SetParam;
			crt->DSA_genKeypair			= SDRM_DSA_GenKeypair;
			crt->DSA_setKeyPair			= SDRM_DSA_SetKeyPair;
			crt->DS_sign					= SDRM_DSA_sign;
			crt->DS_verify				= SDRM_DSA_verify;
			break;
		case ID_ECDSA:
			crt->ctx->ecdsactx			= (SDRM_ECDSAContext*)SDRM_CURVE_Init();
			crt->EC_setCurve				= SDRM_ECC_Set_CTX;
			crt->EC_genKeypair			= SDRM_ECC_genKeypair;
			crt->EC_setKeypair			= SDRM_ECC_setKeypair;
			crt->DS_sign					= SDRM_ECDSA_sign;
			crt->DS_verify				= SDRM_ECDSA_verify;
			break;
		default:
			// free CryptoCoreContainer data structure
			free(crt->ctx);
			free(crt);
			crt = NULL;
			break;
	}
	return crt;
}

/*
 * @fn		void destroy_CryptoCoreContainer(CryptoCoreContainer* crt)
 *
 * @brief	free allocated memory
 * @param	crt		[in]crypt context
 *
 * @return	void
 */
CRYPTOCORE_INTERNAL void destroy_CryptoCoreContainer(CryptoCoreContainer* crt)
{
	if (crt == NULL)
	{
		return;
	}

	if (crt->ctx == NULL)
	{
		free(crt);
		return;
	}

	// free context data structure
	switch(crt->alg)
	{
		case ID_X931:
			CCFree(crt->ctx->x931ctx);
			break;
		case ID_MD5:
			CCFree(crt->ctx->md5ctx);
			break;	
		case ID_SHA1:
			CCFree(crt->ctx->sha1ctx);
			break;
		case ID_SHA224:
			CCFree(crt->ctx->sha224ctx);
			break;
		case ID_SHA256:
			CCFree(crt->ctx->sha256ctx);
			break;
#ifndef _OP64_NOTSUPPORTED
		case ID_SHA384:
			CCFree(crt->ctx->sha384ctx);
			break;
		case ID_SHA512:
			CCFree(crt->ctx->sha512ctx);
			break;
#endif
		case ID_CMAC:
			CCFree(crt->ctx->cmacctx);
			break;
		case ID_HMD5:
		case ID_HSHA1:
		case ID_HSHA256:
#ifndef _OP64_NOTSUPPORTED
		case ID_HSHA384:
		case ID_HSHA512:
#endif //_OP64_NOTSUPPORTED
			CCFree(crt->ctx->hmacctx);
			break;
		case ID_AES128:
		case ID_AES192:
		case ID_AES256:
			CCFree(crt->ctx->aesctx);
			break;
		case ID_DES:
			CCFree(crt->ctx->desctx);
			break;
		case ID_TDES:
			CCFree(crt->ctx->tdesctx);
			break;
		case ID_RC4:
			CCFree(crt->ctx->rc4ctx);
			break;
		case ID_SNOW2:
			CCFree(crt->ctx->snow2ctx);
			break;
		case ID_RSA512:
		case ID_RSA:
		case ID_RSA1024:
		case ID_RSA2048:
			CCFree(crt->ctx->rsactx);
			break;
		case ID_DSA:
			CCFree(crt->ctx->dsactx);
			break;
		case ID_ECDSA:
			CCFree(crt->ctx->ecdsactx);
			break;
		case ID_ECDH:
			CCFree(crt->ctx->ecdhctx);
			break;
		case ID_DH :
			SDRM_FreeDHContext(crt->ctx->dhctx);
			CCFree(crt->ctx->dhctx);
			break;
	}

	// free CryptoCoreContainer data structure
	CCFree(crt->ctx);
	CCFree(crt);
}

/***************************** End of File *****************************/
