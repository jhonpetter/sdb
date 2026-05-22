/**
 * \file	pkcs1_v21.c
 * @brief	PKCS#1 V1.5, V2.0(RSAES-OAEP), V2.1(RSASSA-PSS) Implemetation
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/11/20
 * Note : Edited for Big-Endian Machine support, 2008/12/16
 */

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include "pkcs1_v21.h"
#include "md5.h"
#include "sha1.h"
#include "sha2.h"
#include "ANSI_x931.h"

//////////////////////////////////////////////////////////////////////////
// Functions
//////////////////////////////////////////////////////////////////////////
/*
 * @fn		SDRM_Padding_Rsaes_pkcs15
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
CRYPTOCORE_INTERNAL int SDRM_Padding_Rsaes_pkcs15(SDRM_BIG_NUM* BN_Dest, SDRM_BIG_NUM* BN_Src, int MODE, cc_u32 k)
{
	cc_u8 ECRYPTO_API Si_ANSI_X9_31[SDRM_X931_SEED_SIZ];
	cc_u32			mLen;
	cc_u32			i;
	cc_u32			RSA_KeyByteLen = k;
	cc_u8			*EM = (cc_u8*)malloc(RSA_KeyByteLen);

	if (EM == NULL)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	srand((unsigned int)time(NULL));

	SDRM_BN_Clr(BN_Dest);

	if (MODE == SDRM_ENPADDING)
	{
		//Get message length
		mLen = BN_Src->Length << 2;

		while(SDRM_CheckByteUINT32(BN_Src->pData, mLen - 1) == 0)
		{
			--mLen;
		}

		//Check message length
		if (mLen >= k - 11)
		{
			free(EM);
			return CRYPTO_MSG_TOO_LONG;
		}

		EM[0] = 0x00;
		EM[1] = 0x02;
		
		for (i = 0; i < 16; i++)
		{
			Si_ANSI_X9_31[i] = ((rand() << 16) + rand()) & 0xff;
		}

		SDRM_RNG_X931(Si_ANSI_X9_31, (k - mLen - 3) * 8, &EM[2]);
		EM[k - mLen - 1] = 0x00;
		EM[k - mLen - 2] = 0x00;

		for (i = 0; i < k - mLen - 3; i++)
		{
			if (EM[2 + i] == 0)
			{
				EM[2 + i] = (cc_u8)((i + 2) * (i + 1)) & 0xff;
			}
		}

		EM[k - mLen - 1] = 0x00;
		
		SDRM_I2OSP(BN_Src, mLen, &EM[k - mLen]);

		SDRM_OS2BN(EM, RSA_KeyByteLen, BN_Dest);
	} 
	else if (MODE == SDRM_DEPADDING)
	{
		mLen = BN_Src->Length * SDRM_SIZE_OF_DWORD - 1;
		while(((int)mLen >= 0) && (SDRM_CheckByteUINT32(BN_Src->pData, mLen) == 0))
		{
			--mLen;
		}

		//if there's no message
		if ((int)mLen < 0)
		{
			free(EM);
			return CRYPTO_INVALID_ARGUMENT;
		}

		//Check EM[0]
		if (((cc_u32)mLen != BN_Src->Length * SDRM_SIZE_OF_DWORD - 1) && (SDRM_CheckByteUINT32(BN_Src->pData, mLen + 1) != 0x00))
		{
			free(EM);
			return CRYPTO_INVALID_ARGUMENT;
		}

		mLen++;

		SDRM_I2OSP(BN_Src, mLen, EM);

		//Check EM[1]
		if (EM[0] != 0x02)
		{
			free(EM);
			return CRYPTO_INVALID_ARGUMENT;
		}

		//Check PS
		for (i = 1; i < (RSA_KeyByteLen - 1); i++)
		{
			if (EM[i] == 0)
			{
				break;
			}
		}

		if (i == (RSA_KeyByteLen - 1))
		{
			free(EM);
			return CRYPTO_INVALID_ARGUMENT;
		}

		//Copy Message
		SDRM_OS2BN(&EM[i + 1], RSA_KeyByteLen - i - 2, BN_Dest);
	}

	free(EM);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_Padding_Rsaes_oaep
 * @brief	RSAES OAEP
 *
 * @param	BN_Dest						[out]Padded msg if MODE is ENPADDING, Depadded msg if MODE is DEPADDING
 * @param	BN_Src						[in]Message to pad if MODE is ENPADDING, Message to depad if MODE is DEPADDING
 * @param	MODE						[in]ENPADDING or DEPADDING
 * @param	k							[in]byte-size of n
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if malloc is failed
 * \n		CRYPTO_MSG_TOO_LONG			if message is longer then key
 * \n		CRYPTO_NULL_POINTER			if argument is null
 */
CRYPTOCORE_INTERNAL int SDRM_Padding_Rsaes_oaep(SDRM_BIG_NUM* BN_Dest, SDRM_BIG_NUM* BN_Src, int MODE, int HASH_Algorithm, cc_u32 k)
{
	cc_u8				*DB, *EM, *Seed, *dbMask, *maskedDB, *seedMask, *maskedSeed, *Msg;
	cc_u8				hash[SDRM_SHA512_DATA_SIZE];
	cc_u32				i, mLen, dbLen;
	SDRM_BIG_NUM		*BN_Rnd;
	cc_u32				RSA_KeyByteLen = k;
	cc_u32				DigestLen = 0;
	SDRM_MD5Context		md5_ctx;					//Hash env var
	SDRM_SHA1Context	sha1_ctx;					//Hash env var
	SDRM_SHA256Context	sha256_ctx;					//Hash env var
#ifndef _OP64_NOTSUPPORTED
	SDRM_SHA384Context	sha384_ctx;					//Hash env var
	SDRM_SHA512Context	sha512_ctx;					//Hash env var
#endif	//_OP64_NOTSUPPORTED

	switch(HASH_Algorithm)
	{
		case ID_MD5 :
			DigestLen = SDRM_MD5_BLOCK_SIZ;
			break;
		case 0 :
		case ID_SHA1 :
			DigestLen = SDRM_SHA1_BLOCK_SIZ;
			break;
		case ID_SHA256 :
			DigestLen = SDRM_SHA256_BLOCK_SIZ;
			break;
#ifndef _OP64_NOTSUPPORTED
		case ID_SHA384 :
			DigestLen = SDRM_SHA384_BLOCK_SIZ;
			break;
		case ID_SHA512 :
			DigestLen = SDRM_SHA512_BLOCK_SIZ;
			break;
#endif	//_OP64_NOTSUPPORTED
		default :
			return CRYPTO_INVALID_ARGUMENT;
	}

	dbLen = k - DigestLen - 1;

	//Memory allocation
	EM = (cc_u8*)malloc(k * 4);
	if (EM == NULL)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	DB		   = EM		  + k;
	dbMask	   = DB		  + dbLen;
	maskedDB   = dbMask	  + dbLen;
	Seed	   = maskedDB + dbLen;
	seedMask   = Seed	  + DigestLen;
	maskedSeed = seedMask + DigestLen;

	SDRM_BN_Clr(BN_Dest);

	if (MODE == SDRM_ENPADDING)
	{
		//Get message length
		mLen = BN_Src->Length << 2;
		while(SDRM_CheckByteUINT32(BN_Src->pData, mLen - 1) == 0)
		{
			--mLen;
		}

		//Check message length
		if (mLen >= k - 2 * DigestLen - 2)
		{
			free(EM);
			return CRYPTO_MSG_TOO_LONG;
		}

		Msg = (cc_u8*)malloc(mLen);
		if (Msg == NULL)
		{
			free(EM);
			return CRYPTO_MEMORY_ALLOC_FAIL;
		}

		//Change Big Number to Byte array
		SDRM_I2OSP(BN_Src, mLen, Msg);

		//Generate random number and change to Byte array
		BN_Rnd = SDRM_BN_Init(SDRM_RSA_BN_BUFSIZE);
		if(BN_Rnd == NULL)
		{
			free(EM);
			free(Msg);
			return CRYPTO_MEMORY_ALLOC_FAIL;
		}

		SDRM_BN_Rand(BN_Rnd, DigestLen << 3);

		SDRM_I2OSP(BN_Rnd, DigestLen, Seed);

		SDRM_BN_FREE(BN_Rnd);

		//Get hash of 'L'
		switch(HASH_Algorithm)
		{
			case ID_MD5 :
				SDRM_MD5_Init(&md5_ctx);									//Init hash function
				SDRM_MD5_Final(&md5_ctx, DB);								//'L' is an empty string, so get output immediately
				break;
			case 0 :
			case ID_SHA1 :
				SDRM_SHA1_Init(&sha1_ctx);									//Init hash function
				SDRM_SHA1_Final(&sha1_ctx, DB);								//'L' is an empty string, so get output immediately
				break;
			case ID_SHA256 :
				SDRM_SHA256_Init(&sha256_ctx);								//Init hash function
				SDRM_SHA256_Final(&sha256_ctx, DB);							//'L' is an empty string, so get output immediately
				break;
#ifndef _OP64_NOTSUPPORTED
			case ID_SHA384 :
				SDRM_SHA384_Init(&sha384_ctx);								//Init hash function
				SDRM_SHA384_Final(&sha384_ctx, DB);							//'L' is an empty string, so get output immediately
				break;
			case ID_SHA512 :
				SDRM_SHA512_Init(&sha512_ctx);								//Init hash function
				SDRM_SHA512_Final(&sha512_ctx, DB);							//'L' is an empty string, so get output immediately
				break;
#endif	//_OP64_NOTSUPPORTED
			default :
				free(EM);
				free(Msg);
				return CRYPTO_INVALID_ARGUMENT;
		}

		//DB = lHash||PS||M
		memset(DB + DigestLen, 0, k - mLen - 2 * DigestLen - 2);
		DB[k - mLen - DigestLen - 2] = 0x01;
		memcpy(DB + k - mLen - DigestLen - 1, Msg, mLen);

		//dbMask = MGF(Seed, dbLen), maskedDB = DB ^ dbMask
		SDRM_MGF1(HASH_Algorithm, dbMask, Seed, DigestLen, dbLen);

		for (i = 0; i < dbLen; i++)
		{
			maskedDB[i] = DB[i] ^ dbMask[i];
		}

		//seedMask = MGF(maskedDB, SDRM_SHA1_BLOCK_SIZ), maskedSeed = Seed ^ seedMask
		SDRM_MGF1(HASH_Algorithm, seedMask, maskedDB, dbLen, DigestLen);
		for (i = 0; i < DigestLen; i++)
		{
			maskedSeed[i] = Seed[i] ^ seedMask[i];
		}

		//EM = 0x00||maskedSeed||maskedDB
		EM[0] = 0x00;
		memcpy(EM + 1, maskedSeed, DigestLen);
		memcpy(EM + 1 + DigestLen, maskedDB, dbLen);

		//Change Byte array to Big Number
		SDRM_OS2BN(EM, k, BN_Dest);
		free(Msg);
	}
	else if (MODE == SDRM_DEPADDING)
	{
		SDRM_I2OSP(BN_Src, k, EM);

		//Seperate EM : 0x00||maskedSeed||maskedDB
		if (EM[0] != 0x00)
		{
			free(EM);
			return CRYPTO_INVALID_ARGUMENT;
		}

		memcpy(maskedSeed, EM + 1, DigestLen);
		memcpy(maskedDB, EM + 1 + DigestLen, dbLen);

		//seedMask = MGF(maskedDB, SDRM_SHA1_BLOCK_SIZ), Seed = maskedSeed ^ seedMask
		SDRM_MGF1(HASH_Algorithm, seedMask, maskedDB, dbLen, DigestLen);
		for (i = 0; i < DigestLen; i++)
		{
			Seed[i] = maskedSeed[i] ^ seedMask[i];
		}

		//dbMask = MGF(Seed, dbLen), DB = maskedDB ^ dbMask
		SDRM_MGF1(HASH_Algorithm, dbMask, Seed, DigestLen, dbLen);
		for (i = 0; i < dbLen; i++)
		{
			DB[i] = maskedDB[i] ^ dbMask[i];
		}

		//Get hash of 'L'
		switch(HASH_Algorithm)
		{
			case ID_MD5 :
				SDRM_MD5_Init(&md5_ctx);									//Init hash function
				SDRM_MD5_Final(&md5_ctx, hash);								//'L' is an empty string, so get output immediately
				break;
			case 0 :
			case ID_SHA1 :
				SDRM_SHA1_Init(&sha1_ctx);									//Init hash function
				SDRM_SHA1_Final(&sha1_ctx, hash);							//'L' is an empty string, so get output immediately
				break;
			case ID_SHA256 :
				SDRM_SHA256_Init(&sha256_ctx);								//Init hash function
				SDRM_SHA256_Final(&sha256_ctx, hash);						//'L' is an empty string, so get output immediately
				break;
#ifndef _OP64_NOTSUPPORTED
			case ID_SHA384 :
				SDRM_SHA384_Init(&sha384_ctx);								//Init hash function
				SDRM_SHA384_Final(&sha384_ctx, hash);						//'L' is an empty string, so get output immediately
				break;
			case ID_SHA512 :
				SDRM_SHA512_Init(&sha512_ctx);								//Init hash function
				SDRM_SHA512_Final(&sha512_ctx, hash);						//'L' is an empty string, so get output immediately
				break;
#endif	//_OP64_NOTSUPPORTED
			default :
				return CRYPTO_INVALID_ARGUMENT;
		}

		//Compare hash value
		for (i = 0; i < DigestLen; i++)
		{
			if (hash[i] != DB[i])
			{
				free(EM);
				return CRYPTO_INVALID_ARGUMENT;
			}
		}

		//ignore 0x00s after hash(PS)
		while(DB[i] == 0x00)
		{
			i++;
		}

		//0x01 must be right after PS
		if (DB[i] != 0x01)
		{
			free(EM);
			return CRYPTO_INVALID_ARGUMENT;
		}

		//Abstract message and change to Big Number
		SDRM_OS2BN(DB + i + 1, dbLen - i - 1, BN_Dest);
	}

	free(EM);

	return CRYPTO_SUCCESS;
}

CRYPTOCORE_INTERNAL cc_u8 SDRM_DER_MD5[SDRM_DIGESTINFO_MD5_LEN] = SDRM_DIGESTINFO_MD5_VALUE;
CRYPTOCORE_INTERNAL cc_u8 SDRM_DER_SHA1[SDRM_DIGESTINFO_SHA1_LEN] = SDRM_DIGESTINFO_SHA1_VALUE;
CRYPTOCORE_INTERNAL cc_u8 SDRM_DER_SHA256[SDRM_DIGESTINFO_SHA256_LEN] = SDRM_DIGESTINFO_SHA256_VALUE;
CRYPTOCORE_INTERNAL cc_u8 SDRM_DER_SHA384[SDRM_DIGESTINFO_SHA384_LEN] = SDRM_DIGESTINFO_SHA384_VALUE;
CRYPTOCORE_INTERNAL cc_u8 SDRM_DER_SHA512[SDRM_DIGESTINFO_SHA512_LEN] = SDRM_DIGESTINFO_SHA512_VALUE;
/*
 * @fn		int SDRM_Padding_Rsassa_pkcs15(SDRM_BIG_NUM* BN_Dest, SDRM_BIG_NUM* BN_Src, cc_u8 *pszHash, int MODE, int HASH_Algorithm, cc_u32 k)
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
 * \n		CRYPTO_INVALID_ARGUMENT		if source is not in the right form
 */
CRYPTOCORE_INTERNAL int SDRM_Padding_Rsassa_pkcs15(SDRM_BIG_NUM* BN_Dest, SDRM_BIG_NUM* BN_Src, cc_u8 *pszHash, int MODE, int HASH_Algorithm, cc_u32 k) {
	cc_u32			tLen;
	cc_u32			i;
	cc_u32			RSA_KeyByteLen = k;
	cc_u32			mLen = 0;
	cc_u8			*EM = (cc_u8*)malloc(RSA_KeyByteLen);
	cc_u32			DigestInfoLen = 0;
	cc_u8			DER[32];

	if (EM == NULL)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	switch(HASH_Algorithm)
	{
		case ID_MD5 :
			DigestInfoLen = SDRM_DIGESTINFO_MD5_LEN;
			memcpy(DER, SDRM_DER_MD5, SDRM_DIGESTINFO_MD5_LEN);
			tLen = DigestInfoLen + SDRM_MD5_BLOCK_SIZ;
			break;
		case 0 : 
		case ID_SHA1 :
			DigestInfoLen = SDRM_DIGESTINFO_SHA1_LEN;
			memcpy(DER, SDRM_DER_SHA1, SDRM_DIGESTINFO_SHA1_LEN);
			tLen = DigestInfoLen + SDRM_SHA1_BLOCK_SIZ;
			break;
		case ID_SHA256 :
			DigestInfoLen = SDRM_DIGESTINFO_SHA256_LEN;
			memcpy(DER, SDRM_DER_SHA256, SDRM_DIGESTINFO_SHA256_LEN);
			tLen = DigestInfoLen + SDRM_SHA256_BLOCK_SIZ;
			break;
#ifndef _OP64_NOTSUPPORTED
		case ID_SHA384 :
			DigestInfoLen = SDRM_DIGESTINFO_SHA384_LEN;
			memcpy(DER, SDRM_DER_SHA384, SDRM_DIGESTINFO_SHA384_LEN);
			tLen = DigestInfoLen + SDRM_SHA384_BLOCK_SIZ;
			break;
		case ID_SHA512 :
			DigestInfoLen = SDRM_DIGESTINFO_SHA512_LEN;
			memcpy(DER, SDRM_DER_SHA512, SDRM_DIGESTINFO_SHA512_LEN);
			tLen = DigestInfoLen + SDRM_SHA512_BLOCK_SIZ;
			break;
#endif	//_OP64_NOTSUPPORTED
		default :
			//++ 2010.02.04 added by jspark - prevent resource leak
			free(EM);
			//-- 2010.02.04 added by jspark - prevent resource leak
			return CRYPTO_INVALID_ARGUMENT;
	}

	if (MODE == SDRM_ENPADDING)
	{
		SDRM_BN_Clr(BN_Dest);
		EM[0] = 0x00;
		EM[1] = 0x01;
		memset(EM + 2, 0xff, k - tLen - 3);
		EM[k - tLen - 1] = 0x00;
		memcpy(EM + k - tLen, DER, DigestInfoLen);
		memcpy(EM + k - tLen + DigestInfoLen, pszHash, tLen - DigestInfoLen);

		SDRM_OS2BN(EM, k, BN_Dest);

		free(EM);

		return CRYPTO_SUCCESS;
	}
	else if (MODE == SDRM_DEPADDING)
	{
		//Get message length
		mLen = BN_Src->Length * SDRM_SIZE_OF_DWORD - 1;
		while(SDRM_CheckByteUINT32(BN_Src->pData, mLen) == 0)
		{
			--mLen;
		}
		
		//Check EM[0] = 0x00
		if (((cc_u32)mLen != BN_Src->Length * SDRM_SIZE_OF_DWORD - 1) && (SDRM_CheckByteUINT32(BN_Src->pData,mLen + 1) != 0x00))
		{
			free(EM);
			return CRYPTO_INVALID_SIGN;
		}

		mLen++;
		SDRM_I2OSP(BN_Src, mLen, EM);

		//Check EM[1]
		if (EM[0] != 0x01)
		{
			free(EM);
			return CRYPTO_INVALID_ARGUMENT;
		}

		//Pass PS
		for (i = 1; i < (RSA_KeyByteLen - 1); i++)
		{
			if (EM[i] != 0xff)
			{
				break;
			}
		}

		if ((i == (RSA_KeyByteLen - 1)) || (EM[i] != 0x00))
		{
			free(EM);
			return CRYPTO_INVALID_ARGUMENT;
		}

		//Check DER encoding
		if (memcmp(&EM[i + 1], DER, DigestInfoLen) != 0x00)
		{
			free(EM);
			return CRYPTO_INVALID_SIGN;
		}

		if (memcmp(&EM[i + DigestInfoLen + 1], pszHash, tLen - DigestInfoLen) != 0)
		{
			free(EM);
			return CRYPTO_INVALID_SIGN;
		}
	}

	free(EM);

	return CRYPTO_VALID_SIGN;
}

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
 * \n		CRYPTO_VALID_SIGN		if sign is valid
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if malloc is failed
 * \n		CRYPTO_MSG_TOO_LONG		if message is longer then key
 * \n		CRYPTO_INVALID_ARGUMENT		if source is not in the right form
 */
CRYPTOCORE_INTERNAL int SDRM_Padding_Rsassa_pss(SDRM_BIG_NUM* BN_Dest, SDRM_BIG_NUM* BN_Src, cc_u8 *pszHash, cc_u32 emBits, int MODE, int HASH_Algorithm, cc_u32 MaxByte)
{
	cc_u8				hash[SDRM_SHA512_DATA_SIZE];
	cc_u8				*M_Prime, *DB, *EM, *dbMask;
	cc_u8				*H_Prime;
	cc_u32				sLen, i, dbLen, emLen;
	SDRM_BIG_NUM		*BN_Rnd;
	cc_u32				RSA_KeyByteLen = emBits / 8;
	cc_u32				DigestLen = 0;
	SDRM_MD5Context		md5_ctx;					//Hash env var
	SDRM_SHA1Context	sha1_ctx;					//Hash env var
	SDRM_SHA256Context	sha256_ctx;					//Hash env var
#ifndef _OP64_NOTSUPPORTED
	SDRM_SHA384Context	sha384_ctx;					//Hash env var
	SDRM_SHA512Context	sha512_ctx;					//Hash env var
#endif	//_OP64_NOTSUPPORTED

	switch(HASH_Algorithm)
	{
		case ID_MD5 :
			DigestLen = SDRM_MD5_BLOCK_SIZ;
			break;
		case 0 :
		case ID_SHA1 :
			DigestLen = SDRM_SHA1_BLOCK_SIZ;
			break;
		case ID_SHA256 :
			DigestLen = SDRM_SHA256_BLOCK_SIZ;
			break;
#ifndef _OP64_NOTSUPPORTED
		case ID_SHA384 :
			DigestLen = SDRM_SHA384_BLOCK_SIZ;
			break;
		case ID_SHA512 :
			DigestLen = SDRM_SHA512_BLOCK_SIZ;
			break;
#endif	//_OP64_NOTSUPPORTED
		default :
			return CRYPTO_INVALID_ARGUMENT;
	}
	
	emLen = (emBits - 1) / 8;
	dbLen = emLen - DigestLen - 1;

	if (MODE == SDRM_ENPADDING)
	{
		//sLen = (emLen - SDRM_SHA1_BLOCK_SIZ - 2) / 2;
		sLen = 20;

		M_Prime = (cc_u8*)malloc(emLen * 3 + sLen - SDRM_SHA1_BLOCK_SIZ + 6);
		if (M_Prime == NULL)
		{
			return CRYPTO_MEMORY_ALLOC_FAIL;
		}

		DB = M_Prime + 8 + DigestLen + sLen;
		EM = DB + dbLen;
		dbMask = EM + emLen;

		//Generate random number(salt)
		BN_Rnd = SDRM_BN_Init(SDRM_RSA_BN_BUFSIZE);
		if(BN_Rnd ==NULL)
		{
				free(M_Prime);
				return CRYPTO_MEMORY_ALLOC_FAIL;
		}
		SDRM_BN_Rand(BN_Rnd, sLen << 3);

		//M' = padding1||mHash||salt
		memset(M_Prime, 0, 8);
		memcpy(M_Prime + 8, pszHash, DigestLen);
		memcpy(M_Prime + 8 + DigestLen, BN_Rnd->pData, sLen);

		//Get Hash of M'
		switch(HASH_Algorithm)
		{
			case ID_MD5 :
				SDRM_MD5_Init(&md5_ctx);									//Init hash function
				SDRM_MD5_Update(&md5_ctx, M_Prime, 8 + DigestLen + sLen);	//Input data
				SDRM_MD5_Final(&md5_ctx, hash);								//Get Output
				break;
			case 0 :
			case ID_SHA1 :
				SDRM_SHA1_Init(&sha1_ctx);									//Init hash function
				SDRM_SHA1_Update(&sha1_ctx, M_Prime, 8 + DigestLen + sLen);	//Input data
				SDRM_SHA1_Final(&sha1_ctx, hash);							//Get Output
				break;
			case ID_SHA256 :
				SDRM_SHA256_Init(&sha256_ctx);									//Init hash function
				SDRM_SHA256_Update(&sha256_ctx, M_Prime, 8 + DigestLen + sLen);	//Input data
				SDRM_SHA256_Final(&sha256_ctx, hash);							//Get Output
				break;
#ifndef _OP64_NOTSUPPORTED
			case ID_SHA384 :
				SDRM_SHA384_Init(&sha384_ctx);									//Init hash function
				SDRM_SHA384_Update(&sha384_ctx, M_Prime, 8 + DigestLen + sLen);	//Input data
				SDRM_SHA384_Final(&sha384_ctx, hash);							//Get Output
				break;
			case ID_SHA512 :
				SDRM_SHA512_Init(&sha512_ctx);									//Init hash function
				SDRM_SHA512_Update(&sha512_ctx, M_Prime, 8 + DigestLen + sLen);	//Input data
				SDRM_SHA512_Final(&sha512_ctx, hash);							//Get Output
				break;
#endif	//_OP64_NOTSUPPORTED
			default :
				return CRYPTO_INVALID_ARGUMENT;
		}

		//DB = padding2||salt
		memset(DB, 0, emLen - sLen - DigestLen - 2);
		DB[emLen - sLen - DigestLen - 2] = 0x01;
		memcpy(DB + emLen - sLen - DigestLen - 1, BN_Rnd->pData, sLen);

		//dbMask = MGF(H, dbLen)
		SDRM_MGF1(HASH_Algorithm, dbMask, hash, DigestLen, dbLen);
		dbMask[0] &= 0x7f;

		//maskedDB = dbMask ^ DB
		for (i = 1; i < dbLen; i++)
		{
			dbMask[i] ^= DB[i];
		}

		//clear 8emLen - emBits bits of the leftmost octet in maskedDB
		EM[0] &= 0xFF >> (8 * emLen - emBits + 1);

		//EM = maskedDB||H||0xbc
		memcpy(EM, dbMask, dbLen);
		memcpy(EM + dbLen, hash, DigestLen);
		EM[emLen - 1] = 0xbc;

		SDRM_BN_Clr(BN_Dest);

		SDRM_OS2BN(EM, emLen, BN_Dest);

		free(M_Prime);
		free(BN_Rnd);

		return CRYPTO_SUCCESS;
	}
	else if (MODE == SDRM_DEPADDING)
	{
		EM = (cc_u8*)malloc(emLen * 4 - DigestLen + 4);
		if (EM == NULL)
		{
			return CRYPTO_MEMORY_ALLOC_FAIL;
		}

		DB = EM + emLen;
		H_Prime = DB + dbLen;
		dbMask = H_Prime + DigestLen;
		M_Prime = dbMask + dbLen;

		SDRM_I2OSP(BN_Src, emLen, EM);

		//Check EM[last] = 0xbc
		if (EM[emLen - 1] != 0xbc)
		{
			free(EM);
			return CRYPTO_INVALID_SIGN;
		}

		//Seperate EM to maskedDB and H'
		memcpy(DB, EM, dbLen);
		memcpy(H_Prime, EM + dbLen, DigestLen);

		//dbMask = MGF(H', dbLen)
		SDRM_MGF1(HASH_Algorithm, dbMask, H_Prime, DigestLen, dbLen);
		dbMask[0] &= 0x7f;

		//DB = maskedDB ^ dbMask
		for (i = 1; i < dbLen; i++)
		{
			DB[i] ^= dbMask[i];
		}

		DB[0] = 0x00;
		//Check padding2
		for (i = 0 ; DB[i] == 0x00; i++);
		if (DB[i] != 0x01)
		{
			free(EM);
			return CRYPTO_INVALID_SIGN;
		}
	
		sLen = dbLen - i - 1;

		//Abstract salt and make M'
		memset(M_Prime, 0, 8);
		memcpy(M_Prime + 8, pszHash, DigestLen);
		memcpy(M_Prime + 8 + DigestLen, DB + i + 1, sLen);

		//Get hash of M'
		switch(HASH_Algorithm)
		{
			case ID_MD5 :
				SDRM_MD5_Init(&md5_ctx);									//Init hash function
				SDRM_MD5_Update(&md5_ctx, M_Prime, 8 + DigestLen + sLen);	//Input data
				SDRM_MD5_Final(&md5_ctx, hash);								//Get Output
				break;
			case 0 :
			case ID_SHA1 :
				SDRM_SHA1_Init(&sha1_ctx);									//Init hash function
				SDRM_SHA1_Update(&sha1_ctx, M_Prime, 8 + DigestLen + sLen);	//Input data
				SDRM_SHA1_Final(&sha1_ctx, hash);							//Get Output
				break;
			case ID_SHA256 :
				SDRM_SHA256_Init(&sha256_ctx);									//Init hash function
				SDRM_SHA256_Update(&sha256_ctx, M_Prime, 8 + DigestLen + sLen);	//Input data
				SDRM_SHA256_Final(&sha256_ctx, hash);							//Get Output
				break;
#ifndef _OP64_NOTSUPPORTED
			case ID_SHA384 :
				SDRM_SHA384_Init(&sha384_ctx);									//Init hash function
				SDRM_SHA384_Update(&sha384_ctx, M_Prime, 8 + DigestLen + sLen);	//Input data
				SDRM_SHA384_Final(&sha384_ctx, hash);							//Get Output
				break;
			case ID_SHA512 :
				SDRM_SHA512_Init(&sha512_ctx);									//Init hash function
				SDRM_SHA512_Update(&sha512_ctx, M_Prime, 8 + DigestLen + sLen);	//Input data
				SDRM_SHA512_Final(&sha512_ctx, hash);							//Get Output
				break;
#endif	//_OP64_NOTSUPPORTED
			default :
				free(EM);
				return CRYPTO_INVALID_ARGUMENT;
		}

		//Compare H' and H
		for (i = 0; i < DigestLen; i++)
		{
			if (H_Prime[i] != hash[i])
			{
				free(EM);
				return CRYPTO_INVALID_SIGN;
			}
		}

		free(EM);
	}

	return CRYPTO_VALID_SIGN;
}

/*
 * @fn		int SDRM_MGF1(int HASH_Algorithm, cc_u8* mask, cc_u8* pbSeed, cc_u32 SeedLen, cc_u32 dMaskLen)
 * @brief	SDRM_MGF1 Function (Mask Generation Function based on a hash function)
 *
 * @param	mask					[out]byte-length of generated mask
 * @param	pbSeed					[in]seed for MGF
 * @param	SeedLen					[in]byte-length of pbSeed
 * @param	dMaskLen				[in]byte-length of mask
 *
 * @return	CRYPTO_SUCCESS			if no error is occured
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if malloc is failed
 */
CRYPTOCORE_INTERNAL int SDRM_MGF1(int HASH_Algorithm, cc_u8* mask, cc_u8* pbSeed, cc_u32 SeedLen, cc_u32 dMaskLen) {
	cc_u8			 *T, *Seed, *pbBuf;
	cc_u32			 counter;
	cc_u8			 hash[64];						//SHA-1 output size is 160 bit
	cc_u8			 hashlen;
	SDRM_MD5Context md5_ctx;						//Hash env var
	SDRM_SHA1Context sha1_ctx;						//Hash env var
	SDRM_SHA256Context sha256_ctx;					//Hash env var
#ifndef _OP64_NOTSUPPORTED
	SDRM_SHA384Context sha384_ctx;					//Hash env var
	SDRM_SHA512Context sha512_ctx;					//Hash env var
#endif	//_OP64_NOTSUPPORTED

	switch(HASH_Algorithm)
	{
		case ID_MD5 :
			hashlen = SDRM_MD5_BLOCK_SIZ;
			break;
		case 0 :
		case ID_SHA1 :
			hashlen = SDRM_SHA1_BLOCK_SIZ;
			break;
		case ID_SHA256 :
			hashlen = SDRM_SHA256_BLOCK_SIZ;
			break;
#ifndef _OP64_NOTSUPPORTED
		case ID_SHA384 :
			hashlen = SDRM_SHA384_BLOCK_SIZ;
			break;
		case ID_SHA512 :
			hashlen = SDRM_SHA512_BLOCK_SIZ;
			break;
#endif	//_OP64_NOTSUPPORTED
		default :
			return CRYPTO_INVALID_ARGUMENT;
	}

	pbBuf = (cc_u8*)malloc(dMaskLen + hashlen + SeedLen + 4);
	if (pbBuf == NULL)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	T = pbBuf;
	Seed = T + dMaskLen + hashlen;

	memset(mask, 0, dMaskLen);
	memcpy(Seed, pbSeed, SeedLen);

	for (counter = 0; counter < (dMaskLen - 1) / hashlen + 1; counter++)
	{
		Seed[SeedLen    ] = (cc_u8)(counter >> 24);
		Seed[SeedLen + 1] = (cc_u8)(counter >> 16);
		Seed[SeedLen + 2] = (cc_u8)(counter >> 8 );
		Seed[SeedLen + 3] = (cc_u8)(counter      );

		//Hash(Seed||counter)
		switch(HASH_Algorithm)
		{
			case ID_MD5 :
				SDRM_MD5_Init(&md5_ctx);						//Init hash function
				SDRM_MD5_Update(&md5_ctx, Seed, SeedLen + 4);	//Input data
				SDRM_MD5_Final(&md5_ctx, hash);					//Get Output
				break;
			case 0 :
			case ID_SHA1 :
				SDRM_SHA1_Init(&sha1_ctx);						//Init hash function
				SDRM_SHA1_Update(&sha1_ctx, Seed, SeedLen + 4);	//Input data
				SDRM_SHA1_Final(&sha1_ctx, hash);				//Get Output
				break;
			case ID_SHA256 :
				SDRM_SHA256_Init(&sha256_ctx);						//Init hash function
				SDRM_SHA256_Update(&sha256_ctx, Seed, SeedLen + 4);	//Input data
				SDRM_SHA256_Final(&sha256_ctx, hash);				//Get Output
				break;
#ifndef _OP64_NOTSUPPORTED	
			case ID_SHA384 :
				SDRM_SHA384_Init(&sha384_ctx);						//Init hash function
				SDRM_SHA384_Update(&sha384_ctx, Seed, SeedLen + 4);	//Input data
				SDRM_SHA384_Final(&sha384_ctx, hash);				//Get Output
				break;
			case ID_SHA512 :
				SDRM_SHA512_Init(&sha512_ctx);						//Init hash function
				SDRM_SHA512_Update(&sha512_ctx, Seed, SeedLen + 4);	//Input data
				SDRM_SHA512_Final(&sha512_ctx, hash);				//Get Output
				break;
#endif	//_OP64_NOTSUPPORTED
			default :
				free(pbBuf);
				return CRYPTO_INVALID_ARGUMENT;
		}

		memcpy(T + counter * hashlen, hash, hashlen);
	}

	memcpy(mask, T, dMaskLen);
	free(pbBuf);

	return CRYPTO_SUCCESS;
}

/***************************** End of File *****************************/
