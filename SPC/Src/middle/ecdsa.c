/**
 * \file	ecdsa.c
 * @brief	implementation of public key signature algorithm
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/11/13
 */

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#ifdef _WIN32_WCE
#include <winbase.h>
#endif
#include <time.h>
#include "ecdsa.h"
#include "ANSI_x931.h"

////////////////////////////////////////////////////////////////////////////
// Functions
////////////////////////////////////////////////////////////////////////////
/*
 * @fn		SDRM_CTX_ECDSA_KEY_GEN
 * @brief	generate signature
 *
 * @param	ctx							[out]ecc context
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 * \n		CRYPTO_NULL_POINTER			if any argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_CTX_ECDSA_KEY_GEN(SDRM_ECC_CTX *ctx)
{
	int				i, retVal;
	cc_u32			Seed[4];
	SDRM_BIG_NUM	*BN_d, *BN_temp;
	SDRM_EC_POINT	*kP;
	
	cc_u8			*pbBuf = NULL;

	if (ctx == NULL)
	{
		return CRYPTO_NULL_POINTER;
	}
	
	pbBuf = (cc_u8*)malloc(SDRM_ECC_ALLOC_SIZE * 2);
	if (!pbBuf)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	BN_d	= SDRM_BN_Alloc( pbBuf							, SDRM_ECC_BN_BUFSIZE);
	BN_temp	= SDRM_BN_Alloc((cc_u8*)BN_d + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);

	kP = SDRM_ECC_Init();
	if (kP == NULL)
	{
		free(pbBuf);
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	for (i = 0; i < 4; i++)
	{
		Seed[i] = (rand() << 16) ^ rand();
	}

	SDRM_BN_Sub(BN_temp, ctx->ECC_n, BN_One);
	do {
		SDRM_RNG_X931((cc_u8 *)Seed, ctx->uDimension, (cc_u8*)BN_d->pData);
		BN_d->Length =  ctx->uDimension / 32;
	} while ((SDRM_BN_Cmp(BN_d, BN_One) < 0) || (SDRM_BN_Cmp(BN_d, BN_temp) > 0));

	SDRM_BN_OPTIMIZE_LENGTH(BN_d);

	SDRM_EC_SET_ZERO(kP);
	retVal = SDRM_CTX_EC_kP(ctx, kP, ctx->ECC_G, BN_d);
	if (retVal != CRYPTO_SUCCESS)
	{
		free(pbBuf);
		free(kP);

		return retVal;
	}

	SDRM_BN_Copy(ctx->PRIV_KEY, BN_d);
	SDRM_EC_COPY(ctx->PUBLIC_KEY, kP);

	free(pbBuf);
	free(kP);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_CTX_ECDSA_SIG_GEN
 * @brief	generate signature
 *
 * @param	ctx							[in]ecc context
 * @param	sig							[out]generated signature
 * @param	hash						[in]hashed message
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 * \n		CRYPTO_NULL_POINTER			if any argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_CTX_ECDSA_SIG_GEN(SDRM_ECC_CTX *ctx, cc_u8 *sig, cc_u8 *hash, unsigned int hashLen)
{
	int				i, res = -1; 
	cc_u32			Seed[20];
	SDRM_BIG_NUM	*BN_Tmp1, *BN_Tmp2, *BN_Tmp3;
	SDRM_BIG_NUM	*BN_k, *BN_r, *BN_s, *BN_hash; 
	SDRM_EC_POINT	*kP;

	cc_u8			*pbBuf = NULL;

	if ((ctx== NULL) || (sig == NULL) || (hash == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	pbBuf = (cc_u8*)malloc(SDRM_ECC_ALLOC_SIZE * 7);
	if (!pbBuf)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	BN_Tmp1 = SDRM_BN_Alloc( pbBuf,								  SDRM_ECC_BN_BUFSIZE);
	BN_Tmp2 = SDRM_BN_Alloc((cc_u8*)BN_Tmp1 + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	BN_Tmp3 = SDRM_BN_Alloc((cc_u8*)BN_Tmp2 + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	BN_k    = SDRM_BN_Alloc((cc_u8*)BN_Tmp3 + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	BN_r    = SDRM_BN_Alloc((cc_u8*)BN_k    + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	BN_s    = SDRM_BN_Alloc((cc_u8*)BN_r    + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	BN_hash = SDRM_BN_Alloc((cc_u8*)BN_s    + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);

	kP = SDRM_ECC_Init();
	if (kP == NULL)
	{
		free(pbBuf);
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	for (i = 0; i < 4; i++)
	{
		Seed[i] = (rand() << 16) ^ rand();
	}

	while(1)
	{
		while(1)
		{
			//	1. [1, r-1] 사이의 난수 k 선택
			SDRM_BN_Sub(BN_Tmp1, ctx->ECC_n, BN_One);
			do {
				SDRM_RNG_X931((cc_u8 *)Seed, ctx->uDimension, (cc_u8*)BN_k->pData);
				BN_k->Length = ctx->uDimension / 32;
			} while((SDRM_BN_Cmp(BN_k, BN_One) < 0) || (SDRM_BN_Cmp(BN_k, BN_Tmp1) > 0));

			//	2. kP = (x1, y1), r = x1 mod n(&ctx.ECC_n) 계산. r = 0 이면 k 다시 선택 
			SDRM_EC_SET_ZERO(kP);
			res = SDRM_CTX_EC_kP(ctx, kP, ctx->ECC_G, BN_k);
			if (res != CRYPTO_SUCCESS)
			{
				free(pbBuf);
				free(kP);

				return res;
			}

			//SDRM_PrintBN("kP->x", kP->x); 
			SDRM_BN_ModRed(BN_r, kP->x, ctx->ECC_n);	
			if (BN_r->Length > 0)		// r = 0 이면 k 다시 선택
			{
				break;
			}
		}

	//	3. k^{-1} mod n 계산.
		SDRM_BN_ModInv(BN_Tmp1, BN_k, ctx->ECC_n);

		//SDRM_PrintBN("BN_k", BN_k); 
		//SDRM_PrintBN("ctx->ECC_n", ctx->ECC_n); 
		//SDRM_PrintBN("BN_Tmp1 = k^{-1} mod n", BN_Tmp1); 

	//	4. s = k^{-1}(hash + dr) mod n 계산 (d = private key). s = 0 이면 1번으로. 
		// BN_Tmp2 = dr
		SDRM_OS2BN(hash, hashLen, BN_hash); 

		SDRM_BN_ModMul(BN_Tmp2, ctx->PRIV_KEY, BN_r, ctx->ECC_n);
		SDRM_BN_ModAdd(BN_Tmp3, BN_hash, BN_Tmp2, ctx->ECC_n);
		SDRM_BN_ModMul(BN_s, BN_Tmp1, BN_Tmp3, ctx->ECC_n);
		if (BN_s->Length > 0)
		{
			break;
		}
	}

//	(r, s) 서명으로 출력.
	//SDRM_PrintBN("BN_r", BN_r);
	//SDRM_PrintBN("BN_s", BN_s);

	SDRM_BN2OS(BN_r, ctx->uDimension / 8, sig);
	SDRM_BN2OS(BN_s, ctx->uDimension / 8, sig + ctx->uDimension / 8);

	free(kP);
	free(pbBuf);

	return CRYPTO_SUCCESS; 
}

/*
 * @fn		SDRM_CTX_ECDSA_SIG_VERIFY
 * @brief	verify ecdsa signature
 *
 * @param	ctx							[in]ecc context
 * @param	sig							[out]generated signature
 * @param	signLen						[out]byte-length of signature
 * @param	hash						[in]hash value
 * @param	hashLen						[in]byte-length of hash
 *
 * @return	CRYPTO_VALID_SIGN			if given signature is valid
 * \n		CRYPTO_INVALID_SIGN			if given signature is invalid
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 * \n		CRYPTO_INVALID_ARGUMENT		if any argument is out of range
 * \n		CRYPTO_INFINITY_INPUT		if given argument represents an infinity value
 */
CRYPTOCORE_INTERNAL int SDRM_CTX_ECDSA_SIG_VERIFY(SDRM_ECC_CTX *ctx, cc_u8 *sig, int signLen, cc_u8 *hash, int hashLen)
{
	int				res;
	SDRM_BIG_NUM	*BN_tmp, *BN_u1, *BN_u2, *BN_w, *BN_hash, *pBN_r, *pBN_s;
	SDRM_EC_POINT	*EC_temp1, *EC_temp2; 

	cc_u8 *pbBuf = (cc_u8*)malloc(SDRM_ECC_ALLOC_SIZE * 7);
	
	if (!pbBuf)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}
	
	BN_tmp  = SDRM_BN_Alloc( pbBuf,								 SDRM_ECC_BN_BUFSIZE);
	BN_u1   = SDRM_BN_Alloc((cc_u8*)BN_tmp + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	BN_u2   = SDRM_BN_Alloc((cc_u8*)BN_u1  + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	BN_w    = SDRM_BN_Alloc((cc_u8*)BN_u2  + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	BN_hash = SDRM_BN_Alloc((cc_u8*)BN_w   + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	pBN_r   = SDRM_BN_Alloc((cc_u8*)BN_hash+ SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	pBN_s   = SDRM_BN_Alloc((cc_u8*)pBN_r  + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	
	EC_temp1 = SDRM_ECC_Init();
	if (EC_temp1 == NULL)
	{
		free(pbBuf);
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	EC_temp2 = SDRM_ECC_Init();
	if (EC_temp2 == NULL)
	{
		free(pbBuf);
		free(EC_temp1);
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	if ((cc_u32)signLen != (ctx->uDimension / 4))
	{
		free(pbBuf);
		free(EC_temp1);
		free(EC_temp2);
		return CRYPTO_INVALID_ARGUMENT;
	}

	SDRM_OS2BN(sig, ctx->uDimension / 8, pBN_r); 	
	SDRM_OS2BN(sig + ctx->uDimension / 8, ctx->uDimension / 8, pBN_s); 	
	//SDRM_PrintBN("BN_r", pBN_r);
	//SDRM_PrintBN("BN_s", pBN_s);

	//	1. r과 s의 범위 조사 
	SDRM_BN_Sub(BN_tmp, ctx->ECC_n, BN_One);
	if ((SDRM_BN_Cmp(pBN_r, BN_One) < 0) || (SDRM_BN_Cmp(pBN_r, BN_tmp) > 0))
	{
		free(pbBuf);
		free(EC_temp1);
		free(EC_temp2);

		return CRYPTO_INVALID_ARGUMENT;
	}

	if ((SDRM_BN_Cmp(pBN_s, BN_One) < 0) || (SDRM_BN_Cmp(pBN_s, BN_tmp) > 0))
	{
		free(pbBuf);
		free(EC_temp1);
		free(EC_temp2);

		return CRYPTO_INVALID_ARGUMENT;
	}
	
	//	2. w = s^(-1) mod n, BN_hash 계산 
	SDRM_OS2BN(hash, hashLen, BN_hash); 
	res = SDRM_BN_ModInv(BN_w, pBN_s, ctx->ECC_n);
//SDRM_PrintBN("BN_w", BN_w);

	if (res != CRYPTO_SUCCESS)
	{
		free(pbBuf);
		free(EC_temp1);
		free(EC_temp2);

		return res;
	}

	//	3. u1 = BN_hash *w mod n, u2 = rw mod n
	SDRM_BN_ModMul(BN_u1, BN_hash, BN_w, ctx->ECC_n);			
	SDRM_BN_ModMul(BN_u2, pBN_r,   BN_w, ctx->ECC_n);
//SDRM_PrintBN("BN_u1", BN_u1);
//SDRM_PrintBN("BN_u2", BN_u2);

	//	4. (x0, y0) = u1P + u2Q, V = x0 mod n
	res = SDRM_CTX_EC_2kP(ctx, EC_temp1, BN_u1, ctx->ECC_G, BN_u2, ctx->PUBLIC_KEY);
	if (res != CRYPTO_SUCCESS)
	{
		free(pbBuf);
		free(EC_temp1);
		free(EC_temp2);

		return res;
	}
	else if(EC_temp1->IsInfinity == 1)
	{
		res = CRYPTO_INFINITY_INPUT;
		free(pbBuf);
		free(EC_temp1);
		free(EC_temp2);

		return res;
	}
	
//	SDRM_PrintBN("EC_temp1->x", EC_temp1->x);
//	SDRM_PrintBN("ctx->ECC_n", ctx->ECC_n);
	SDRM_BN_ModRed(BN_tmp, EC_temp1->x, ctx->ECC_n);	

//	SDRM_PrintBN("BN_tmp", BN_tmp);
//	SDRM_PrintBN("pBN_r", pBN_r);
	// 5. V = r인 경우 서명 ok
	res = SDRM_BN_Cmp_sign(BN_tmp, pBN_r);
	if (res != 0)
	{
		res = CRYPTO_INVALID_SIGN;
		free(pbBuf);
		free(EC_temp1);
		free(EC_temp2);

		return res; 
	}

	//Success
	free(pbBuf);
	free(EC_temp1);
	free(EC_temp2);

	return CRYPTO_VALID_SIGN; 
}

/*
 * @fn		SDRM_ECDSA_sign
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
CRYPTOCORE_INTERNAL int SDRM_ECDSA_sign(CryptoCoreContainer *crt, cc_u8 *hash, cc_u32 hashLen, cc_u8 *signature, cc_u32 *signLen)
{
	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->ecdsactx == NULL) || (hash == NULL) || (signature == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	if (signLen)
	{
		*signLen = crt->ctx->ecdsactx->uDimension / 4;
	}

	return SDRM_CTX_ECDSA_SIG_GEN(crt->ctx->ecdsactx, signature, hash, hashLen);
}

/*
 * @fn		SDRM_ECDSA_verify
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
CRYPTOCORE_INTERNAL int SDRM_ECDSA_verify(CryptoCoreContainer *crt, cc_u8 *hash, cc_u32 hashLen, cc_u8 *signature, cc_u32 signLen, int *result)
{
	int retVal;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->ecdsactx == NULL) || (hash == NULL) || (signature == NULL) || (result == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	if (signLen != (crt->ctx->ecdsactx->uDimension / 4))
	{
		return CRYPTO_INVALID_ARGUMENT;
	}

	retVal = SDRM_CTX_ECDSA_SIG_VERIFY(crt->ctx->ecdsactx, signature, signLen, hash, hashLen);

	if (retVal == CRYPTO_VALID_SIGN)
	{
		*result = CRYPTO_VALID_SIGN;
	}
	else
	{
		*result = CRYPTO_INVALID_SIGN;
	}

	return retVal;
}

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
CRYPTOCORE_INTERNAL int SDRM_ECC_Set_CTX(CryptoCoreContainer *crt, cc_u16 Dimension, 
					 cc_u8* ECC_P_Data,   cc_u32 ECC_P_Len,
					 cc_u8* ECC_A_Data,   cc_u32 ECC_A_Len,
					 cc_u8* ECC_B_Data,   cc_u32 ECC_B_Len,
					 cc_u8* ECC_G_X_Data, cc_u32 ECC_G_X_Len,
					 cc_u8* ECC_G_Y_Data, cc_u32 ECC_G_Y_Len,
					 cc_u8* ECC_R_Data,   cc_u32 ECC_R_Len)
{
	int				retVal;
	cc_u8			zero[] = {0x00};
	SDRM_ECC_CTX	*ECC_ctx;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->ecdsactx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	if ((ECC_P_Data == NULL) || (ECC_A_Data == NULL) || (ECC_B_Data == NULL) || (ECC_G_X_Data == NULL) || (ECC_G_Y_Data == NULL) || (ECC_R_Data == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	ECC_ctx = crt->ctx->ecdhctx;

	ECC_ctx->uDimension = Dimension;

	retVal = SDRM_OS2BN(ECC_P_Data, ECC_P_Len, ECC_ctx->ECC_p); 
	if (retVal != CRYPTO_SUCCESS)
	{
		free(ECC_ctx);
		return retVal;
	}

	retVal = SDRM_OS2BN(ECC_A_Data, ECC_A_Len, ECC_ctx->ECC_a); 
	if (retVal != CRYPTO_SUCCESS)
	{
		free(ECC_ctx);
		return retVal;
	}

	retVal = SDRM_OS2BN(ECC_B_Data, ECC_B_Len, ECC_ctx->ECC_b); 
	if (retVal != CRYPTO_SUCCESS)
	{
		free(ECC_ctx);
		return retVal;
	}

	retVal = SDRM_OS2BN(ECC_R_Data, ECC_R_Len, ECC_ctx->ECC_n); 
	if (retVal != CRYPTO_SUCCESS)
	{
		free(ECC_ctx);
		return retVal;
	}
	
	ECC_ctx->ECC_G->IsInfinity = 0;
	retVal = SDRM_OS2BN(ECC_G_X_Data, ECC_G_X_Len, ECC_ctx->ECC_G->x); 
	if (retVal != CRYPTO_SUCCESS)
	{
		free(ECC_ctx);
		return retVal;
	}
	retVal = SDRM_OS2BN(ECC_G_Y_Data, ECC_G_Y_Len, ECC_ctx->ECC_G->y); 	
	if (retVal != CRYPTO_SUCCESS)
	{
		free(ECC_ctx);
		return retVal;
	}

	SDRM_OS2BN(zero, 0, ECC_ctx->ECC_G->z);
	SDRM_OS2BN(zero, 0, ECC_ctx->ECC_G->z2);
	SDRM_OS2BN(zero, 0, ECC_ctx->ECC_G->z3);

	return CRYPTO_SUCCESS;
}

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
CRYPTOCORE_INTERNAL int SDRM_ECC_genKeypair (CryptoCoreContainer *crt,
						 cc_u8 *PrivateKey,  cc_u32 *PrivateKeyLen, 
						 cc_u8 *PublicKey_X, cc_u32 *PublicKey_XLen,
						 cc_u8 *PublicKey_Y, cc_u32 *PublicKey_YLen)
{
	int retVal;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->ecdsactx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	retVal = SDRM_CTX_ECDSA_KEY_GEN(crt->ctx->ecdsactx);
	if (retVal != CRYPTO_SUCCESS)
	{
		return retVal;
	}

	if (PrivateKey != NULL)
	{
		SDRM_I2OSP(crt->ctx->ecdsactx->PRIV_KEY, crt->ctx->ecdsactx->uDimension / 8, PrivateKey);
	}

	if (PrivateKeyLen != NULL)
	{
		*PrivateKeyLen = crt->ctx->ecdsactx->uDimension / 8;
	}

	if (PublicKey_X != NULL)
	{
		SDRM_I2OSP(crt->ctx->ecdsactx->PUBLIC_KEY->x, crt->ctx->ecdsactx->uDimension / 8, PublicKey_X);
	}

	if (PublicKey_XLen != NULL)
	{
		*PublicKey_XLen = crt->ctx->ecdsactx->uDimension / 8;
	}

	if (PublicKey_Y != NULL)
	{
		SDRM_I2OSP(crt->ctx->ecdsactx->PUBLIC_KEY->y, crt->ctx->ecdsactx->uDimension / 8, PublicKey_Y);
	}

	if (PublicKey_YLen != NULL)
	{
		*PublicKey_YLen = crt->ctx->ecdsactx->uDimension / 8;
	}

	return CRYPTO_SUCCESS;

}

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
CRYPTOCORE_INTERNAL int SDRM_ECC_setKeypair(CryptoCoreContainer *crt,
					    cc_u8* PRIV_Data,  cc_u32 PRIV_Len,
					    cc_u8* PUB_X_Data, cc_u32 PUB_X_Len,
					    cc_u8* PUB_Y_Data, cc_u32 PUB_Y_Len)
{
	int				retVal;
	cc_u8			zero[] = {0x00};
	SDRM_ECC_CTX	*ECC_ctx;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->ecdsactx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	ECC_ctx = crt->ctx->ecdsactx;

	ECC_ctx->PUBLIC_KEY->IsInfinity = 0;

	if (PRIV_Data != NULL)
	{
		retVal = SDRM_OS2BN(PRIV_Data, PRIV_Len, ECC_ctx->PRIV_KEY);
		if (retVal != CRYPTO_SUCCESS)
		{
			return retVal;
		}
	}

	if (PUB_X_Data != NULL && PUB_Y_Data != NULL)
	{
		retVal = SDRM_OS2BN(PUB_X_Data, PUB_X_Len, ECC_ctx->PUBLIC_KEY->x); 
		if (retVal != CRYPTO_SUCCESS)
		{
			return retVal;
		}

		retVal = SDRM_OS2BN(PUB_Y_Data, PUB_Y_Len, ECC_ctx->PUBLIC_KEY->y);
		if (retVal != CRYPTO_SUCCESS)
		{
			return retVal;
		}
	}

	SDRM_OS2BN(zero, 0, ECC_ctx->PUBLIC_KEY->z);
	SDRM_OS2BN(zero, 0, ECC_ctx->PUBLIC_KEY->z2);
	SDRM_OS2BN(zero, 0, ECC_ctx->PUBLIC_KEY->z3);

	return CRYPTO_SUCCESS;
}

/***************************** End of File *****************************/
