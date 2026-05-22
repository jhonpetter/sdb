/**
 * \file	dsa.c
 * @brief	implementation of dsa signature/verifycation
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/11/23
 */

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include "dsa.h"
#include "bignum.h"
#include "sha1.h"
#include "ANSI_x931.h"

////////////////////////////////////////////////////////////////////////////
// Functions
////////////////////////////////////////////////////////////////////////////
/*
 * @fn		SDRM_Add_DW2BA
 * @brief	Add a UINT32 value to a Byte Array
 *			function works correctly only when dLen >= 4
 *
 * @param	BA						[i/o]byte array
 * @param	dLen					[in]byte-length of BA
 * @param	val						[in]value to add
 *
 * @return	void
 */
CRYPTOCORE_INTERNAL void SDRM_Add_DW2BA(cc_u8* BA, cc_u32 dLen, cc_u32 val)
{
	cc_u32 i, DIGIT = 0;

	if (dLen >= 4)
	{
		DIGIT = BA[dLen - 4] ^ (BA[dLen - 3] << 8) ^ (BA[dLen - 2] << 16) ^ (BA[dLen - 1] << 24);
		DIGIT += val;
		BA[dLen - 4] = (cc_u8)(DIGIT      ) & 0xff;
		BA[dLen - 3] = (cc_u8)(DIGIT >> 8 ) & 0xff;
		BA[dLen - 2] = (cc_u8)(DIGIT >> 16) & 0xff;
		BA[dLen - 1] = (cc_u8)(DIGIT >> 24) & 0xff;

		if (DIGIT < val)
		{
			for (i = dLen - 5; i != (cc_u32)-1; i--)
			{
				if (++BA[i] != 0) 
				{
					return;
				}
			}
		}
	}

	return;
}

/*
 * @fn		SDRM_DSA_InitCrt
 * @brief	generate DSA Context
 *
 * @return	pointer to the generated context
 * \n		NULL	if memory allocation is failed
 */
CRYPTOCORE_INTERNAL SDRM_DSAContext *SDRM_DSA_InitCrt()
{
	SDRM_DSAContext *ctx;
	cc_u8			*pbBuf = (cc_u8*)malloc(sizeof(SDRM_DSAContext) + SDRM_DSA_ALLOC_SIZE * 5);

	if (pbBuf == NULL)
	{
		return NULL;
	}

	ctx		= (SDRM_DSAContext*)(void*)pbBuf;
	ctx->p	= SDRM_BN_Alloc((cc_u8*)ctx	   + sizeof(SDRM_DSAContext),   SDRM_DSA_BN_BUFSIZE);
	ctx->q	= SDRM_BN_Alloc((cc_u8*)ctx->p  + SDRM_DSA_ALLOC_SIZE,		SDRM_DSA_BN_BUFSIZE);
	ctx->al	= SDRM_BN_Alloc((cc_u8*)ctx->q  + SDRM_DSA_ALLOC_SIZE,		SDRM_DSA_BN_BUFSIZE);
	ctx->y	= SDRM_BN_Alloc((cc_u8*)ctx->al + SDRM_DSA_ALLOC_SIZE,		SDRM_DSA_BN_BUFSIZE);
	ctx->a	= SDRM_BN_Alloc((cc_u8*)ctx->y  + SDRM_DSA_ALLOC_SIZE,		SDRM_DSA_BN_BUFSIZE);

	return ctx;
}

/*
 * @fn		int SDRM_DSA_SetParam(CryptoCoreContainer *crt,
				 cc_u8 *DSA_P_Data,	cc_u32 DSA_P_Len,
				 cc_u8 *DSA_Q_Data,	cc_u32 DSA_Q_Len,
				 cc_u8 *DSA_G_Data,	cc_u32 DSA_G_Len)
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
CRYPTOCORE_INTERNAL int SDRM_DSA_SetParam(CryptoCoreContainer *crt,
				 cc_u8 *DSA_P_Data,	cc_u32 DSA_P_Len,
				 cc_u8 *DSA_Q_Data,	cc_u32 DSA_Q_Len,
				 cc_u8 *DSA_G_Data,	cc_u32 DSA_G_Len)
{
	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->dsactx == NULL) || (DSA_P_Data == NULL) || (DSA_Q_Data == NULL) || (DSA_G_Data == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_OS2BN(DSA_P_Data, DSA_P_Len, crt->ctx->dsactx->p);
	SDRM_BN_OPTIMIZE_LENGTH(crt->ctx->dsactx->p);

	SDRM_OS2BN(DSA_Q_Data, DSA_Q_Len, crt->ctx->dsactx->q);
	SDRM_BN_OPTIMIZE_LENGTH(crt->ctx->dsactx->q);

	SDRM_OS2BN(DSA_G_Data, DSA_G_Len, crt->ctx->dsactx->al);
	SDRM_BN_OPTIMIZE_LENGTH(crt->ctx->dsactx->al);

	return CRYPTO_SUCCESS;
}


/*
 * @fn		int SDRM_DSA_SetKeyPair(CryptoCoreContainer *crt,
				   cc_u8 *DSA_Y_Data,	cc_u32 DSA_Y_Len,
				   cc_u8 *DSA_X_Data,	cc_u32 DSA_X_Len)
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
CRYPTOCORE_INTERNAL int SDRM_DSA_SetKeyPair(CryptoCoreContainer *crt,
				   cc_u8 *DSA_Y_Data,	cc_u32 DSA_Y_Len,
				   cc_u8 *DSA_X_Data,	cc_u32 DSA_X_Len)
{
	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->dsactx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	if (DSA_Y_Data != NULL)
	{
		SDRM_OS2BN(DSA_Y_Data, DSA_Y_Len, crt->ctx->dsactx->y);
		SDRM_BN_OPTIMIZE_LENGTH(crt->ctx->dsactx->y);
	}

	if (DSA_X_Data != NULL)
	{
		SDRM_OS2BN(DSA_X_Data, DSA_X_Len, crt->ctx->dsactx->a);
		SDRM_BN_OPTIMIZE_LENGTH(crt->ctx->dsactx->a);
	}

	return CRYPTO_SUCCESS;
}

/*
 * @fn		int SDRM_DSA_GenParam(CryptoCoreContainer *crt, cc_u32 T_Siz,
				 cc_u8 *DSA_P_Data, cc_u32 *DSA_P_Len,
				 cc_u8 *DSA_Q_Data, cc_u32 *DSA_Q_Len,
				 cc_u8 *DSA_G_Data, cc_u32 *DSA_G_Len)
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
CRYPTOCORE_INTERNAL int SDRM_DSA_GenParam(CryptoCoreContainer *crt, cc_u32 T_Siz,
				 cc_u8 *DSA_P_Data, cc_u32 *DSA_P_Len,
				 cc_u8 *DSA_Q_Data, cc_u32 *DSA_Q_Len,
				 cc_u8 *DSA_G_Data, cc_u32 *DSA_G_Len)
{
	cc_u32			 i, k, L, n/*, g*/;
	cc_u8			 pbTemp[260], pbSeed[64];
	SDRM_SHA1Context ctx;
	SDRM_BIG_NUM	 /**BN_A, */*BN_G, *BN_P, *BN_Q, *BN_AL, *BN_Temp;
	cc_u8			 *pbBuf = NULL;
	
	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->dsactx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	if (T_Siz > 8)
	{
		return CRYPTO_INVALID_ARGUMENT;
	}

	L = 512 + 64 * T_Siz;
	n = (L - 1) / 160;
//	g = (L - 1) % 160;


	pbBuf = (cc_u8*)malloc(SDRM_DSA_ALLOC_SIZE * 2);
	if (pbBuf == NULL)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}
	
	BN_G	= SDRM_BN_Alloc((cc_u8*)pbBuf,				 SDRM_DSA_BN_BUFSIZE);
	BN_Temp	= SDRM_BN_Alloc((cc_u8*)BN_G + SDRM_DSA_ALLOC_SIZE, SDRM_DSA_BN_BUFSIZE);

	BN_P  = crt->ctx->dsactx->p;
	BN_Q  = crt->ctx->dsactx->q;
	BN_AL = crt->ctx->dsactx->al;
//	BN_A  = crt->ctx->dsactx->a;

	//generate p and q
	while(1)
	{
		do
		{
			//choose a random seed s of bitlength g >= 160
			for (i = 0; i < SDRM_SHA1_BLOCK_SIZ; i++)
			{
				pbSeed[i] = (rand() << 16) ^ rand();
			}
			pbSeed[0] |= 0x80;
			pbSeed[SDRM_SHA1_BLOCK_SIZ - 1] |= 0x01;

			//U = H(s) xor H((s + 1) mod g)
			SDRM_SHA1_Init(&ctx);
			SDRM_SHA1_Update(&ctx, pbSeed, SDRM_SHA1_BLOCK_SIZ);
			SDRM_SHA1_Final(&ctx, pbTemp);

			SDRM_INC_BA(pbSeed, SDRM_SHA1_BLOCK_SIZ);

			SDRM_SHA1_Init(&ctx);
			SDRM_SHA1_Update(&ctx, pbSeed, SDRM_SHA1_BLOCK_SIZ);
			SDRM_SHA1_Final(&ctx, pbTemp + SDRM_SHA1_BLOCK_SIZ);

			for (i = 0; i < SDRM_SHA1_BLOCK_SIZ / sizeof(cc_u32); i++)
			{
				((cc_u32*)(void*)pbTemp)[i] ^= ((cc_u32*)(void*)pbTemp)[i + SDRM_SHA1_BLOCK_SIZ / sizeof(cc_u32)];
			}

			pbTemp[0] |= 0x80;
			pbTemp[SDRM_SHA1_BLOCK_SIZ - 1] |= 0x01;

			SDRM_OS2BN(pbTemp, SDRM_SHA1_BLOCK_SIZ, BN_Q);
		} while(SDRM_BN_MILLER_RABIN(BN_Q, 18) != CRYPTO_SUCCESS);

		SDRM_INC_BA(pbSeed, SDRM_SHA1_BLOCK_SIZ);

		for (i = 0; i < 4096; i++)
		{
			for (k = 0; k <= n; k++)
			{
				SDRM_SHA1_Init(&ctx);
				SDRM_SHA1_Update(&ctx, pbSeed, SDRM_SHA1_BLOCK_SIZ);
				SDRM_SHA1_Final(&ctx, pbTemp + (n - k) * SDRM_SHA1_BLOCK_SIZ);
				SDRM_Add_DW2BA(pbSeed, SDRM_SHA1_BLOCK_SIZ, n + 2);
			}

			pbTemp[(n + 1) * SDRM_SHA1_BLOCK_SIZ - L / 8] |= 0x80;
			SDRM_OS2BN(pbTemp + (n + 1) * SDRM_SHA1_BLOCK_SIZ - L / 8, L / 8, BN_P);

			SDRM_BN_SHL(BN_Q, BN_Q, 1);
			SDRM_BN_ModRed(BN_Temp, BN_P, BN_Q);
			SDRM_BN_SHR(BN_Q, BN_Q, 1);
			SDRM_BN_Sub(BN_P, BN_P, BN_Temp);
			SDRM_BN_Add(BN_P, BN_P, BN_One);

			if (SDRM_CheckBitUINT32(BN_P->pData, L - 1))
			{
				if (SDRM_BN_MILLER_RABIN(BN_P, 5) == CRYPTO_ISPRIME)
				{
					goto SUCCESS;
				}
				else
				{
					break;
				}
			}
		}
	}

SUCCESS :
	//select a generator al(alpha) of the unique cyclic group of order q in Zp
	SDRM_BN_Clr(BN_Temp);
	//temp = (p-1)/q
	SDRM_BN_Sub(BN_Temp, BN_P, BN_One);
	SDRM_BN_Div(BN_Temp, NULL, BN_Temp, BN_Q);

	do {
		//select an element g excluded in Zp*
		do {
			SDRM_RNG_X931(pbSeed, L, (cc_u8*)BN_G->pData);
			BN_G->Length = L / 32 + 1;
			SDRM_BN_OPTIMIZE_LENGTH(BN_G);
		} while(SDRM_BN_Cmp(BN_G, BN_P) >= 0);

		//al(alpha) = g^temp mod p
		SDRM_BN_ModExp(BN_AL, BN_G, BN_Temp, BN_P);
	} while (SDRM_BN_Cmp(BN_AL, BN_One) == 0);

	//write output
	if (DSA_P_Data != NULL)
	{
		SDRM_I2OSP(BN_P, L / 8, DSA_P_Data);
	}

	if (DSA_P_Len != NULL)
	{
		*DSA_P_Len = L / 8;
	}

	if (DSA_Q_Data != NULL)
	{
		SDRM_I2OSP(BN_Q, 20, DSA_Q_Data);
	}

	if (DSA_Q_Len != NULL)
	{
		*DSA_Q_Len = 20;
	}

	if (DSA_G_Data != NULL)
	{
		SDRM_I2OSP(BN_AL, BN_AL->Length * 4, DSA_G_Data);
	}

	if (DSA_G_Len != NULL)
	{
		*DSA_G_Len = BN_AL->Length * 4;
	}
	
	free(pbBuf);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		int SDRM_DSA_GenKeypair(CryptoCoreContainer *crt,
					    cc_u8 *DSA_Y_Data, cc_u32 *DSA_Y_Len,
					    cc_u8 *DSA_X_Data, cc_u32 *DSA_X_Len)
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
CRYPTOCORE_INTERNAL int SDRM_DSA_GenKeypair(CryptoCoreContainer *crt,
					    cc_u8 *DSA_Y_Data, cc_u32 *DSA_Y_Len,
					    cc_u8 *DSA_X_Data, cc_u32 *DSA_X_Len)
{
	SDRM_BIG_NUM *BN_A;
	cc_u32		 Seed[4], i;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->dsactx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	BN_A = crt->ctx->dsactx->a;

	for (i = 0; i < 4; i++)
	{
		Seed[i] = (rand() << 16) ^ rand();
	}

	//Select a random integer a such that 1 <= a <= q-1
	do {
		SDRM_RNG_X931((cc_u8*)Seed, 160, (cc_u8*)BN_A->pData);
		BN_A->Length = 6;					//6 = 160 / 32 + 1
		SDRM_BN_OPTIMIZE_LENGTH(BN_A);
	} while(SDRM_BN_Cmp(BN_A, crt->ctx->dsactx->q) >= 0);

	//y = al ^ a mod p
	SDRM_BN_ModExp(crt->ctx->dsactx->y, crt->ctx->dsactx->al, BN_A, crt->ctx->dsactx->p);


	//write output
	if (DSA_Y_Data != NULL)
	{
		SDRM_I2OSP(crt->ctx->dsactx->y, crt->ctx->dsactx->y->Length * 4, DSA_Y_Data);
	}

	if (DSA_Y_Len != NULL)
	{
		*DSA_Y_Len = crt->ctx->dsactx->y->Length * 4;
	}

	if (DSA_X_Data != NULL)
	{
		SDRM_I2OSP(BN_A, BN_A->Length * 4, DSA_X_Data);
	}

	if (DSA_X_Len != NULL)
	{
		*DSA_X_Len = BN_A->Length * 4;
	}

	return CRYPTO_SUCCESS;
}

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
CRYPTOCORE_INTERNAL int SDRM_DSA_sign(CryptoCoreContainer *crt, cc_u8 *hash, cc_u32 hashLen, cc_u8 *signature, cc_u32 *signLen)
{
	cc_u8		 pbSeed[16] = {0};
	SDRM_BIG_NUM *BN_P, *BN_Q, *BN_AL, *BN_A;
	SDRM_BIG_NUM *BN_r, *BN_s, *BN_k, *BN_hash, *BN_ar, *temp1, *temp2;

	cc_u8*	pbBuf = NULL;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->dsactx == NULL) || (crt->ctx->dsactx->a == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	pbBuf = (cc_u8*)malloc(SDRM_DSA_ALLOC_SIZE * 7);
	if (!pbBuf)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	BN_r	= SDRM_BN_Alloc( pbBuf,                          SDRM_DSA_BN_BUFSIZE);
	BN_s	= SDRM_BN_Alloc((cc_u8*)BN_r    + SDRM_DSA_ALLOC_SIZE, SDRM_DSA_BN_BUFSIZE);
	BN_k	= SDRM_BN_Alloc((cc_u8*)BN_s    + SDRM_DSA_ALLOC_SIZE, SDRM_DSA_BN_BUFSIZE);
	BN_hash	= SDRM_BN_Alloc((cc_u8*)BN_k    + SDRM_DSA_ALLOC_SIZE, SDRM_DSA_BN_BUFSIZE);
	BN_ar	= SDRM_BN_Alloc((cc_u8*)BN_hash + SDRM_DSA_ALLOC_SIZE, SDRM_DSA_BN_BUFSIZE);
	temp1	= SDRM_BN_Alloc((cc_u8*)BN_ar   + SDRM_DSA_ALLOC_SIZE, SDRM_DSA_BN_BUFSIZE);
	temp2	= SDRM_BN_Alloc((cc_u8*)temp1   + SDRM_DSA_ALLOC_SIZE, SDRM_DSA_BN_BUFSIZE);

	BN_P  = crt->ctx->dsactx->p;
	BN_Q  = crt->ctx->dsactx->q;
	BN_AL = crt->ctx->dsactx->al;
	BN_A  = crt->ctx->dsactx->a;

	//select a random secret integer k, 0 < k < q
	do {
		SDRM_RNG_X931(pbSeed, 160, (cc_u8*)BN_k->pData);
		BN_k->Length = 6;					//6 = 160 / 32 + 1
		SDRM_BN_OPTIMIZE_LENGTH(BN_k);
	} while(SDRM_BN_Cmp(BN_k, BN_Q) > 0);

	SDRM_BN_ModExp(temp1, BN_AL, BN_k, BN_P);
	//r = (al ^ k mod p) mod q
	SDRM_BN_ModRed(BN_r, temp1, BN_Q);

	SDRM_BN_ModInv(temp1, BN_k, BN_Q);

	SDRM_OS2BN((cc_u8*)hash, hashLen, BN_hash);

	SDRM_BN_Mul(BN_ar, BN_A, BN_r);
	SDRM_BN_Add(temp2, BN_hash, BN_ar);

	SDRM_BN_ModRed(temp2, temp2, BN_Q);

	SDRM_BN_ModMul(BN_s, temp1, temp2, BN_Q);

	SDRM_I2OSP(BN_r, 20, signature);
	SDRM_I2OSP(BN_s, 20, signature + 20);

	if (signLen != NULL)
	{
		*signLen = 40;
	}

	free(pbBuf);
	
	return CRYPTO_SUCCESS;
 }

/*
 * @fn		int SDRM_DSA_verify(CryptoCoreContainer *crt, cc_u8 *hash, cc_u32 hashLen, cc_u8 *signature, cc_u32 signLen, int *result)
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
CRYPTOCORE_INTERNAL int SDRM_DSA_verify(CryptoCoreContainer *crt, cc_u8 *hash, cc_u32 hashLen, cc_u8 *signature, cc_u32 signLen, int *result)
{
	SDRM_BIG_NUM *w, *u1, *u2, *v, *BNH_m, *BN_r, *BN_s;
	SDRM_BIG_NUM *temp1, *temp2, *temp3;

	cc_u8		 *pbBuf = NULL;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->dsactx == NULL) || (crt->ctx->dsactx->y == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	pbBuf = (cc_u8*)malloc(SDRM_DSA_ALLOC_SIZE * 10);
	if (!pbBuf)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	w	  =	SDRM_BN_Alloc( pbBuf,		                      SDRM_DSA_BN_BUFSIZE);
	u1	  = SDRM_BN_Alloc((cc_u8*)w     + SDRM_DSA_ALLOC_SIZE, SDRM_DSA_BN_BUFSIZE);
	u2	  = SDRM_BN_Alloc((cc_u8*)u1    + SDRM_DSA_ALLOC_SIZE, SDRM_DSA_BN_BUFSIZE);
	v	  =	SDRM_BN_Alloc((cc_u8*)u2    + SDRM_DSA_ALLOC_SIZE, SDRM_DSA_BN_BUFSIZE);
	BNH_m = SDRM_BN_Alloc((cc_u8*)v     + SDRM_DSA_ALLOC_SIZE, SDRM_DSA_BN_BUFSIZE);
	BN_r  = SDRM_BN_Alloc((cc_u8*)BNH_m + SDRM_DSA_ALLOC_SIZE, SDRM_DSA_BN_BUFSIZE);
	BN_s  = SDRM_BN_Alloc((cc_u8*)BN_r  + SDRM_DSA_ALLOC_SIZE, SDRM_DSA_BN_BUFSIZE);
	temp1 = SDRM_BN_Alloc((cc_u8*)BN_s  + SDRM_DSA_ALLOC_SIZE, SDRM_DSA_BN_BUFSIZE);
	temp2 = SDRM_BN_Alloc((cc_u8*)temp1 + SDRM_DSA_ALLOC_SIZE, SDRM_DSA_BN_BUFSIZE);
	temp3 = SDRM_BN_Alloc((cc_u8*)temp2 + SDRM_DSA_ALLOC_SIZE, SDRM_DSA_BN_BUFSIZE);


	if ((SDRM_BN_Cmp(BN_r, crt->ctx->dsactx->q) >= 0) || (SDRM_BN_Cmp(BN_s, crt->ctx->dsactx->q) >= 0))			//r < q and s < q
	{
		free(pbBuf);
		return CRYPTO_ERROR;
	}

	if (signLen != 40)
	{
		free(pbBuf);
		return CRYPTO_INVALID_ARGUMENT;
	}


	SDRM_OS2BN((cc_u8*)signature,	  20, BN_r);
	SDRM_OS2BN((cc_u8*)signature + 20, 20, BN_s);


	SDRM_BN_ModInv(w, BN_s, crt->ctx->dsactx->q);							//w = s^-1 mod q
	SDRM_OS2BN((cc_u8*)hash, 20, BNH_m);

	SDRM_BN_ModMul(u1, w, BNH_m, crt->ctx->dsactx->q);						//u1 = w x h(m) mod q
	SDRM_BN_ModMul(u2, BN_r, w, crt->ctx->dsactx->q);						//u2 = rw mod q

	SDRM_BN_ModExp(temp1, crt->ctx->dsactx->al, u1, crt->ctx->dsactx->p);	//temp1 = alpha^u1 mod p
	SDRM_BN_ModExp(temp2, crt->ctx->dsactx->y,  u2, crt->ctx->dsactx->p);	//temp2 = y^u2 mod p

	SDRM_BN_ModMul(temp3, temp1, temp2, crt->ctx->dsactx->p);				//temp3 = (alpha^u1 x y^u2 mod p) mod p

	SDRM_BN_ModRed(v, temp3, crt->ctx->dsactx->q);							//v = (alpha^u1 x y^u2 mod p) mod q

//	SDRM_PrintBN("v    : ", v);
//	SDRM_PrintBN("Hash : ", BNH_m);

	if (SDRM_BN_Cmp(v, BN_r) == 0)
	{
		*result = CRYPTO_VALID_SIGN;
	} else
	{
		*result = CRYPTO_INVALID_SIGN;
	}

	free(pbBuf);

	return CRYPTO_SUCCESS;
}

/***************************** End of File *****************************/
