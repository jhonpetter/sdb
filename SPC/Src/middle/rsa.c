/**
 * \file	rsa.c
 * @brief	implementation of rsa encryption/decryption and signature/verifycation
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/11/20
 * Note : Modified for support RSA-2048(Jisoon Park, 2007/03/14)
 */

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include "rsa.h"
#include "pkcs1_v21.h"
#include "ANSI_x931.h"
#include "bignum.h"

//////////////////////////////////////////////////////////////////////////
// Functions
//////////////////////////////////////////////////////////////////////////
/*
 * @fn		SDRM_RSAContext *SDRM_RSA_InitCrt(cc_u32 KeyByteLen)
 *
 * @brief	generate RSA Context
 *
 * @return	pointer to the generated context
 * \n		NULL	if memory allocation is failed
 */
CRYPTOCORE_INTERNAL SDRM_RSAContext *SDRM_RSA_InitCrt(cc_u32 KeyByteLen)
{
	SDRM_RSAContext *ctx;
	cc_u32			RSA_KeyByteLen = KeyByteLen;
	cc_u8			*pbBuf = (cc_u8*)malloc(sizeof(SDRM_RSAContext) + SDRM_RSA_ALLOC_SIZE * 8);

	if (pbBuf == NULL)
	{
		return NULL;
	}

	ctx			= (SDRM_RSAContext*)(void*)pbBuf;
	ctx->n		= SDRM_BN_Alloc((cc_u8*)ctx	   			+ sizeof(SDRM_RSAContext),	SDRM_RSA_BN_BUFSIZE);
	ctx->e		= SDRM_BN_Alloc((cc_u8*)ctx->n  		+ SDRM_RSA_ALLOC_SIZE,		SDRM_RSA_BN_BUFSIZE);
	ctx->d		= SDRM_BN_Alloc((cc_u8*)ctx->e  		+ SDRM_RSA_ALLOC_SIZE,		SDRM_RSA_BN_BUFSIZE);
	ctx->p		= SDRM_BN_Alloc((cc_u8*)ctx->d  		+ SDRM_RSA_ALLOC_SIZE,		SDRM_RSA_BN_BUFSIZE);
	ctx->q		= SDRM_BN_Alloc((cc_u8*)ctx->p  		+ SDRM_RSA_ALLOC_SIZE,		SDRM_RSA_BN_BUFSIZE);
	ctx->dmodp1	= SDRM_BN_Alloc((cc_u8*)ctx->q  		+ SDRM_RSA_ALLOC_SIZE,		SDRM_RSA_BN_BUFSIZE);
	ctx->dmodq1	= SDRM_BN_Alloc((cc_u8*)ctx->dmodp1		+ SDRM_RSA_ALLOC_SIZE,		SDRM_RSA_BN_BUFSIZE);
	ctx->iqmodp	= SDRM_BN_Alloc((cc_u8*)ctx->dmodq1		+ SDRM_RSA_ALLOC_SIZE,		SDRM_RSA_BN_BUFSIZE);

	ctx->crt_operation = (unsigned int)-1;
	ctx->k	= RSA_KeyByteLen;

	return ctx;
}

/*
 * @fn		int SDRM_RSA_setNED(CryptoCoreContainer *crt, cc_u32 PaddingMethod, cc_u8* RSA_N_Data,   cc_u32 RSA_N_Len, cc_u8* RSA_E_Data,   cc_u32 RSA_E_Len, cc_u8* RSA_D_Data,   cc_u32 RSA_D_Len)
 * @brief	set RSA parameters
 *
 * @param	crt					[out]rsa context
 * @param	PaddingMethod		[in]padding method
 * @param	RSA_N_Data			[in]n value
 * @param	RSA_N_Len			[in]byte-length of n
 * @param	RSA_E_Data			[in]e value
 * @param	RSA_E_Len			[in]byte-length of e
 * @param	RSA_D_Data			[in]d value
 * @param	RSA_D_Len			[in]byte-length of d
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if an argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_RSA_setNED(CryptoCoreContainer *crt, cc_u32 PaddingMethod,
				    cc_u8* RSA_N_Data,   cc_u32 RSA_N_Len,
				    cc_u8* RSA_E_Data,   cc_u32 RSA_E_Len,
				    cc_u8* RSA_D_Data,   cc_u32 RSA_D_Len)
{
	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->rsactx == NULL) || (RSA_N_Data == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	SDRM_OS2BN(RSA_N_Data, RSA_N_Len, crt->ctx->rsactx->n);
	SDRM_BN_OPTIMIZE_LENGTH(crt->ctx->rsactx->n);

	if (RSA_E_Data != NULL)
	{
		SDRM_OS2BN(RSA_E_Data, RSA_E_Len, crt->ctx->rsactx->e);
		SDRM_BN_OPTIMIZE_LENGTH(crt->ctx->rsactx->e);
	}

	if (RSA_D_Data != NULL)
	{
		SDRM_OS2BN(RSA_D_Data, RSA_D_Len, crt->ctx->rsactx->d);
		SDRM_BN_OPTIMIZE_LENGTH(crt->ctx->rsactx->d);
	}

	crt->ctx->rsactx->pm = PaddingMethod;
	crt->ctx->rsactx->crt_operation = 0;

	return CRYPTO_SUCCESS;
}

/*
 * @fn		int SDRM_RSA_setNEDPQ(CryptoCoreContainer *crt, cc_u32 PaddingMethod,
 *				    cc_u8* RSA_N_Data,   cc_u32 RSA_N_Len,
 *				    cc_u8* RSA_E_Data,   cc_u32 RSA_E_Len,
 *				    cc_u8* RSA_D_Data,   cc_u32 RSA_D_Len,
 *				    cc_u8* RSA_P_Data,   cc_u32 RSA_P_Len,
 *				    cc_u8* RSA_Q_Data,   cc_u32 RSA_Q_Len,
 *				    cc_u8* RSA_DmodP1_Data,   cc_u32 RSA_DmodP1_Len,
 *				    cc_u8* RSA_DmodQ1_Data,   cc_u32 RSA_DmodQ1_Len,
 *				    cc_u8* RSA_iQmodP_Data,   cc_u32 RSA_iQmodP_Len)
 *
 * @brief	set RSA parameters
 *
 * @param	crt					[out]rsa context
 * @param	PaddingMethod		[in]padding method
 * @param	RSA_N_Data			[in]n value
 * @param	RSA_N_Len			[in]byte-length of n
 * @param	RSA_E_Data			[in]e value
 * @param	RSA_E_Len			[in]byte-length of e
 * @param	RSA_D_Data			[in]d value
 * @param	RSA_D_Len			[in]byte-length of d
 * @param	RSA_P_Data			[in]p value
 * @param	RSA_P_Len			[in]byte-length of p
 * @param	RSA_Q_Data			[in]q value
 * @param	RSA_Q_Len			[in]byte-length of q
 * @param	RSA_DmodP1_Data		[in]d mod (p-1) value
 * @param	RSA_DmodP1_Len		[in]byte-length of d mod (p-1)
 * @param	RSA_DmodQ1_Data		[in]d mod (q-1) value
 * @param	RSA_DmodQ1_Len		[in]byte-length of d mod (q-1)
 * @param	RSA_iQmodP_Data		[in]q^(-1) mod p value
 * @param	RSA_iQmodP_Len		[in]byte-length of q^(-1) mod p
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 * \n		CRYPTO_NULL_POINTER	if an argument is a null pointer
 */
CRYPTOCORE_INTERNAL int SDRM_RSA_setNEDPQ(CryptoCoreContainer *crt, cc_u32 PaddingMethod,
				    cc_u8* RSA_N_Data,   cc_u32 RSA_N_Len,
				    cc_u8* RSA_E_Data,   cc_u32 RSA_E_Len,
				    cc_u8* RSA_D_Data,   cc_u32 RSA_D_Len,
				    cc_u8* RSA_P_Data,   cc_u32 RSA_P_Len,
				    cc_u8* RSA_Q_Data,   cc_u32 RSA_Q_Len,
				    cc_u8* RSA_DmodP1_Data,   cc_u32 RSA_DmodP1_Len,
				    cc_u8* RSA_DmodQ1_Data,   cc_u32 RSA_DmodQ1_Len,
				    cc_u8* RSA_iQmodP_Data,   cc_u32 RSA_iQmodP_Len)
{
	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->rsactx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	crt->ctx->rsactx->crt_operation = 0;
	if ((RSA_P_Data != NULL) && (RSA_Q_Data != NULL) && (RSA_DmodP1_Data != NULL) && (RSA_DmodQ1_Data != NULL) && (RSA_iQmodP_Data != NULL))
	{
		crt->ctx->rsactx->crt_operation = 1;
	}
	else if (RSA_N_Data == NULL)
	{
		return CRYPTO_NULL_POINTER;
	}

	if (RSA_N_Data != NULL)
	{
		SDRM_OS2BN(RSA_N_Data, RSA_N_Len, crt->ctx->rsactx->n);
		SDRM_BN_OPTIMIZE_LENGTH(crt->ctx->rsactx->n);
	}

	if (RSA_E_Data != NULL)
	{
		SDRM_OS2BN(RSA_E_Data, RSA_E_Len, crt->ctx->rsactx->e);
		SDRM_BN_OPTIMIZE_LENGTH(crt->ctx->rsactx->e);
	}

	if (RSA_D_Data != NULL)
	{
		SDRM_OS2BN(RSA_D_Data, RSA_D_Len, crt->ctx->rsactx->d);
		SDRM_BN_OPTIMIZE_LENGTH(crt->ctx->rsactx->d);
	}

	if (RSA_P_Data != NULL)
	{
		SDRM_OS2BN(RSA_P_Data, RSA_P_Len, crt->ctx->rsactx->p);
		SDRM_BN_OPTIMIZE_LENGTH(crt->ctx->rsactx->p);
	}

	if (RSA_Q_Data != NULL)
	{
		SDRM_OS2BN(RSA_Q_Data, RSA_Q_Len, crt->ctx->rsactx->q);
		SDRM_BN_OPTIMIZE_LENGTH(crt->ctx->rsactx->q);
	}

	if (RSA_DmodP1_Data != NULL)
	{
		SDRM_OS2BN(RSA_DmodP1_Data, RSA_DmodP1_Len, crt->ctx->rsactx->dmodp1);
		SDRM_BN_OPTIMIZE_LENGTH(crt->ctx->rsactx->dmodp1);
	}

	if (RSA_DmodQ1_Data != NULL)
	{
		SDRM_OS2BN(RSA_DmodQ1_Data, RSA_DmodQ1_Len, crt->ctx->rsactx->dmodq1);
		SDRM_BN_OPTIMIZE_LENGTH(crt->ctx->rsactx->dmodq1);
	}

	if (RSA_iQmodP_Data != NULL)
	{
		SDRM_OS2BN(RSA_iQmodP_Data, RSA_iQmodP_Len, crt->ctx->rsactx->iqmodp);
		SDRM_BN_OPTIMIZE_LENGTH(crt->ctx->rsactx->iqmodp);
	}

	crt->ctx->rsactx->pm = PaddingMethod;

	return CRYPTO_SUCCESS;
}


/*
 * @fn		int SDRM_RSA_GenerateKey(CryptoCoreContainer *crt, cc_u32 PaddingMethod,
 *						 cc_u8* RSA_N_Data,   cc_u32 *RSA_N_Len,
 *						 cc_u8* RSA_E_Data,   cc_u32 *RSA_E_Len,
 *						 cc_u8* RSA_D_Data,   cc_u32 *RSA_D_Len)
 * @brief	generate and set RSA parameters
 *
 * @param	crt							[in/out]rsa context
 * @param	PaddingMethod				[in]padding method
 * @param	RSA_N_Data					[out]n value
 * @param	RSA_N_Len					[out]byte-length of n
 * @param	RSA_E_Data					[out]e value
 * @param	RSA_E_Len					[out]byte-length of e
 * @param	RSA_D_Data					[out]d value
 * @param	RSA_D_Len					[out]byte-length of d
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_NULL_POINTER			if an argument is a null pointer
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 */
CRYPTOCORE_INTERNAL int SDRM_RSA_GenerateKey(CryptoCoreContainer *crt, cc_u32 PaddingMethod,
						 cc_u8* RSA_N_Data,   cc_u32 *RSA_N_Len,
						 cc_u8* RSA_E_Data,   cc_u32 *RSA_E_Len,
						 cc_u8* RSA_D_Data,   cc_u32 *RSA_D_Len)
{
	cc_u32		 Seed[4];
	SDRM_BIG_NUM *p, *q, *pi, *e, *temp1, *temp2;
	cc_u32		 RSA_KeyByteLen = 0;
	int			 i, sp, t1;
	cc_u8 *pbBuf = NULL;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->rsactx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	RSA_KeyByteLen = crt->ctx->rsactx->k;
	t1 = (RSA_KeyByteLen * 4 - 1) % 32;

	pbBuf = (cc_u8*)malloc(SDRM_RSA_ALLOC_SIZE * 5);
	if (pbBuf == NULL)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	p	  = SDRM_BN_Alloc((cc_u8*)pbBuf,						  SDRM_RSA_BN_BUFSIZE);
	q	  = SDRM_BN_Alloc((cc_u8*)p	   + SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);
	pi	  = SDRM_BN_Alloc((cc_u8*)q	   + SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);
	temp1 = SDRM_BN_Alloc((cc_u8*)pi	   + SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);
	temp2 = SDRM_BN_Alloc((cc_u8*)temp1 + SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);

	e = crt->ctx->rsactx->e;

	for (i = 0; i < 4; i++)
	{
		Seed[i] = (rand() << 16) ^ rand();
	}

	//set security parameter for miller-rabin probabilistic primality test
	if (RSA_KeyByteLen >= 256)
	{
		sp = 3;
	}
	else if (RSA_KeyByteLen >= 128)
	{
		sp = 5;
	}
	else if (RSA_KeyByteLen >= 30)
	{
		sp = 15;
	}
	else
	{
		sp = 30;
	}

GEN_RND:
	//Generate p
	p->Length = (RSA_KeyByteLen + 7) / 8;
	do {
		SDRM_RNG_X931((cc_u8 *)Seed, RSA_KeyByteLen * 4, (cc_u8*)p->pData);
		p->pData[0] |= 1L;
		p->pData[p->Length - 1] &= ~((-1L) << t1);
		p->pData[p->Length - 1] |= (1L << t1);
	} while(SDRM_BN_MILLER_RABIN(p, sp) != CRYPTO_ISPRIME);

	//Generate q
	q->Length = (RSA_KeyByteLen + 7) / 8;
	do {
		SDRM_RNG_X931((cc_u8 *)Seed, RSA_KeyByteLen * 4, (cc_u8*)q->pData);
		q->pData[0] |= 1L;
		q->pData[q->Length - 1] &= ~((-1L) << t1);
		q->pData[q->Length - 1] |= (1L << t1);
	} while(SDRM_BN_MILLER_RABIN(q, sp) != CRYPTO_ISPRIME);

	//temp1 = (p - 1), temp2 = (q - 1)
	SDRM_BN_Sub(temp1, p, BN_One);
	SDRM_BN_Sub(temp2, q, BN_One);

	//evaluate n and pi
	//n = p * q, pi = (p - 1) * (q - 1)
	SDRM_BN_Mul(crt->ctx->rsactx->n, p, q);
	SDRM_BN_Mul(pi, temp1, temp2);

	//generate e
	e->Length = (RSA_KeyByteLen + 3) / 4;
	do {
		do {
			SDRM_RNG_X931((cc_u8 *)Seed, RSA_KeyByteLen * 8 - 8, (cc_u8*)e->pData);
			e->pData[0] |= 0x01;
		} while(SDRM_BN_CheckRelativelyPrime(e, pi) != CRYPTO_ISPRIME);
	} while (SDRM_BN_Cmp(e, pi) >= 0);

	if (SDRM_BN_ModInv(crt->ctx->rsactx->d, e, pi) != CRYPTO_SUCCESS)
	{
		goto GEN_RND;
	}

	crt->ctx->rsactx->pm = PaddingMethod;

	if (RSA_N_Data != NULL)
	{
		SDRM_I2OSP(crt->ctx->rsactx->n, RSA_KeyByteLen, RSA_N_Data);
	}

	if (RSA_N_Len != NULL)
	{
		*RSA_N_Len = RSA_KeyByteLen;
	}

	if (RSA_E_Data != NULL)
	{
		SDRM_I2OSP(crt->ctx->rsactx->e, RSA_KeyByteLen, RSA_E_Data);
	}

	if (RSA_E_Len != NULL)
	{
		*RSA_E_Len = RSA_KeyByteLen;
	}

	if (RSA_D_Data != NULL)
	{
		SDRM_I2OSP(crt->ctx->rsactx->d, RSA_KeyByteLen, RSA_D_Data);
	}

	if (RSA_D_Len != NULL)
	{
		*RSA_D_Len = RSA_KeyByteLen;
	}
	
	free(pbBuf);
	
	crt->ctx->rsactx->crt_operation = 0;

	return CRYPTO_SUCCESS;
}

/*
 * @fn		int SDRM_RSA_GenerateND(CryptoCoreContainer *crt, cc_u32 PaddingMethod,
 *						 cc_u8* RSA_E_Data,   cc_u32 RSA_E_Len,
 *						 cc_u8* RSA_N_Data,   cc_u32 *RSA_N_Len,
 *						 cc_u8* RSA_D_Data,   cc_u32 *RSA_D_Len)
 * @brief	generate and set RSA parameters with specfied e
 *
 * @param	crt							[in/out]rsa context
 * @param	PaddingMethod				[in]padding method
 * @param	RSA_E_Data					[in]e value
 * @param	RSA_E_Len					[in]byte-length of e
 * @param	RSA_N_Data					[out]n value
 * @param	RSA_N_Len					[out]byte-length of n
 * @param	RSA_D_Data					[out]d value
 * @param	RSA_D_Len					[out]byte-length of d
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_NULL_POINTER			if an argument is a null pointer
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 */
CRYPTOCORE_INTERNAL int SDRM_RSA_GenerateND(CryptoCoreContainer *crt, cc_u32 PaddingMethod,
						 cc_u8* RSA_E_Data,   cc_u32 RSA_E_Len,
						 cc_u8* RSA_N_Data,   cc_u32 *RSA_N_Len,
						 cc_u8* RSA_D_Data,   cc_u32 *RSA_D_Len)
{
	cc_u32		 Seed[4];
	SDRM_BIG_NUM *p, *q, *pi, *e, *temp1, *temp2;
	cc_u32		 RSA_KeyByteLen = 0;
	int			 i, sp, t1;
	cc_u8 *pbBuf = NULL;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->rsactx == NULL)) {
		return CRYPTO_NULL_POINTER;
	}

	RSA_KeyByteLen = crt->ctx->rsactx->k;
	t1 = (RSA_KeyByteLen * 4 - 1) % 32;
		
	pbBuf = (cc_u8*)malloc(SDRM_RSA_ALLOC_SIZE * 5);
	if (pbBuf == NULL)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	p	  = SDRM_BN_Alloc((cc_u8*)pbBuf,						  SDRM_RSA_BN_BUFSIZE);
	q	  = SDRM_BN_Alloc((cc_u8*)p	   + SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);
	pi	  = SDRM_BN_Alloc((cc_u8*)q	   + SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);
	temp1 = SDRM_BN_Alloc((cc_u8*)pi	   + SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);
	temp2 = SDRM_BN_Alloc((cc_u8*)temp1 + SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);

	e = crt->ctx->rsactx->e;

	for (i = 0; i < 4; i++)
	{
		Seed[i] = (rand() << 16) ^ rand();
	}

	//set security parameter for miller-rabin probabilistic primality test
	if (RSA_KeyByteLen >= 256)
	{
		sp = 3;
	}
	else if (RSA_KeyByteLen >= 128)
	{
		sp = 5;
	}
	else if (RSA_KeyByteLen >= 30)
	{
		sp = 15;
	}
	else
	{
		sp = 30;
	}

GEN_RND:
	//Generate p
	p->Length = (RSA_KeyByteLen + 7) / 8;
	do {
		SDRM_RNG_X931((cc_u8 *)Seed, RSA_KeyByteLen * 4, (cc_u8*)p->pData);
		p->pData[0] |= 1L;
		p->pData[p->Length - 1] &= ~((-1L) << t1);
		p->pData[p->Length - 1] |= (1L << t1);
	} while(SDRM_BN_MILLER_RABIN(p, sp) != CRYPTO_ISPRIME);

	//Generate q
	q->Length = (RSA_KeyByteLen + 7) / 8;
	do {
		SDRM_RNG_X931((cc_u8 *)Seed, RSA_KeyByteLen * 4, (cc_u8*)q->pData);
		q->pData[0] |= 1L;
		q->pData[q->Length - 1] &= ~((-1L) << t1);
		q->pData[q->Length - 1] |= (1L << t1);
	} while(SDRM_BN_MILLER_RABIN(q, sp) != CRYPTO_ISPRIME);

	//temp1 = (p - 1), temp2 = (q - 1)
	SDRM_BN_Sub(temp1, p, BN_One);
	SDRM_BN_Sub(temp2, q, BN_One);

	//evaluate n and pi
	//n = p * q, pi = (p - 1) * (q - 1)
	SDRM_BN_Mul(crt->ctx->rsactx->n, p, q);
	SDRM_BN_Mul(pi, temp1, temp2);

	//check N for e
	SDRM_OS2BN(RSA_E_Data, RSA_E_Len, e);
	if ((SDRM_BN_CheckRelativelyPrime(e, pi) != CRYPTO_ISPRIME) || (SDRM_BN_Cmp(e, pi) >= 0))
	{
		goto GEN_RND;
	}

	if (SDRM_BN_ModInv(crt->ctx->rsactx->d, e, pi) != CRYPTO_SUCCESS)
	{
		goto GEN_RND;
	}

	crt->ctx->rsactx->pm = PaddingMethod;

	if (RSA_N_Data != NULL)
	{
		SDRM_I2OSP(crt->ctx->rsactx->n, RSA_KeyByteLen, RSA_N_Data);
	}

	if (RSA_N_Len != NULL)
	{
		*RSA_N_Len = RSA_KeyByteLen;
	}

	if (RSA_D_Data != NULL)
	{
		SDRM_I2OSP(crt->ctx->rsactx->d, RSA_KeyByteLen, RSA_D_Data);
	}

	if (RSA_D_Len != NULL)
	{
		*RSA_D_Len = RSA_KeyByteLen;
	}
	
	free(pbBuf);
	
	crt->ctx->rsactx->crt_operation = 0;

	return CRYPTO_SUCCESS;
}

/*
 * @fn		int SDRM_RSA_GenerateDwithPQE(CryptoCoreContainer *crt, cc_u32 PaddingMethod,
 *						 cc_u8* RSA_E_Data,   cc_u32 RSA_E_Len,
 *						 cc_u8* RSA_P_Data,   cc_u32 RSA_P_Len,
 *						 cc_u8* RSA_Q_Data,   cc_u32 RSA_Q_Len,
 *						 cc_u8* RSA_N_Data,   cc_u32 *RSA_N_Len,
 *						 cc_u8* RSA_D_Data,   cc_u32 *RSA_D_Len)
 * @brief	generate D with specfied p, q, d mod (p-1), d mod (q-1) and e
 *
 * @param	crt							[in/out]rsa context
 * @param	PaddingMethod				[in]padding method
 * @param	RSA_E_Data					[in]e value
 * @param	RSA_E_Len					[in]byte-length of e
 * @param	RSA_P_Data					[in]n value
 * @param	RSA_P_Len					[in]byte-length of n
 * @param	RSA_Q_Data					[in]d value
 * @param	RSA_Q_Len					[in]byte-length of d
 * @param	RSA_D_P_Data				[in]d mod (p-1) value
 * @param	RSA_D_P_Len					[in]byte-length of d mod (p-1) 
 * @param	RSA_D_Q_Data				[in]d mod (q-1)  value
 * @param	RSA_D_Q_Len					[in]byte-length of d mod (q-1) 
 * @param	RSA_D_Data					[out]d value
 * @param	RSA_D_Len					[out]byte-length of d
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_NULL_POINTER			if an argument is a null pointer
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 */
CRYPTOCORE_INTERNAL int SDRM_RSA_GenerateDwithPQE(CryptoCoreContainer *crt, cc_u32 PaddingMethod,
						 cc_u8* RSA_E_Data,   cc_u32 RSA_E_Len,
						 cc_u8* RSA_P_Data,   cc_u32 RSA_P_Len,
						 cc_u8* RSA_Q_Data,   cc_u32 RSA_Q_Len,
						 cc_u8* RSA_N_Data,   cc_u32 *RSA_N_Len,
						 cc_u8* RSA_D_Data,   cc_u32 *RSA_D_Len)
{
	SDRM_BIG_NUM *p, *q, *pi, *e, *temp1, *temp2;
	cc_u32		 RSA_KeyByteLen = 0;
	int			 sp;
	cc_u8 *pbBuf = NULL;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->rsactx == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	RSA_KeyByteLen = crt->ctx->rsactx->k;
		
	pbBuf = (cc_u8*)malloc(SDRM_RSA_ALLOC_SIZE * 5);
	if (pbBuf == NULL)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	p	  = SDRM_BN_Alloc((cc_u8*)pbBuf,						  SDRM_RSA_BN_BUFSIZE);
	q	  = SDRM_BN_Alloc((cc_u8*)p	   + SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);
	pi	  = SDRM_BN_Alloc((cc_u8*)q	   + SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);
	temp1 = SDRM_BN_Alloc((cc_u8*)pi	   + SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);
	temp2 = SDRM_BN_Alloc((cc_u8*)temp1 + SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);

	e = crt->ctx->rsactx->e;

	//set security parameter for miller-rabin probabilistic primality test
	if (RSA_KeyByteLen >= 256)
	{
		sp = 3;
	}
	else if (RSA_KeyByteLen >= 128)
	{
		sp = 5;
	}
	else if (RSA_KeyByteLen >= 30)
	{
		sp = 15;
	}
	else
	{
		sp = 30;
	}

	SDRM_OS2BN((cc_u8*)RSA_P_Data, RSA_P_Len, p);	
	if (SDRM_BN_MILLER_RABIN(p, sp) != CRYPTO_ISPRIME)
	{
		free(pbBuf);
		return CRYPTO_INVALID_ARGUMENT;
	}

 	SDRM_OS2BN((cc_u8*)RSA_Q_Data, RSA_Q_Len, q);	
	if (SDRM_BN_MILLER_RABIN(q, sp) != CRYPTO_ISPRIME)
	{
		free(pbBuf);
		return CRYPTO_INVALID_ARGUMENT;
	}

	//temp1 = (p - 1), temp2 = (q - 1)
	SDRM_BN_Sub(temp1, p, BN_One);
	SDRM_BN_Sub(temp2, q, BN_One);

	//evaluate n and pi
	//n = p * q, pi = (p - 1) * (q - 1)
	SDRM_BN_Mul(crt->ctx->rsactx->n, p, q);
	SDRM_BN_Mul(pi, temp1, temp2);

	//check N for e
	SDRM_OS2BN(RSA_E_Data, RSA_E_Len, e);
	if ((SDRM_BN_CheckRelativelyPrime(e, pi) != CRYPTO_ISPRIME) || (SDRM_BN_Cmp(e, pi) >= 0))
	{
		free(pbBuf);
		return CRYPTO_INVALID_ARGUMENT;
	}

	if (SDRM_BN_ModInv(crt->ctx->rsactx->d, e, pi) != CRYPTO_SUCCESS)
	{
		free(pbBuf);
		return CRYPTO_INVALID_ARGUMENT;
	}

	crt->ctx->rsactx->pm = PaddingMethod;

	if (RSA_N_Data != NULL)
	{
		SDRM_I2OSP(crt->ctx->rsactx->n, RSA_KeyByteLen, RSA_N_Data);
	}

	if (RSA_N_Len != NULL)
	{
		*RSA_N_Len = RSA_KeyByteLen;
	}

	if (RSA_D_Data != NULL)
	{
		SDRM_I2OSP(crt->ctx->rsactx->d, RSA_KeyByteLen, RSA_D_Data);
	}

	if (RSA_D_Len != NULL)
	{
		*RSA_D_Len = RSA_KeyByteLen;
	}
	
	free(pbBuf);
	
	crt->ctx->rsactx->crt_operation = 0;

	return CRYPTO_SUCCESS;
}

/*
 * @fn		int SDRM_RSA_encrypt(CryptoCoreContainer *crt, cc_u8 *in, cc_u32 inLen, cc_u8 *out, cc_u32 *outLen)
 * @brief	RSA Encryption
 *
 * @param	crt							[in]rsa context
 * @param	in							[in]message to encrypt
 * @param	inLen						[in]byte-length of in
 * @param	out							[out]encrypted message
 * @param	outLen						[out]byte-length of out
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_NULL_POINTER			if an argument is a null pointer
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 */
CRYPTOCORE_INTERNAL int SDRM_RSA_encrypt(CryptoCoreContainer *crt, cc_u8 *in, cc_u32 inLen, cc_u8 *out, cc_u32 *outLen)
{
	SDRM_BIG_NUM *BN_pMsg, *BN_Src, *BN_Cipher;
	int			 retVal, cipherLen;
	cc_u32		 RSA_KeyByteLen = 0;
	cc_u8		 *pbBuf = NULL;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->rsactx == NULL) || (in == NULL) || (out == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	RSA_KeyByteLen = crt->ctx->rsactx->k;
	if (inLen > RSA_KeyByteLen)
	{
		return CRYPTO_MSG_TOO_LONG;
	}

	pbBuf = (cc_u8*)malloc(SDRM_RSA_ALLOC_SIZE * 3);
	if (pbBuf == NULL)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	BN_pMsg	  = SDRM_BN_Alloc((cc_u8*)pbBuf,						 SDRM_RSA_BN_BUFSIZE);
	BN_Src	  = SDRM_BN_Alloc((cc_u8*)BN_pMsg + SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);
	BN_Cipher = SDRM_BN_Alloc((cc_u8*)BN_Src  + SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);

	SDRM_OS2BN(in, inLen, BN_Src);

	//Padding the message
	switch(SDRM_LOW_HALF(crt->ctx->rsactx->pm))
	{
		case ID_RSAES_PKCS15 :
			retVal = SDRM_Padding_Rsaes_pkcs15(BN_pMsg, BN_Src, SDRM_ENPADDING, RSA_KeyByteLen);
			break;
		case ID_RSAES_OAEP :
			retVal = SDRM_Padding_Rsaes_oaep(BN_pMsg, BN_Src, SDRM_ENPADDING, SDRM_HIGH_HALF(crt->ctx->rsactx->pm), RSA_KeyByteLen);
			break;
		case ID_NO_PADDING :
			SDRM_BN_Copy(BN_pMsg, BN_Src);
			retVal = CRYPTO_SUCCESS;
			break;
		default :
			free(pbBuf);
			return CRYPTO_INVALID_ARGUMENT;
	}

//	SDRM_PrintBN("ENPADDED Text  : ", BN_pMsg);

	if (retVal != CRYPTO_SUCCESS)
	{
		free(pbBuf);
		return retVal;
	}

	//RSA Encryption by modular exponent
#ifndef _OP64_NOTSUPPORTED
	retVal = SDRM_BN_ModExp2(BN_Cipher, BN_pMsg, crt->ctx->rsactx->e, crt->ctx->rsactx->n);
#else
	retVal = SDRM_BN_ModExp(BN_Cipher, BN_pMsg, crt->ctx->rsactx->e, crt->ctx->rsactx->n);
#endif	//_OP64_NOTSUPPORTED

	if (retVal != CRYPTO_SUCCESS)
	{
		free(pbBuf);
		return retVal;
	}

	SDRM_BN_GETBYTELEN(BN_Cipher, cipherLen);

	SDRM_I2OSP(BN_Cipher, cipherLen, out);

	if (outLen != NULL)
	{
		*outLen = cipherLen;
	}

	free(pbBuf);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		int SDRM_RSA_decrypt(CryptoCoreContainer *crt, cc_u8 *in, cc_u32 inLen, cc_u8 *out, cc_u32 *outLen)
 * @brief	RSA Decryption
 *
 * @param	crt							[in]rsa context
 * @param	in							[in]message to decrypt
 * @param	inLen						[in]byte-length of in
 * @param	out							[out]decrypted message
 * @param	outLen						[out]byte-length of out
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_NULL_POINTER			if an argument is a null pointer
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 */
CRYPTOCORE_INTERNAL int SDRM_RSA_decrypt(CryptoCoreContainer *crt, cc_u8 *in, cc_u32 inLen, cc_u8 *out, cc_u32 *outLen)
{
	SDRM_BIG_NUM	*BN_dMsg, *BN_Plain, *BN_Src;
	int				retVal, plainLen;
	cc_u32			RSA_KeyByteLen = 0;
	cc_u8			*pbBuf = NULL;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->rsactx == NULL) || (in == NULL) || (out == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	RSA_KeyByteLen = crt->ctx->rsactx->k;
	if (inLen > RSA_KeyByteLen)
	{
		return CRYPTO_MSG_TOO_LONG;
	}

	pbBuf = (cc_u8*)malloc(SDRM_RSA_ALLOC_SIZE * 3);
	if (pbBuf == NULL)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	BN_dMsg	  = SDRM_BN_Alloc((cc_u8*)pbBuf,					  SDRM_RSA_BN_BUFSIZE);
	BN_Src	  = SDRM_BN_Alloc((cc_u8*)BN_dMsg + SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);
	BN_Plain  = SDRM_BN_Alloc((cc_u8*)BN_Src  + SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);

	SDRM_OS2BN(in, inLen, BN_Src);
	
	//RSA Decryption by modular exponent
#ifndef _OP64_NOTSUPPORTED
	retVal = SDRM_BN_ModExp2(BN_dMsg, BN_Src, crt->ctx->rsactx->d, crt->ctx->rsactx->n);
#else
	retVal = SDRM_BN_ModExp(BN_dMsg, BN_Src, crt->ctx->rsactx->d, crt->ctx->rsactx->n);
#endif	//_OP64_NOTSUPPORTED

	if (retVal != CRYPTO_SUCCESS)
	{
		free(pbBuf);
		return retVal;
	}

	//Remove Padding from message
	switch(SDRM_LOW_HALF(crt->ctx->rsactx->pm))
	{
		case ID_RSAES_PKCS15 :
			retVal = SDRM_Padding_Rsaes_pkcs15(BN_Plain, BN_dMsg, SDRM_DEPADDING, RSA_KeyByteLen);
			break;
		case ID_RSAES_OAEP :
			retVal = SDRM_Padding_Rsaes_oaep(BN_Plain, BN_dMsg, SDRM_DEPADDING, SDRM_HIGH_HALF(crt->ctx->rsactx->pm), RSA_KeyByteLen);
			break;
		case ID_NO_PADDING :
			SDRM_BN_Copy(BN_Plain, BN_dMsg);
			retVal = CRYPTO_SUCCESS;
			break;
		default :
			free(pbBuf);
			return CRYPTO_INVALID_ARGUMENT;
	}

	if (retVal != CRYPTO_SUCCESS)
	{
		free(pbBuf);
		return retVal;
	}

	SDRM_BN_GETBYTELEN(BN_Plain, plainLen);

	SDRM_I2OSP(BN_Plain, plainLen, out);

	if (outLen != NULL)
	{
		*outLen = plainLen;
	}

//	SDRM_PrintBN("DEPADDED Text  : ", BN_Plain);

	free(pbBuf);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		int SDRM_RSA_decryptByCRT(CryptoCoreContainer *crt, cc_u8 *in, cc_u32 inLen, cc_u8 *out, cc_u32 *outLen)
 * @brief	RSA Decryption using CRT
 *
 * @param	crt							[in]rsa context
 * @param	in							[in]message to decrypt
 * @param	inLen						[in]byte-length of in
 * @param	out							[out]decrypted message
 * @param	outLen						[out]byte-length of out
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_NULL_POINTER			if an argument is a null pointer
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 */
CRYPTOCORE_INTERNAL int SDRM_RSA_decryptByCRT(CryptoCoreContainer *crt, cc_u8 *in, cc_u32 inLen, cc_u8 *out, cc_u32 *outLen)
{
	SDRM_BIG_NUM	*BN_dMsg, *BN_Plain, *BN_Src;
	int				retVal, plainLen;
	cc_u32			RSA_KeyByteLen = 0;
	SDRM_BIG_NUM *pi, *temp1, *temp2, *m1, *m2, *h;
	cc_u8			*pbBuf = NULL;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->rsactx == NULL) || (in == NULL) || (out == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	if (crt->ctx->rsactx->crt_operation != 1)
	{
		return CRYPTO_INVALID_ARGUMENT;
	}

	RSA_KeyByteLen = crt->ctx->rsactx->k;
	if (inLen > RSA_KeyByteLen)
	{
		return CRYPTO_MSG_TOO_LONG;
	}

	pbBuf = (cc_u8*)malloc(SDRM_RSA_ALLOC_SIZE * 9);
	if (pbBuf == NULL)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	BN_dMsg		= SDRM_BN_Alloc((cc_u8*)pbBuf,							   SDRM_RSA_BN_BUFSIZE);
	BN_Src		= SDRM_BN_Alloc((cc_u8*)BN_dMsg		+ SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);
	BN_Plain	= SDRM_BN_Alloc((cc_u8*)BN_Src		+ SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);
	pi			= SDRM_BN_Alloc((cc_u8*)BN_Plain	+ SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);
	temp1		= SDRM_BN_Alloc((cc_u8*)pi 			+ SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);
	temp2		= SDRM_BN_Alloc((cc_u8*)temp1		+ SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);
	m1			= SDRM_BN_Alloc((cc_u8*)temp2		+ SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);
	m2			= SDRM_BN_Alloc((cc_u8*)m1 			+ SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);
	h			= SDRM_BN_Alloc((cc_u8*)m2			+ SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);

	SDRM_OS2BN(in, inLen, BN_Src);
	
	//RSA Decryption by CRT
	/*
		dp = d mod (p - 1)
		dq = d mod (q - 1)
		qInv = (1/q) mod p  where p > q
	=> 
		m1 = c^dp mod p
		m2 = c^dq mod q
		h = qInv(m1 - m2) mod p if (m1 >= m2) or h = qInv(m1 + p - m2) mod p if (m1 < m2)
		m = m2 + hq
	*/

	// Prepare variables
	// 1. dP = d mod (p - 1)
	//	dP is already set when SDRM_RSA_setNEDPQ

	// 2. dQ = d mod (q - 1)
	//	dQ is already set when SDRM_RSA_setNEDPQ

	// 3. qInv = (1/q) mod p  where p > q
	//	qInv is already set when SDRM_RSA_setNEDPQ

	// Computation
	// 4. m1 = c^dP mod p
	if(SDRM_BN_ModExp2(m1, BN_Src, crt->ctx->rsactx->dmodp1, crt->ctx->rsactx->p))
	{
		free(pbBuf);
		return CRYPTO_INVALID_ARGUMENT;
	}

	// 5. m2 = c^dQ mod q
	if(SDRM_BN_ModExp2(m2, BN_Src, crt->ctx->rsactx->dmodq1, crt->ctx->rsactx->q))
	{
		free(pbBuf);
		return CRYPTO_INVALID_ARGUMENT;
	}

	// 6. h = qInv(m1 - m2) mod p if (m1 >= m2) or h = qInv(m1 + p - m2) mod p if (m1 < m2)
	if(SDRM_BN_Cmp(m1, m2) < 0)
	{
		if(SDRM_BN_Add(m1, m1, crt->ctx->rsactx->p))
		{
			free(pbBuf);
			return CRYPTO_INVALID_ARGUMENT;
		}
	}

	if(SDRM_BN_Sub(m1, m1, m2))
	{
		free(pbBuf);
		return CRYPTO_INVALID_ARGUMENT;
	}

	if(SDRM_BN_ModMul(h, crt->ctx->rsactx->iqmodp, m1, crt->ctx->rsactx->p))
	{
		free(pbBuf);
		return CRYPTO_INVALID_ARGUMENT;
	}
	
	// 7. m = m2 + hq
	if(SDRM_BN_Mul(h, h, crt->ctx->rsactx->q))
	{
		free(pbBuf);
		return CRYPTO_INVALID_ARGUMENT;
	}
		
	if(SDRM_BN_Add(BN_dMsg, m2, h))
	{
		free(pbBuf);
		return CRYPTO_INVALID_ARGUMENT;
	}

//	SDRM_PrintBN("OAEP Text  : ", BN_dMsg);

	//Remove Padding from message
	switch(SDRM_LOW_HALF(crt->ctx->rsactx->pm))
	{
		case ID_RSAES_PKCS15 :
			retVal = SDRM_Padding_Rsaes_pkcs15(BN_Plain, BN_dMsg, SDRM_DEPADDING, RSA_KeyByteLen);
			break;
		case ID_RSAES_OAEP :
			retVal = SDRM_Padding_Rsaes_oaep(BN_Plain, BN_dMsg, SDRM_DEPADDING, SDRM_HIGH_HALF(crt->ctx->rsactx->pm), RSA_KeyByteLen);
			break;
		case ID_NO_PADDING :
			SDRM_BN_Copy(BN_Plain, BN_dMsg);
			retVal = CRYPTO_SUCCESS;
			break;
		default :
			free(pbBuf);
			return CRYPTO_INVALID_ARGUMENT;
	}

	if (retVal != CRYPTO_SUCCESS)
	{
		free(pbBuf);
		return retVal;
	}

	SDRM_BN_GETBYTELEN(BN_Plain, plainLen);

	SDRM_I2OSP(BN_Plain, plainLen, out);

	if (outLen != NULL)
	{
		*outLen = plainLen;
	}

//	SDRM_PrintBN("DEPADDED Text  : ", BN_Plain);

	free(pbBuf);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		int SDRM_RSA_sign(CryptoCoreContainer *crt, cc_u8 *hash, cc_u32 hashLen, cc_u8 *signature, cc_u32 *signLen)
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
CRYPTOCORE_INTERNAL int SDRM_RSA_sign(CryptoCoreContainer *crt, cc_u8 *hash, cc_u32 hashLen, cc_u8 *signature, cc_u32 *signLen)
{
	SDRM_BIG_NUM	*BN_pMsg, *BN_Sign;
	cc_u32			SignatureLength;
	int				retVal;
	cc_u32			RSA_KeyByteLen = 0;
	cc_u8			*pbBuf = NULL;
	cc_u32			emBits;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->rsactx == NULL) || (hash == NULL) || (signature == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	RSA_KeyByteLen = crt->ctx->rsactx->k;
	if (hashLen > RSA_KeyByteLen)
	{
		return CRYPTO_MSG_TOO_LONG;
	}

	pbBuf = (cc_u8*)malloc(SDRM_RSA_ALLOC_SIZE * 3);	
	if (pbBuf == NULL)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	BN_pMsg	  = SDRM_BN_Alloc((cc_u8*)pbBuf,					  SDRM_RSA_BN_BUFSIZE);
	BN_Sign	  = SDRM_BN_Alloc((cc_u8*)BN_pMsg + SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);

	//Msg Padding
	switch(SDRM_LOW_HALF(crt->ctx->rsactx->pm))
	{
		case ID_RSASSA_PKCS15 :
			SDRM_Padding_Rsassa_pkcs15(BN_pMsg, NULL, hash, SDRM_ENPADDING, SDRM_HIGH_HALF(crt->ctx->rsactx->pm), RSA_KeyByteLen);
			break;
		case ID_RSASSA_PSS :
			SDRM_BN_GETBITLEN(crt->ctx->rsactx->n, emBits);
			SDRM_Padding_Rsassa_pss(BN_pMsg, NULL, hash, emBits, SDRM_ENPADDING, SDRM_HIGH_HALF(crt->ctx->rsactx->pm), SDRM_CheckByteUINT32(crt->ctx->rsactx->n->pData, RSA_KeyByteLen - 1));
			break;
		case ID_NO_PADDING :
			SDRM_OS2BN(hash, hashLen, BN_pMsg);
			break;
		default :
			free(pbBuf);
			return CRYPTO_INVALID_ARGUMENT;
	}

//	SDRM_PrintBN("ENPADDED Msg   : ", BN_pMsg);

	//RSA Signature by modular exponent
#ifndef _OP64_NOTSUPPORTED
	retVal = SDRM_BN_ModExp2(BN_Sign, BN_pMsg, crt->ctx->rsactx->d, crt->ctx->rsactx->n);
#else
	retVal = SDRM_BN_ModExp(BN_Sign, BN_pMsg, crt->ctx->rsactx->d, crt->ctx->rsactx->n);
#endif	//_OP64_NOTSUPPORTED

	if (retVal != CRYPTO_SUCCESS) 
	{
		free(pbBuf);
		return retVal;
	}

	SDRM_BN_GETBYTELEN(BN_Sign, SignatureLength);
	SDRM_I2OSP(BN_Sign, SignatureLength, signature);

	if (signLen != NULL)
	{
		*signLen = SignatureLength;
	}

	free(pbBuf);

	return retVal;
}

/*
 * @fn		int SDRM_RSA_verify(CryptoCoreContainer *crt, cc_u8 *hash, cc_u32 hashLen, cc_u8 *signature, cc_u32 signLen, int *result)
 * @brief	generate signature for given value
 *
 * @param	crt						[in]crypto env structure
 * @param	hash					[in]hash value
 * @param	hashLen					[in]byte-length of hash
 * @param	signature				[in]signature
 * @param	signLen					[in]byte-length of signature
 * @param	result					[in]result of verifying signature
 *
 * @return	CRYPTO_SUCCESS			if success
 * \n		CRYPTO_NULL_POINTER		if given argument is a null pointer
 * \n		CRYPTO_INVALID_ARGUMENT	if the length of signature is invalid
 */
CRYPTOCORE_INTERNAL int SDRM_RSA_verify(CryptoCoreContainer *crt, cc_u8 *hash, cc_u32 hashLen, cc_u8 *signature, cc_u32 signLen, int *result)
{
	SDRM_BIG_NUM	*BN_dMsg, *BN_Sign;
	int				retVal;
	cc_u32			RSA_KeyByteLen = 0;
	cc_u8			*pbBuf = NULL;
	cc_u32			emBits;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->rsactx == NULL) || (hash == NULL) || (signature == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	RSA_KeyByteLen = crt->ctx->rsactx->k;
	if (hashLen > RSA_KeyByteLen)
	{
		return CRYPTO_MSG_TOO_LONG;
	}

	pbBuf = (cc_u8*)malloc(SDRM_RSA_ALLOC_SIZE * 3);
	if (pbBuf == NULL)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	BN_dMsg	  = SDRM_BN_Alloc((cc_u8*)pbBuf,					  SDRM_RSA_BN_BUFSIZE);
	BN_Sign	  = SDRM_BN_Alloc((cc_u8*)BN_dMsg + SDRM_RSA_ALLOC_SIZE, SDRM_RSA_BN_BUFSIZE);

	SDRM_OS2BN(signature, signLen, BN_Sign);
//	SDRM_PrintBN("Generated Sign : ", BN_Sign);
	
	//RSA Verification by modular exponent
#ifndef _OP64_NOTSUPPORTED
	retVal = SDRM_BN_ModExp2(BN_dMsg, BN_Sign, crt->ctx->rsactx->e, crt->ctx->rsactx->n);
#else
	retVal = SDRM_BN_ModExp(BN_dMsg, BN_Sign, crt->ctx->rsactx->e, crt->ctx->rsactx->n);
#endif	//_OP64_NOTSUPPORTED

	if (retVal != CRYPTO_SUCCESS)
	{
		free(pbBuf);
		return retVal;
	}

	//Msg Depadding
	switch(SDRM_LOW_HALF(crt->ctx->rsactx->pm))
	{
		case ID_RSASSA_PKCS15 :
			*result = SDRM_Padding_Rsassa_pkcs15(NULL, BN_dMsg, hash, SDRM_DEPADDING, SDRM_HIGH_HALF(crt->ctx->rsactx->pm), RSA_KeyByteLen);
			break;
		case ID_RSASSA_PSS :
			SDRM_BN_GETBITLEN(crt->ctx->rsactx->n, emBits);
			*result = SDRM_Padding_Rsassa_pss(NULL, BN_dMsg, hash, emBits, SDRM_DEPADDING, SDRM_HIGH_HALF(crt->ctx->rsactx->pm), SDRM_CheckByteUINT32(crt->ctx->rsactx->n->pData, RSA_KeyByteLen - 1));
			break;
		case ID_NO_PADDING :
			SDRM_OS2BN(hash, hashLen, BN_Sign);
			if (SDRM_BN_Cmp(BN_Sign, BN_dMsg) == 0)
			{
				*result = CRYPTO_VALID_SIGN;
			}
			else
			{
				*result = CRYPTO_INVALID_SIGN;
			}

		default :
			break;
	}

	SDRM_BN_FREE(pbBuf);

	return CRYPTO_SUCCESS;
}

/***************************** End of File *****************************/

