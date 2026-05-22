/**
 * \file	ecdh.c
 * @brief	implementation of EC Diffie-Hellman Key Exchange Protocol
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/11/27
 */

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include "ANSI_x931.h"
#include "bignum.h"
#include "fast_math.h"
#include "dh.h"

////////////////////////////////////////////////////////////////////////////
// Functions
////////////////////////////////////////////////////////////////////////////
/**
 * @fn		SDRM_GenerateDHParam(CryptoCoreContainer* crt, unsigned char* pPrime, unsigned int nPrimeLen, unsigned int* pGenerator)
 * @brief	generate parameters for Diffie-Hellman protocol
 *
 * @param	[out] crt				context
 * @param	[out] pPrime			prime number
 * @param	[in]  nPrimeLen			size of pPrime buffer
 * @param	[out] pGenerator		generator value
 *
 * @return	int
 */
CRYPTOCORE_INTERNAL int SDRM_GenerateDHParam(CryptoCoreContainer* crt, unsigned char* pPrime, unsigned int nPrimeLen, unsigned char* pGenerator)
{
	SDRM_DHContext* ctx;
	cc_u32 Seed[4];
	int i, sp, t1;
	SDRM_BIG_NUM *p = NULL;
	SDRM_BIG_NUM *g = NULL;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->dhctx == NULL) || (pPrime == NULL) || (pGenerator == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	ctx = crt->ctx->dhctx;

	p = SDRM_BN_Init(nPrimeLen / 2 + 1);
	if (p == NULL)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	g = SDRM_BN_Init(nPrimeLen / 2 + 1);
	if (g == NULL)
	{
		free(p);
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	for (i = 0; i < 4; i++)
	{
		Seed[i] = (rand() << 16) ^ rand();
	}

	t1 = (nPrimeLen * 8 - 1) % 32;

	//set security parameter for miller-rabin probabilistic primality test
	if (nPrimeLen >= 128)
	{
		sp = 3;
	}
	else if (nPrimeLen >= 64)
	{
		sp = 5;
	}
	else if (nPrimeLen >= 15)
	{
		sp = 15;
	}
	else
	{
		sp = 30;
	}

	//generate p
	p->Length = (nPrimeLen + 3) / 4;
	do {
		SDRM_RNG_X931((cc_u8 *)Seed, nPrimeLen * 8, (cc_u8*)p->pData);
		p->pData[0] |= 1L;
		p->pData[p->Length - 1] &= ~((-1L) << t1);
		p->pData[p->Length - 1] |= (1L << t1);
	} while(SDRM_BN_MILLER_RABIN(p, sp) != CRYPTO_ISPRIME);

	SDRM_I2OSP(p, nPrimeLen, pPrime);

	memset(pGenerator, 0x00, nPrimeLen - 1);
	pGenerator[nPrimeLen - 1] = DH_DEFAULT_GENERATOR;

	SDRM_OS2BN(pGenerator, nPrimeLen, g);

	if (ctx->p != NULL)
	{
		free(ctx->p);
	}
	ctx->p = p;

	if (ctx->g != NULL)
	{
		free(ctx->g);
	}
	ctx->g = g;

	ctx->PrimeLen = nPrimeLen;

	return CRYPTO_SUCCESS;
}

/**
 * @fn		SDRM_SetDHParam(CryptoCoreContainer* crt, unsigned char* pPrime, unsigned int nPrimeLen, unsigned int pGenerator)
 * @brief	set parameters for Diffie-Hellman protocol
 *
 * @param	[out] crt				context
 * @param	[in]  pPrime			prime number
 * @param	[in]  nPrimeLen			size of pPrime buffer
 * @param	[in]  pGenerator		generator value
 *
 * @return	int
 */
CRYPTOCORE_INTERNAL int SDRM_SetDHParam(CryptoCoreContainer* crt, unsigned char* pPrime, unsigned int nPrimeLen, unsigned char* pGenerator, unsigned int nGeneratorLen)
{
	SDRM_DHContext* ctx;
	SDRM_BIG_NUM* p = NULL;
	SDRM_BIG_NUM* g = NULL;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->dhctx == NULL) || (pPrime == NULL) || (pGenerator == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	ctx = crt->ctx->dhctx;

	p = SDRM_BN_Init(nPrimeLen / 2 + 1);
	if (p == NULL)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	g = SDRM_BN_Init(nPrimeLen / 2 + 1);
	if (g == NULL)
	{
		free(p);
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	SDRM_OS2BN(pPrime, nPrimeLen, p);
	SDRM_OS2BN(pGenerator, nGeneratorLen, g);

	ctx->PrimeLen = nPrimeLen;
	ctx->p = p;
	ctx->g = g;

	return CRYPTO_SUCCESS;
}

/**
 * @fn		SDRM_GenerateDHPrivate(CryptoCoreContainer* crt, unsigned char* pPub)
 * @brief	generate private value and calculate public value
 *
 * @param	[in]  crt				context
 * @param	[out] pPriv				private value
 * @param	[out] pPub				public value
 *
 * @return	int
 */
CRYPTOCORE_INTERNAL int SDRM_GenerateDHPrivate(CryptoCoreContainer* crt, unsigned char* pPriv, unsigned char* pPub)
{
	SDRM_DHContext* ctx;
	cc_u32 Seed[4] = {0,};
	int retVal;
	SDRM_BIG_NUM* priv = NULL;
	SDRM_BIG_NUM* pub = NULL;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->dhctx == NULL) || (pPriv == NULL) || (pPub == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	ctx = crt->ctx->dhctx;

	priv = SDRM_BN_Init(ctx->PrimeLen / 2 + 1);
	if (priv == NULL)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	pub = SDRM_BN_Init(ctx->PrimeLen / 2 + 1);
	if (pub == NULL)
	{
		free(priv);
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	//generate priv
	priv->Length = (ctx->PrimeLen + 3) / 4;
	SDRM_RNG_X931((cc_u8 *)Seed, ctx->PrimeLen * 8, (cc_u8*)priv->pData);
	SDRM_BN_ModRed(priv, priv, ctx->p);

#ifndef _OP64_NOTSUPPORTED
	retVal = SDRM_BN_ModExp2(pub, ctx->g, priv, ctx->p);
#else
	retVal = SDRM_BN_ModExp(pub, ctx->g, priv, ctx->p);
#endif	//_OP64_NOTSUPPORTED

	if (retVal != CRYPTO_SUCCESS)
	{
		free(priv);
		free(pub);

		return retVal;
	}

	SDRM_I2OSP(priv, ctx->PrimeLen, pPriv);
	SDRM_I2OSP(pub, ctx->PrimeLen, pPub);

	free(priv);
	free(pub);

	return CRYPTO_SUCCESS;
}

/**
 * @fn		SDRM_GetDHSharedSecret(CryptoCoreContainer* crt, unsigned char* pPriv, unsigned char* pPub, unsigned char* pSharedSecret)
 * @brief	calculate shared secret
 *
 * @param	[in]  crt				context
 * @param	[in]  Priv				private value
 * @param	[in]  pPub				guest's public value
 * @param	[out] pSharedSecret		public value
 *
 * @return	int
 */
CRYPTOCORE_INTERNAL int SDRM_GetDHSharedSecret(CryptoCoreContainer* crt, unsigned char* pPriv, unsigned char* pPub, unsigned char* pSharedSecret)
{
	SDRM_DHContext* ctx;
	SDRM_BIG_NUM* priv = NULL;
	SDRM_BIG_NUM* pub = NULL;
	SDRM_BIG_NUM* SharedSecret = NULL;
	int retVal;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->dhctx == NULL) || (pPriv == NULL) || (pPub == NULL) || (pSharedSecret == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	ctx = crt->ctx->dhctx;

	priv = SDRM_BN_Init(ctx->PrimeLen / 2 + 1);
	if (priv == NULL)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	pub = SDRM_BN_Init(ctx->PrimeLen / 2 + 1);
	if (pub == NULL)
	{
		free(priv);
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	SharedSecret = SDRM_BN_Init(ctx->PrimeLen / 2 + 1);
	if (SharedSecret == NULL)
	{
		free(priv);
		free(pub);
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	SDRM_OS2BN(pPriv, ctx->PrimeLen, priv);
	SDRM_OS2BN(pPub, ctx->PrimeLen, pub);

#ifndef _OP64_NOTSUPPORTED
	retVal = SDRM_BN_ModExp2(SharedSecret, pub, priv, ctx->p);
#else
	retVal = SDRM_BN_ModExp(SharedSecret, pub, priv, ctx->p);
#endif	//_OP64_NOTSUPPORTED

	if (retVal != CRYPTO_SUCCESS)
	{
		free(priv);
		free(pub);
		free(SharedSecret);

		return retVal;
	}

	SDRM_I2OSP(SharedSecret, ctx->PrimeLen, pSharedSecret);

	free(priv);
	free(pub);
	free(SharedSecret);

	return CRYPTO_SUCCESS;
}

/**
 * @fn		SDRM_FreeDHContext(CryptoCoreContainer* crt)
 * @brief	free context buffer
 *
 * @param	[in]  crt				context
 */
CRYPTOCORE_INTERNAL void SDRM_FreeDHContext(SDRM_DHContext* ctx)
{
	if (ctx != NULL)
	{
		if (ctx->p != NULL)
		{
			free(ctx->p);
		}

		if (ctx->g != NULL)
		{
			free(ctx->g);
		}

		memset(ctx, 0x00, sizeof(SDRM_DHContext));
	}
}

/***************************** End of File *****************************/
