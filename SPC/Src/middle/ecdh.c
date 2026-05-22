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
#include "ecdh.h"
#include "ANSI_x931.h"
#include "ecc.h"

////////////////////////////////////////////////////////////////////////////
// Functions
////////////////////////////////////////////////////////////////////////////
/*
 * @fn		SDRM_generateDH1stPhaseKey
 * @brief	generate Xk and its Xv
 *
 * @param	crt					[in]crypto context
 * @param	pchXk				[out]Generated Random Number
 * @param	pchXv				[out]DH 1st phase value
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 */
CRYPTOCORE_INTERNAL int SDRM_generateDH1stPhaseKey(CryptoCoreContainer *crt, cc_u8 *pchXk, cc_u8 *pchXv)
{
	cc_u8 Si_ANSI_X9_31[SDRM_X931_SEED_SIZ];

	SDRM_BIG_NUM	*BN_Xk, *BN_Temp;
	SDRM_EC_POINT	*kP;
	SDRM_ECC_CTX	*ctx;

	int i;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->ecdhctx == NULL) || (pchXk == NULL) || (pchXv == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	ctx = crt->ctx->ecdhctx;

	for (i = 0; i < SDRM_X931_SEED_SIZ; i++)
	{
		Si_ANSI_X9_31[i] = ((rand() << 16) + rand()) & 0xff;
	}


	BN_Temp = SDRM_BN_Init(crt->ctx->ecdsactx->uDimension >> 3);
	if (BN_Temp == NULL)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	BN_Xk = SDRM_BN_Init(crt->ctx->ecdsactx->uDimension >> 3);
	if (BN_Xk == NULL)
	{
		free(BN_Temp);
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	SDRM_BN_Sub(BN_Temp, ctx->ECC_n, BN_One);
	do {
		SDRM_RNG_X931(Si_ANSI_X9_31, crt->ctx->ecdsactx->uDimension, pchXk);
		SDRM_OS2BN(pchXk, crt->ctx->ecdsactx->uDimension >> 3,  BN_Xk);
	} while ((SDRM_BN_Cmp(BN_Xk, BN_One) < 0) || (SDRM_BN_Cmp(BN_Xk, BN_Temp) > 0));

	kP = SDRM_ECC_Init();
	if (kP == NULL)
	{
		free(BN_Temp);
		free(BN_Xk);

		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	if (SDRM_CTX_EC_kP(ctx, kP, ctx->ECC_G, BN_Xk) == CRYPTO_MEMORY_ALLOC_FAIL)
	{
		free(BN_Temp);
		free(BN_Xk);
		free(kP);

		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	SDRM_BN2OS(kP->x, crt->ctx->ecdsactx->uDimension >> 3, pchXv); 
	SDRM_BN2OS(kP->y, crt->ctx->ecdsactx->uDimension >> 3, pchXv + (crt->ctx->ecdsactx->uDimension >> 3));

	free(BN_Temp);
	free(BN_Xk);
	free(kP);
	
	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_generateDHKey
 * @brief	genenrate auth key with Xk and Yv
 *
 * @param	crt					[in]crypto context
 * @param	pchXk				[in]Generated Random Number
 * @param	pchYv				[in]DH 1st phase value
 * @param	pchKauth			[out]authentication key
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 */
CRYPTOCORE_INTERNAL int SDRM_generateDHKey(CryptoCoreContainer *crt, cc_u8* pchXk, cc_u8* pchYv, cc_u8* pchKauth)
{
	SDRM_BIG_NUM	*BN_Xk;
	SDRM_EC_POINT	*kP, *EC_Yv;
	SDRM_ECC_CTX	*ctx;
	int retVal;

	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->ecdhctx == NULL) || (pchXk == NULL) || (pchYv == NULL) || (pchKauth == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	ctx = crt->ctx->ecdhctx;

	BN_Xk = SDRM_BN_Init(crt->ctx->ecdsactx->uDimension >> 3);
	if (BN_Xk == NULL)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	retVal = SDRM_OS2BN(pchXk, crt->ctx->ecdsactx->uDimension >> 3, BN_Xk);
	if (retVal != CRYPTO_SUCCESS)
	{
		free(BN_Xk);
		return retVal;
	}

	kP = SDRM_ECC_Init();
	if (kP == NULL)
	{
		free(BN_Xk);
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	EC_Yv = SDRM_ECC_Init();
	if (EC_Yv == NULL)
	{
		free(BN_Xk);
		free(kP);

		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	SDRM_EC_CLR(EC_Yv);
	retVal = SDRM_OS2BN(pchYv, crt->ctx->ecdsactx->uDimension >> 3, EC_Yv->x);
	if (retVal != CRYPTO_SUCCESS)
	{
		free(BN_Xk);
		free(kP);
		free(EC_Yv);

		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	retVal = SDRM_OS2BN(pchYv + (crt->ctx->ecdsactx->uDimension >> 3), crt->ctx->ecdsactx->uDimension >> 3, EC_Yv->y);
	if (retVal != CRYPTO_SUCCESS)
	{
		free(BN_Xk);
		free(kP);
		free(EC_Yv);

		return CRYPTO_MEMORY_ALLOC_FAIL;
	}
		
	if (SDRM_CTX_EC_kP(ctx, kP, EC_Yv, BN_Xk) == CRYPTO_MEMORY_ALLOC_FAIL)
	{
		free(BN_Xk);
		free(kP);
		free(EC_Yv);

		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	retVal = SDRM_BN2OS(kP->x, crt->ctx->ecdsactx->uDimension >> 3, pchKauth); 
	if (retVal != CRYPTO_SUCCESS)
	{
		free(BN_Xk);
		free(kP);
		free(EC_Yv);

		return retVal;
	}

	free(BN_Xk);
	free(kP);
	free(EC_Yv);
		
	return CRYPTO_SUCCESS;
}

/***************************** End of File *****************************/
