/**
 * \file	rng.c
 * @brief	Random Number Generator Interface
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon, Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/11/07
 */

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include "ANSI_x931.h"
#include "rng.h"

////////////////////////////////////////////////////////////////////////////
// Functions
////////////////////////////////////////////////////////////////////////////
/*
 * @fn		SDRM_X931_seed
 * @brief	Seed RNG System
 *
 * @param	crt					[in]crypto env structure
 * @param	seed				[in]seed for RNG System
 *
 * @return	CRYPTO_SUCCESS		if success
 */
CRYPTOCORE_INTERNAL int SDRM_X931_seed(CryptoCoreContainer *crt, cc_u8 *seed)
{
	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->x931ctx == NULL) || (seed == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

	memcpy(crt->ctx->x931ctx->Seed, seed, SDRM_X931_SEED_SIZ);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_X931_get
 * @brief	generate random number
 *
 * @param	crt					[in]crypto env structure
 * @param	bitLength			[in]bit length for generated number
 * @param	data				[out]generated data
 *
 * @return	CRYPTO_SUCCESS		if success
 */
CRYPTOCORE_INTERNAL int	SDRM_X931_get(CryptoCoreContainer *crt, cc_u32 bitLength, cc_u8 *data)
{
	if ((crt == NULL) || (crt->ctx == NULL) || (crt->ctx->x931ctx == NULL) || (data == NULL))
	{
		return CRYPTO_NULL_POINTER;
	}

#ifdef _WIN32_WCE
	srand(GetTickCount());
#else
	srand((unsigned int)time(NULL));
#endif

	return SDRM_RNG_X931(crt->ctx->x931ctx->Seed, bitLength, data);
}

/***************************** End of File *****************************/
