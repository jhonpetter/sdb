/**
 * \file	rng.h
 * @brief	Random Number Generator Interface
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon, Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/11/07
 */

#ifndef _RNG_H
#define _RNG_H

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include <time.h>
#include "CC_API.h"

////////////////////////////////////////////////////////////////////////////
// Function Prototypes
////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @fn		SDRM_X931_seed
 * @brief	Seed RNG System
 *
 * @param	crt					[in]crypto env structure
 * @param	seed				[in]seed for RNG System
 *
 * @return	CRYPTO_SUCCESS		if success
 */
CRYPTOCORE_INTERNAL int SDRM_X931_seed(CryptoCoreContainer *crt, cc_u8 *seed);

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
CRYPTOCORE_INTERNAL int	SDRM_X931_get(CryptoCoreContainer *crt, cc_u32 bitLength, cc_u8 *data);

#ifdef __cplusplus
}
#endif

#endif // _RNG_H

/***************************** End of File *****************************/
