/**
 * \file	ANSI_x931.h
 * @brief	Pseudorandom number generator based on a design described in ANSI X9.31
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Junbum Shin
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/08/23
 */

#ifndef _ANSI_X931_H
#define _ANSI_X931_H

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include <time.h>
#include "CryptoCore.h"

////////////////////////////////////////////////////////////////////////////
// Function Prototypes
////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @fn		SDRM_RNG_X931	
 * @brief	generate random number with seed
 *
 * @param	Seed				[in]seed for RNG System
 * @param	bitLength			[in]bit length of data to generate
 * @param	data				[out]generated data
 *
 * @return	CRYPTO_SUCCESS		if success
 */
CRYPTOCORE_INTERNAL int	SDRM_RNG_X931(cc_u8 *Seed, cc_u32 bitLength, cc_u8 *data);

#ifdef __cplusplus
}
#endif

#endif

/***************************** End of File *****************************/
