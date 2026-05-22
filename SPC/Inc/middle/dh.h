/**
 * \file	dh.h
 * @brief	implementation of Diffie-Hellman Key Exchange Protocol
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2012/04/12
 */

#ifndef _DIFFIE_HELLMAN_H
#define _DIFFIE_HELLMAN_H

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include "CC_API.h"

#define DH_DEFAULT_GENERATOR	5					/**<	fixed generator value	*/

////////////////////////////////////////////////////////////////////////////
// Function Prototypes
////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @fn		SDRM_GenerateDHParam(SDRM_DHContext* crt, unsigned char* pPrime, unsigned int nPrimeLen, unsigned int* pGenerator)
 * @brief	generate parameters for Diffie-Hellman protocol
 *
 * @param	[out] crt				context
 * @param	[out] pPrime			prime number
 * @param	[in]  nPrimeLen			size of pPrime buffer
 * @param	[out] pGenerator		generator value
 * @return	int
 */
CRYPTOCORE_INTERNAL int SDRM_GenerateDHParam(CryptoCoreContainer* crt, unsigned char* pPrime, unsigned int nPrimeLen, unsigned char* pGenerator);

/**
 * @fn		SDRM_SetDHParam(SDRM_DHContext* crt, unsigned char* pPrime, unsigned int nPrimeLen, unsigned int nGenerator)
 * @brief	set parameters for Diffie-Hellman protocol
 *
 * @param	[out] crt				context
 * @param	[in]  pPrime			prime number
 * @param	[in]  nPrimeLen			size of pPrime buffer
 * @param	[in]  pGenerator		generator value
 * @param	[in]  nGeneratorLen		generator len
 * @return	int
 */
CRYPTOCORE_INTERNAL int SDRM_SetDHParam(CryptoCoreContainer* crt, unsigned char* pPrime, unsigned int nPrimeLen, unsigned char* pGenerator, unsigned int nGeneratorLen);

/**
 * @fn		SDRM_GenerateDHPrivate(CryptoCoreContainer* crt, unsigned char* pPub)
 * @brief	generate private value and calculate public value
 *
 * @param	[in]  crt				context
 * @param	[out] pPriv				private value
 * @param	[out] pPub				public value
 * @return	int
 */
CRYPTOCORE_INTERNAL int SDRM_GenerateDHPrivate(CryptoCoreContainer* crt, unsigned char* pPriv, unsigned char* pPub);

/**
 * @fn		SDRM_GetDHSharedSecret(CryptoCoreContainer* crt, unsigned char* pPub, unsigned char* pSharedSecret)
 * @brief	calculate shared secret
 *
 * @param	[in]  crt				context
 * @param	[in]  pPriv				private value
 * @param	[in]  pPub				guest's public value
 * @param	[out] pSharedSecret		public value
 * @return	int
 */
CRYPTOCORE_INTERNAL int SDRM_GetDHSharedSecret(CryptoCoreContainer* crt, unsigned char* pPriv, unsigned char* pPub, unsigned char* pSharedSecret);

/**
 * @fn		SDRM_FreeDHContext(CryptoCoreContainer* crt)
 * @brief	free context buffer
 *
 * @param	[in]  crt				context
 */
CRYPTOCORE_INTERNAL void SDRM_FreeDHContext(SDRM_DHContext* ctx);

#ifdef __cplusplus
}
#endif

#endif // _DIFFIE_HELLMAN_H

/***************************** End of File *****************************/
