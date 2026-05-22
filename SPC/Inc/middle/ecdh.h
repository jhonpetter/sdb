/**
 * \file	ecdh.h
 * @brief	implementation of EC Diffie-Hellman Key Exchange Protocol
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/11/27
 */

#ifndef _ECDH_H
#define _ECDH_H

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include "CC_API.h"

////////////////////////////////////////////////////////////////////////////
// Function Prototypes
////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @fn		int SDRM_generateDH1stPhaseKey(CryptoCoreContainer *crt, cc_u8 *pchXk, cc_u8 *pchXv)
 * @brief	generate Xk and its Xv
 *
 * @param	crt					[in]crypto context
 * @param	pchXk				[out]Generated Random Number
 * @param	pchXv				[out]DH 1st phase value
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 */
CRYPTOCORE_INTERNAL  int SDRM_generateDH1stPhaseKey(CryptoCoreContainer *crt, cc_u8 *pchXk, cc_u8 *pchXv);

/*
 * @fn		int SDRM_generateDHKey(CryptoCoreContainer *crt, cc_u8* pchXk, cc_u8* pchYv, cc_u8* pchKauth)
 * @brief	genenrate auth key with Xk and Yv
 *
 * @param	crt					[in]crypto context
 * @param	pchXk				[in]Generated Random Number
 * @param	pchYv				[in]DH 1st phase value
 * @param	pchKauth			[out]authentication key
 *
 * @return	CRYPTO_SUCCESS		if no error is occured
 */
CRYPTOCORE_INTERNAL int SDRM_generateDHKey(CryptoCoreContainer *crt, cc_u8* pchXk, cc_u8* pchYv, cc_u8* pchKauth);

#ifdef __cplusplus
}
#endif

#endif // _ECDH_H

/***************************** End of File *****************************/
