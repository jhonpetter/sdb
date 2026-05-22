/*
 * Implementation of MD5
 */

#ifndef _MD5_H
#define _MD5_H

#include <stdio.h>
#include <string.h>
#include "CryptoCore.h"

//prototypes

#ifdef __cplusplus
extern "C" {
#endif

CRYPTOCORE_INTERNAL void SDRM_MD5_Init(SDRM_MD5Context *ctx);

CRYPTOCORE_INTERNAL void SDRM_MD5_Update(SDRM_MD5Context *ctx, cc_u8* buffer, cc_u32 cc_u8Count);

CRYPTOCORE_INTERNAL void SDRM_MD5_Final(SDRM_MD5Context *ctx, cc_u8* output );

#ifdef __cplusplus
}
#endif

#endif // _MD5_H

/***************************** End of File *****************************/
