/*
 * Implementation of SHA-1
 */

#ifndef _SHA1_H
#define _SHA1_H

#include <stdio.h>
#include <string.h>
#include "CryptoCore.h"

//prototypes

#ifdef __cplusplus
extern "C" {
#endif

CRYPTOCORE_INTERNAL void SDRM_SHA1_Init(SDRM_SHA1Context* ctx);

CRYPTOCORE_INTERNAL void SDRM_SHA1_Update(SDRM_SHA1Context* ctx, const cc_u8* buffer, int ByteCount);

CRYPTOCORE_INTERNAL void SDRM_SHA1_Final(SDRM_SHA1Context* ctx, cc_u8* output);

#ifdef __cplusplus
}
#endif

#endif // _SHA1_H

/***************************** End of File *****************************/
