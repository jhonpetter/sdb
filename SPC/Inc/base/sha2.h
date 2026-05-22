/*
 * Implementation of SHA-2
 */

#ifndef _SHA2_H
#define _SHA2_H

#include <stdio.h>
#include <string.h>
#include "CryptoCore.h"

//prototypes

#ifdef __cplusplus
extern "C" {
#endif

CRYPTOCORE_INTERNAL void SDRM_SHA224_Init(SDRM_SHA224Context* ctx);
CRYPTOCORE_INTERNAL void SDRM_SHA224_Update(SDRM_SHA224Context* ctx, const cc_u8 *message, cc_u32 len);
CRYPTOCORE_INTERNAL void SDRM_SHA224_Final(SDRM_SHA224Context* ctx, cc_u8 *digest);

CRYPTOCORE_INTERNAL void SDRM_SHA256_Init(SDRM_SHA256Context* ctx);
CRYPTOCORE_INTERNAL void SDRM_SHA256_Update(SDRM_SHA256Context* ctx, const cc_u8 *message, cc_u32 len);
CRYPTOCORE_INTERNAL void SDRM_SHA256_Final(SDRM_SHA256Context* ctx, cc_u8 *digest);

#ifndef _OP64_NOTSUPPORTED

CRYPTOCORE_INTERNAL void SDRM_SHA384_Init(SDRM_SHA384Context* ctx);
CRYPTOCORE_INTERNAL void SDRM_SHA384_Update(SDRM_SHA384Context* ctx, const cc_u8 *message, cc_u32 len);
CRYPTOCORE_INTERNAL void SDRM_SHA384_Final(SDRM_SHA384Context* ctx, cc_u8 *digest);

CRYPTOCORE_INTERNAL void SDRM_SHA512_Init(SDRM_SHA512Context* ctx);
CRYPTOCORE_INTERNAL void SDRM_SHA512_Update(SDRM_SHA512Context* ctx, const cc_u8 *message, cc_u32 len);
CRYPTOCORE_INTERNAL void SDRM_SHA512_Final(SDRM_SHA512Context* ctx, cc_u8 *digest);

#endif //_OP64_NOTSUPPORTED

#ifdef __cplusplus
}
#endif

#endif // _SHA2_H

/***************************** End of File *****************************/
