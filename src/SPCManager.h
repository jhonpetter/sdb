#ifndef __SPCMANAGER_H__
#define __SPCMANAGER_H__

#include "SPCApi.h"

typedef int (*READX_PTR)(int fd, void* buffer, size_t r_length);
typedef int (*WRITEX_PTR)(int fd, const void* buffer, size_t w_length);

int SPC_Init(void* SPC_context, void* SPC_Server, unsigned char *pUserID);
int SPC_GenServerHello(SPCApi* SPCServer, SPCHandle_CTX * SPC_context, unsigned char* pServerOutMsg, unsigned int* LenpServerOutMsg);
int SPC_ParseClientHello(SPCApi* SPCServer, SPCHandle_CTX* SPC_context, unsigned char* ReadMsg, unsigned int* LenReadMsg);
int SPC_GenServerAck(SPCApi* SPCServer, SPCHandle_CTX* SPC_context, unsigned char* pServerAckOutMsg, unsigned int* LenpServerAckOutMsg);
int SPC_ParseClientAck(SPCApi* SPCServer, SPCHandle_CTX* SPC_context, unsigned char* ReadMsg, unsigned int* LenReadMsg);
int SPC_ParseRecordMsg(SPCApi* SPCServer, SPCHandle_CTX* SPC_context,unsigned char* pEncryptedData , unsigned int uEncryptedDataLen,unsigned char* pPlainData , unsigned int* uPlainDataLen);
int SPC_GenRecordMsg(SPCApi* SPCServer, SPCHandle_CTX* SPC_context, unsigned char* pPlainData , unsigned int uPlainDataLen, unsigned char* pEncryptedData , unsigned int *uEncryptedDataLen);

unsigned char* constChar_to_unsignedChar(const char * InputChar);
char *int_to_char(int num, char *str, int size);

#endif
