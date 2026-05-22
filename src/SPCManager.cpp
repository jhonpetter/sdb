#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef OS_LINUX
#include <sys/socket.h>
#endif

#ifdef OS_WINDOWS
#include <winsock.h>
#include <windows.h>
#endif

#include <fcntl.h>
#include "SPCManager.h"
#include <errno.h>

#define MESSAGE_LENGTH 4096
#define PWD_LENGTH 8
#define PWD_MAX_LENGTH 8
#define DATA_LENGTH_PACKET_LENGTH 10

#define D(format, arg...) void() //LOGI


int SPC_Init(void* SPC_context, void* SPC_Server, unsigned char *pUserID)
{
	if(!SPC_context || !SPC_Server || !pUserID){
		D("Invalid argument : SPC_context=[0x%p] SPC_Server=[0x%p] pUserID=[0x%p]", SPC_context, SPC_Server, pUserID );
		return -2;
	}

	int reVal = SPC_SUCCESS;

	SPCHandle_CTX* m_Ctx = (SPCHandle_CTX*)SPC_context;
	m_Ctx->LoginTryCount = SPC_LOGIN_LIMITED_COUNT;

	SPCApi* SPCServer = (SPCApi*)SPC_Server;
	reVal = SPCServer->InitSPCContext(m_Ctx, CLIENT_MODE, pUserID, strlen((char*)pUserID));
	if(reVal != SPC_SUCCESS)
	{
		D("SPC Init Error type : %d\n", SPC_context->ctx.eErrorType);
		return -1;
	}
	m_Ctx->ctx.eState = STATE_WAIT_SERVERHELLO;
	m_Ctx->LoginTryCount = 5;

	return SPC_SUCCESS; // SPC_SUCCESS
}

int SPC_GenServerHello(SPCApi* SPCServer, SPCHandle_CTX * SPC_context, unsigned char* pServerOutMsg, unsigned int* LenpServerOutMsg)
{
	if(!SPCServer || !SPC_context || !pServerOutMsg || !LenpServerOutMsg){
		D("Invalid argument : SPCServer=[0x%p] SPC_context=[0x%p] pServerOutMsg=[0x%p] LenpServerOutMsg=[0x%p]", SPCServer, SPC_context, pServerOutMsg,LenpServerOutMsg );
		return -2;
	}

	int reVal = SPC_SUCCESS;

	unsigned char pPwd[PWD_MAX_LENGTH];
	memcpy(pPwd, "PASSWORD", PWD_LENGTH);

	reVal = SPCServer->GeneratorServerHello(SPC_context, pPwd, PWD_LENGTH, SPC_context->pUserID, pServerOutMsg, LenpServerOutMsg);
	if(reVal != SPC_SUCCESS)
	{
		D("SPC GenServerHello Error type : %d\n", SPC_context->ctx.eErrorType);
		return -1;
	}

	return SPC_SUCCESS;
}

int SPC_ParseClientHello(SPCApi* SPCServer, SPCHandle_CTX* SPC_context, unsigned char* ReadMsg, unsigned int* LenReadMsg)
{
	if(!SPCServer || !SPC_context || !ReadMsg || !LenReadMsg){
		D("Invalid argument : SPCServer=[0x%p] SPC_context=[0x%p] ReadMsg=[0x%p] LenReadMsg=[0x%p]", SPCServer, SPC_context, ReadMsg, LenReadMsg );
		return -2;
	}

	int reVal = SPC_SUCCESS;

	unsigned char pPwd[PWD_MAX_LENGTH];
	memcpy(pPwd, "PASSWORD", PWD_LENGTH);
	reVal = SPCServer->ParseClientHello(SPC_context, pPwd, PWD_LENGTH, ReadMsg, *LenReadMsg);
	if(reVal != SPC_SUCCESS)
	{
		D("SPC ParseClientHello Error type : %d\n", SPC_context->ctx.eErrorType);
		return -1;
	}
	return SPC_SUCCESS;
}

int SPC_GenServerAck(SPCApi* SPCServer, SPCHandle_CTX* SPC_context, unsigned char* pServerAckOutMsg, unsigned int* LenpServerAckOutMsg)
{
	if(!SPCServer || !SPC_context || !pServerAckOutMsg || !LenpServerAckOutMsg){
		D("Invalid argument : SPCServer=[0x%p] SPC_context=[0x%p] pServerAckOutMsg=[0x%p] LenpServerAckOutMsg=[0x%p]", SPCServer, SPC_context, pServerAckOutMsg, LenpServerAckOutMsg);
		return -2;
	}

	int reVal = SPC_SUCCESS;

	reVal = SPCServer->GeneratorServerAck(SPC_context, pServerAckOutMsg, LenpServerAckOutMsg);
	if( reVal != SPC_SUCCESS )
	{
		D("SPC Generator Server Ack Error type : %d \n", SPC_context->ctx.eErrorType);
		return -1;
	}
	return SPC_SUCCESS;
}

int SPC_ParseClientAck(SPCApi* SPCServer, SPCHandle_CTX* SPC_context, unsigned char* ReadMsg, unsigned int* LenReadMsg)
{
	if(!SPCServer || !SPC_context || !ReadMsg || !LenReadMsg){
		D("Invalid argument : SPCServer=[0x%p] SPC_context=[0x%p] ReadMsg=[0x%p] LenReadMsg=[0x%p]", SPCServer, SPC_context, ReadMsg, LenReadMsg );
		return -2;
	}

	int reVal = SPC_SUCCESS;

	reVal = SPCServer->ParseClientAck(SPC_context, ReadMsg, *LenReadMsg);
	if(reVal != SPC_SUCCESS)
	{
		D("SPC ParseClientrAck Error type : %d\n", SPC_context->ctx.eErrorType);
		return -1;
	}
	return SPC_SUCCESS;

}

int SPC_ParseRecordMsg(SPCApi* SPCServer, SPCHandle_CTX* SPC_context,unsigned char* pEncryptedData , unsigned int uEncryptedDataLen,unsigned char* pPlainData , unsigned int* uPlainDataLen)
{
	if(!SPCServer || !SPC_context || !pEncryptedData || !pPlainData || !uPlainDataLen || uEncryptedDataLen <= 0){
		D("Invalid argument : SPCServer=[0x%p] SPC_context=[0x%p] pEncryptedData=[0x%p] uEncryptedDataLen=[0x%p] pPlainData=[0x%p] uPlainDataLen=[0x%p]",
			SPCServer, SPC_context, pEncryptedData, uEncryptedDataLen, pPlainData, uPlainDataLen );
		return -2;
	}

	int reVal=SPC_SUCCESS;

	reVal = SPCServer->ParseRecordMsg(SPC_context, pEncryptedData ,  uEncryptedDataLen , pPlainData , uPlainDataLen);
	if(reVal != SPC_SUCCESS)
	{
		D("SPC Parse Record Msg Error type : %d \n", SPC_context->ctx.eErrorType);
		return -1;
	}

	return SPC_SUCCESS;
}

int SPC_GenRecordMsg(SPCApi* SPCServer, SPCHandle_CTX* SPC_context, unsigned char* pPlainData , unsigned int uPlainDataLen, unsigned char* pEncryptedData , unsigned int *uEncryptedDataLen)
{
	if(!SPCServer || !SPC_context || !pPlainData || !pEncryptedData || !uEncryptedDataLen || uPlainDataLen <= 0){
		D("Invalid argument : SPCServer=[0x%p] SPC_context=[0x%p] pPlainData=[0x%p] uPlainDataLen=[0x%p] pEncryptedData=[0x%p] uEncryptedDataLen=[0x%p]",
			SPCServer, SPC_context, pPlainData, uPlainDataLen, pEncryptedData, uEncryptedDataLen );
		return -2;
	}

	int reVal = SPC_SUCCESS;
	
	reVal = SPCServer->GeneratorRecordMsg(SPC_context, pPlainData , uPlainDataLen ,pEncryptedData , uEncryptedDataLen);
	if(reVal != SPC_SUCCESS)
	{
		D("SPC Gen Record Msg Error type : %d \n", SPC_context->ctx.eErrorType);
		return -1;
	}

	return SPC_SUCCESS;
}

unsigned char* constChar_to_unsignedChar(const char * InputChar)
{
	unsigned char* OutputChar = (unsigned char *)InputChar;
	return OutputChar;
}

char *int_to_char(int num, char *str, int size)
{
	 if(str == NULL)
     {
		 return NULL;
     }
     snprintf(str, size, "%d", num);
     return str;
}
