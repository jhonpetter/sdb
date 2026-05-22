#include "SPCApi.h"


#ifndef PRINT_LOG
#define PRINT_BUFFER(A, B, C)
#else
#define PRINT_BUFFER	PrintBYTE
#endif


#define _SPC_DEBUG_VER 
//#define _SPC_FILE_LOG		

#ifdef _SPC_DEBUG_VER
FILE*       SPClogfile = NULL;
FILE*       SPCmsgfile = NULL;
DRMLOG_CTX  SPCLogCTX;
#endif 



SPC_INTERNAL SPCApi::SPCApi()
{

}


SPC_INTERNAL int SPCApi::InitSPCContext(SPCHandle_CTX* pSPCctx,ModeType eMode,unsigned char* pUserID,unsigned int nUserIDLen)
{
	#ifdef _SPC_DEBUG_VER
	#ifdef _SPC_FILE_LOG
		// Output log infomation to file	
	#ifdef _LINUX
	    SPClogfile = fopen ("/sdcard/logClient.txt", "wt");
	    SPCmsgfile = fopen ("/sdcard/msgClient.txt", "wt");
	#else
		SPClogfile = fopen ("./log.txt", "a+");
	    SPCmsgfile = fopen ("./msg.txt", "a+");
	#endif
	    // Print logs into the specifed file
	    DRMLOG_SetOutput (&SPCLogCTX, SPClogfile);
	#else 
		// output to stdout
		printf(" InitSPCContext stdout \n");
	    DRMLOG_SetOutput (&SPCLogCTX, stdout);
	#endif 
	    // Log level
	#ifdef  _SPC_LOG_LEVEL_DEBUG
	    DRMLOG_SetLevel (&SPCLogCTX, LOG_DEBUG);
	#elif   _SPC_LOG_LEVEL_INFO 
	    DRMLOG_SetLevel (&SPCLogCTX, LOG_INFO);
	#elif   _SPC_LOG_LEVEL_WARN 
	    DRMLOG_SetLevel (&SPCLogCTX, LOG_WARN);
	#elif   _SPC_LOG_LEVEL_ERROR 
	    DRMLOG_SetLevel (&SPCLogCTX, LOG_ERROR);
	#elif   _SPC_LOG_LEVEL_FATAL 
	    DRMLOG_SetLevel (&SPCLogCTX, LOG_FATAL);
	#else
	    DRMLOG_SetLevel (&SPCLogCTX, LOG_INFO);
	#endif
	    // Print: Level + Filename
	    DRMLOG_SetFormat (&SPCLogCTX, LOG_FORMAT_LEVEL | LOG_FORMAT_FILE);
	#endif
	
		if(pSPCctx==NULL)
		{
			return SAKEP_INPUT_INVALID_ERROR;
		}


		DRMLOG_Message(&SPCLogCTX,LOG_INFO,__FILE__,__LINE__,"InitSPCContext UserID: %s UserIDLen:%d\n",pUserID,nUserIDLen);
		
		pSPCctx->pUserID = (unsigned char*)malloc( nUserIDLen+1);
		if(pSPCctx->pUserID == NULL)
		return SAKEP_MEMROY_ALLOCATE_ERROR;
		pSPCctx->nUserIDLen = nUserIDLen;
		pSPCctx->LoginTryCount = SPC_LOGIN_LIMITED_COUNT;
//		pSPCctx->LoginTryCount = nLoginCount;
		memset(pSPCctx->pUserID,0x00,nUserIDLen+1);
		memcpy(pSPCctx->pUserID,pUserID,nUserIDLen);		
		//added by sangsu 0308
		memset(pSPCctx->ctx.pPreHashMsg,0x00,SAKEP_SHA1_HASH_SIZE);
		memset(pSPCctx->ctx.pSharedkey,0x00,SAKEP_SHARED_KEY_SIZE);
		memset(pSPCctx->ctx.pSKPrime,0x00,SAKEP_SK_PRIME_KEY_SIZE);
		pSPCctx->ctx.eErrorType = (ErrorType) 0x00;
		if(eMode == SERVER_MODE)
		{
			pSPCctx->ctx.eState = STATE_WAIT_INITALSETUP;
		}
		if(eMode == CLIENT_MODE)
		{
		
			pSPCctx->ctx.eState = STATE_IDLE;
		}

		return SPC_SUCCESS;
	
}

SPCApi::~SPCApi()
{
	#ifdef _SPC_DEBUG_VER
	#ifdef _SPC_FILE_LOG
	    if (SPClogfile != NULL)
	    {
	    	fclose (SPClogfile);
	    	SPClogfile = NULL;
	    }
	
	    if (SPCmsgfile != NULL)
	    {
		    fclose (SPCmsgfile);
		    SPCmsgfile = NULL;
	    }
	#endif
	#endif
}

SPC_INTERNAL void SPCApi::DestroySPCContext(SPCHandle_CTX* pSPCctx)
{
	if(pSPCctx->pUserID !=NULL)
	{
		free(pSPCctx->pUserID);
	}
	pSPCctx->ctx.eErrorType = (ErrorType)SUCCESS;
	pSPCctx->ctx.eState = (AkeState)STATE_IDLE;
	memset(pSPCctx->ctx.pPreHashMsg,0x00,SAKEP_SHA1_HASH_SIZE);
	memset(pSPCctx->ctx.pSharedkey,0x00,SAKEP_SHARED_KEY_SIZE);
	memset(pSPCctx->ctx.pSKPrime,0x00,SAKEP_SK_PRIME_KEY_SIZE);
}

SPC_INTERNAL void SPCApi::ClearSPCSessionContext(SPCHandle_CTX* pSPCctx)
{
	pSPCctx->ctx.eErrorType = (ErrorType)SUCCESS;
	pSPCctx->ctx.eState = (AkeState)STATE_IDLE;
	memset(pSPCctx->ctx.pPreHashMsg,0x00,SAKEP_SHA1_HASH_SIZE);
	//memset(pSPCctx->ctx.pSharedkey,0x00,SAKEP_SHARED_KEY_SIZE);
	//memset(pSPCctx->ctx.pSKPrime,0x00,SAKEP_SK_PRIME_KEY_SIZE);
}


/**
	* @fn		int ParseClientHello(SPCHandle_CTX* pSPCctx,unsigned char* pPwd,unsigned int nPwdLen,unsigned char* pMessage,unsigned int nInLen)
	* @brief	Parse Client Hello Message
	*
	* @param	[in/out] pSPCctx			Context Container
	* @param	[in] pPin			common Pin Data
	* @param	[in] nPinLen		common Pin Data Length
	* @param	[in] pMessage		input Message
	* @param	[in] nInLen		input Message Length		 
	* @return	result of ParseClientHello
	*/
SPC_INTERNAL int SPCApi::ParseClientHello(SPCHandle_CTX* pSPCctx,unsigned char* pPwd, unsigned int nPwdLen,unsigned char* pMessage,unsigned int nInLen)
{
	int reVal = SPC_SUCCESS;

	if((NULL==pSPCctx) || (pMessage == NULL) || (nInLen == 0))
	{
		return SAKEP_INPUT_INVALID_ERROR;
	}
	
	reVal = m_SAkep.ParseClientHello(&(pSPCctx->ctx),pPwd,nPwdLen,pMessage,nInLen);
	if(reVal != SPC_SUCCESS)
	{
	
		DRMLOG_Message(&SPCLogCTX,LOG_ERROR,__FILE__,__LINE__,"ParseClientHello login count  [ : %d ]\n",pSPCctx->LoginTryCount);

		return reVal;
	}	
	
	return reVal;
}

/**
	* @fn		int GeneratorServerHello(SPCHandle_CTX* pSPCctx,unsigned char* pPwd,unsigned int nPwdLen,unsigned char* pID,unsigned char* pOutMsg,unsigned int* nOutLen)
	* @brief	Generate Server Hello Message
	*
	* @param	[in] pSPCctx			Context Container		
	* @param	[in] pPwd			common password Data
	* @param	[in] pPwdLen		password Data length
	* @param	[in] pID			Client's ID Value
	* @param	[out] pOutMsg		ClientHelloMessage result
	* @param	[out] nOutLen		ClientHelloMessage Length
	* @return	result of GeneratorServerHello
	*/
SPC_INTERNAL int SPCApi::GeneratorServerHello(SPCHandle_CTX* pSPCctx,unsigned char* pPwd,unsigned int nPwdLen,unsigned char* pID,unsigned char* pOutMsg,unsigned int* nOutLen)
{
	int reVal = SPC_SUCCESS;
	

	if((NULL==pSPCctx) || (pPwd == NULL) || (nPwdLen == 0) || (pID == NULL) || (pOutMsg==NULL))
	{
		return SAKEP_INPUT_INVALID_ERROR;
	}

	reVal = m_SAkep.GeneratorServerHello(&(pSPCctx->ctx),pPwd,nPwdLen,pSPCctx->pUserID,pSPCctx->nUserIDLen,pOutMsg,nOutLen);
	if(reVal != SPC_SUCCESS)
	{
		DRMLOG_Message(&SPCLogCTX,LOG_ERROR,__FILE__,__LINE__,"GeneratorServerHello login count  [ : %d ]\n",pSPCctx->LoginTryCount);
		return reVal;
	}
	
	return reVal;
}

/**
 * @fn		int GeneratorAck(SPCHandle_CTX* pSPCctx,unsigned char* pOutMsg,unsigned int* nOutLen)
 * @brief	Generate ACK Message
 *
 * @param	[in] pSPCctx			Context Container	
 * @param	[out] pOutMsg		ClientHelloMessage result
 * @param	[out] nOutLen		ClientHelloMessage Length
 * @return	result of GeneratorAck
 */
SPC_INTERNAL int SPCApi::GeneratorServerAck(SPCHandle_CTX* pSPCctx,unsigned char* pOutMsg,unsigned int* nOutLen)
{
	int reVal = SPC_SUCCESS;
	
	if((NULL==pSPCctx)||(pOutMsg==NULL) )
	{
		return SAKEP_INPUT_INVALID_ERROR;
	}

	reVal = m_SAkep.GeneratorServerAck(&(pSPCctx->ctx),pOutMsg,nOutLen);
	if(reVal != SPC_SUCCESS)
	{
			
		DRMLOG_Message(&SPCLogCTX,LOG_ERROR,__FILE__,__LINE__,"GeneratorServerAck login count  [ : %d ]\n",pSPCctx->LoginTryCount);
		return reVal;
	}	
	
	

	return reVal;
}



/**
 * @fn		int ParseAck(SPCHandle_CTX* pSPCctx,unsigned char* pMessage,unsigned int nInLen)
 * @brief	Parse Ack Message
 *
 * @param	[in] pSPCctx			Context Container
 * @param	[in] pMessage			input Message
 * @param	[in] nInLen				input Message len
 * @return	result of ParseAck
 */
SPC_INTERNAL int SPCApi::ParseClientAck(SPCHandle_CTX* pSPCctx,unsigned char* pMessage,unsigned int nInLen)
{
	int reVal = SPC_SUCCESS;

	if((NULL == pSPCctx) || (pMessage == NULL)|| (nInLen == 0))
	{
		return SAKEP_INPUT_INVALID_ERROR;
	}

	reVal = m_SAkep.ParserClientAck(&(pSPCctx->ctx),pMessage,nInLen);
	if(reVal !=SPC_SUCCESS)
	{
		return reVal;
	}
	

	return reVal;
}


/**
 * @fn		int GeneratorRecordMsg ( Handle_CTX* ctx,unsigned char* pPlainData , unsigned int uPlainDataLen , unsigned char* pEncryptedData , unsigned int* uEncryptedDataLen)
 * @brief	Content Encrytion
 *
 * @param	[in] ctx					Context Container
 * @param	[in] pPlainData				Plain Data(original data)
 * @param	[in] uPlainDataLen			Plain Data Length
 * @param	[out] pEncryptedData		Encrypted Message(including Header)
 * @param	[out] uEncryptedDataLen				Encrypted Message length( Encrypted Data Length + Header length)
 * @return	result of EncryptContents
 */
 
SPC_INTERNAL int SPCApi::GeneratorRecordMsg ( SPCHandle_CTX* pSPCctx,unsigned char* pPlainData , unsigned int uPlainDataLen , unsigned char* pEncryptedData , unsigned int* uEncryptedDataLen)
{
	int reVal = SPC_SUCCESS;
	
	if((NULL==pSPCctx) || (pPlainData == NULL) || (uPlainDataLen == 0))
	{
		return SAKEP_INPUT_INVALID_ERROR;
	}
	
	
	reVal = m_SAkep.GeneratorRecordMsg ( &(pSPCctx->ctx),pPlainData , uPlainDataLen , pEncryptedData ,  uEncryptedDataLen);
	if(reVal != SPC_SUCCESS)
	{
		return reVal;
	}
	
	return reVal;
}

/**
 * @fn		int ParseRecordMsg ( Handle_CTX* ctx,unsigned char* pEncryptedData , unsigned int uEncryptedDataLen ,unsigned char* pPlainData , unsigned int* uPlainDataLen)
 * @brief	Content Encrytion
 *
 * @param	[in] pSPCctx					Context Container
 * @param	[in] pEncryptedData				Encrypted Message(including Header)
 * @param	[in] uEncryptedDataLen			Encrypted Message length( Encrypted Data Length + Header length)
 * @param	[out] pPlainData				Decrypted Message(only payload Message) - (delete Header)
 * @param	[out] uPlainDataLen				Decrypted Message length(only payload Message length)-- (delete Header)
 * @return	result of ParseRecordMsg
 */
SPC_INTERNAL int SPCApi::ParseRecordMsg ( SPCHandle_CTX* pSPCctx,unsigned char* pEncryptedData , unsigned int uEncryptedDataLen ,unsigned char* pPlainData , unsigned int* uPlainDataLen)
{
	int reVal = SPC_SUCCESS;
	
	if((NULL==pSPCctx) || (pEncryptedData == NULL) || (uEncryptedDataLen == 0))
	{
		return SAKEP_INPUT_INVALID_ERROR;
	}
	
	
	reVal = m_SAkep.ParseRecordMsg ( &(pSPCctx->ctx),pEncryptedData ,  uEncryptedDataLen ,pPlainData ,uPlainDataLen);
	if(reVal != SPC_SUCCESS)
	{
		pSPCctx->LoginTryCount = 0;		
		return reVal;
	}

	return reVal;
}

