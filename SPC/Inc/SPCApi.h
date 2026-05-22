/**
 * \file	SPCApi.h
 * \brief	API for key sharing and En/Decryption 
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : sangsu choi
 * Dept : S/W center Cloud Computing lab
 * Creation date : 2013/01/15 
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "SAKEP.h"
#include "Util.h"
#include "DRMLog.h"



class SPCApi
{
public:
		/**
		 * @fn		SPCApi()
		 * @brief	SPCApi Constrctor
		 *		 
		 * @return	None
		 */
		SPC_INTERNAL SPCApi();

		/**
		 * @fn		SPCApi()
		 * @brief	SPCApi Destrctor
		 *		 
		 * @return	None
		 */
		~SPCApi();

	
		/**
		 * @fn		InitSPCContext(SPCHandle_CTX* pSPCctx,ModeType eMode,unsigned char* pUserID,unsigned int nUserIDLen)
		 * @brief	SPC Context initialize
		 * @param	[in] pSPCctx			context of SPC
		 * @param	[in] eMode				Server or Client
		 * @param	[in] pUserID			UserID
		 * @param	[in] nUserIDLen		UserID Length
		 *		 
		 * @return	None
		 */
		SPC_INTERNAL int InitSPCContext(SPCHandle_CTX* pSPCctx,ModeType eMode,unsigned char* pUserID,unsigned int nUserIDLen);
		
		/**
		 * @fn		void DestroySPCContext(SPCHandle_CTX* pSPCctx)
		 * @brief	Destroy Context
		 * @param	[in] pSPCctx			context of SPC		 
		 *		 
		 * @return	None
		 */
		SPC_INTERNAL void DestroySPCContext(SPCHandle_CTX* pSPCctx);

	/**
		 * @fn		void ClearSPCSessionContext(SPCHandle_CTX* pSPCctx)
		 * @brief	Clear Context
		 * @param	[in] pSPCctx			context of SPC		 
		 *		 
		 * @return	None
		 */
		SPC_INTERNAL void ClearSPCSessionContext(SPCHandle_CTX* pSPCctx);
		
		/**
		 * @fn		int ParseClientHello(SPCHandle_CTX* pSPCctx,unsigned char* pMessage,unsigned int nInLen)
		 * @brief	Parse Client Hello Message
		 *
		 * @param	[in] pSPCctx			Context Container	
		 * @param	[in] pMessage		  Received Client Hello Message 
		 * @param	[in] nInLen		    Received Client Hello Message Length		 
		 * @return	result of ParseClientHello
		 */
		SPC_INTERNAL int ParseClientHello(SPCHandle_CTX* pSPCctx,unsigned char* pPwd, unsigned int nPwdLen,unsigned char* pMessage,unsigned int nInLen);

		/**
		 * @fn		int GeneratorServerHello(SPCHandle_CTX* pSPCctx,unsigned char* pOutMsg,unsigned int* nOutLen)
		 * @brief	Generate Server Hello Message
		 *
		 * @param	[in] ctx			Context Container		
		 * @param	[in] pPwd			common password Data
		 * @param	[in] pPwdLen		password Data length
		 * @param	[in] pID			Client's ID Value
		 * @param	[out] pOutMsg		ClientHelloMessage result
		 * @param	[out] nOutLen		ClientHelloMessage Length
		 * @return	result of GeneratorServerHello
		 */
		SPC_INTERNAL int GeneratorServerHello(SPCHandle_CTX* pSPCctx,unsigned char* pPwd,unsigned int nPwdLen,unsigned char* pID,unsigned char* pOutMsg,unsigned int* nOutLen);


		/**
		 * @fn		int GeneratorServerAck(SPCHandle_CTX* pSPCctx,unsigned char* pOutMsg,unsigned int* nOutLen)
		 * @brief	Generate Server Acknowledgement Message
		 *
		 * @param	[in] ctx			Context Container	
		 * @param	[out] pOutMsg		ClientHelloMessage result
		 * @param	[out] nOutLen		ClientHelloMessage Length
		 * @return	result of GeneratorServerAck
		 */
		SPC_INTERNAL int GeneratorServerAck(SPCHandle_CTX* pSPCctx,unsigned char* pOutMsg,unsigned int* nOutLen);


		/**
		 * @fn		int ParseClientAck(SPCHandle_CTX* pSPCctx,unsigned char* pMessage,unsigned int nInLen)
		 * @brief	Parse Client Acknowledgement Message
		 *
		 * @param	[in] pSPCctx			Context Container
		 * @param	[in] pMessage		input Message
		 * @param	[in] nInLen			input Message len
		 * @return	result of ParseClientAck
		 */
		SPC_INTERNAL int ParseClientAck(SPCHandle_CTX* pSPCctx,unsigned char* pMessage,unsigned int nInLen);

		
		/**
		 * @fn		int GeneratorRecordMsg ( Handle_CTX* ctx,unsigned char* pPlainData , unsigned int uPlainDataLen , unsigned char* pEncryptedData , unsigned int* uEncryptedDataLen)
		 * @brief	Content Encrytion
		 *
		 * @param	[in] pSPCctx					Context Container
		 * @param	[in] pPlainData				Plain Data(original data)
		 * @param	[in] uPlainDataLen			Plain Data Length
		 * @param	[out] pEncryptedData		Encrypted Message(including Header)
		 * @param	[out] uEncryptedDataLen				Encrypted Message length( Encrypted Data Length + Header length)
		 * @return	result of GeneratorRecordMsg
		 */
		SPC_INTERNAL int GeneratorRecordMsg ( SPCHandle_CTX* pSPCctx,unsigned char* pPlainData , unsigned int uPlainDataLen , unsigned char* pEncryptedData , unsigned int* uEncryptedDataLen);

		/**
		 * @fn		int ParseRecordMsg ( SPCHandle_CTX* pSPCctx,unsigned char* pEncryptedData , unsigned int uEncryptedDataLen ,unsigned char* pPlainData , unsigned int* uPlainDataLen);
		 * @brief	Content Decryption
		 *
		 * @param	[in] pSPCctx					Context Container
		 * @param	[in] pEncryptedData				Encrypted Message(including Header)
		 * @param	[in] uEncryptedDataLen			Encrypted Message length( Encrypted Data Length + Header length)
		 * @param	[out] pPlainData				Decrypted Message(only payload Message) - (delete Header)
		 * @param	[out] uPlainDataLen				Decrypted Message length(only payload Message length)-- (delete Header)
		 * @return	result of ParseRecordMsg
		 */
		SPC_INTERNAL int ParseRecordMsg ( SPCHandle_CTX* pSPCctx,unsigned char* pEncryptedData , unsigned int uEncryptedDataLen ,unsigned char* pPlainData , unsigned int* uPlainDataLen);
		

private:

	
		SAkepApi m_SAkep;

};



