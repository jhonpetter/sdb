/**
 * \file	SakepApi.h
 * \brief	API for key sharing and En/Decryption 
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : sangsu choi
 * Dept : S/W center Cloud Computing lab
 * Creation date : 2012/10/29 
 */

/*
Sequnce Diagram

Client	Side											Server Side
			//////////////////////////////////////////////////////////////////////
			AKE Step
			//////////////////////////////////////////////////////////////////////

			GeneratorServerHello ---------------------------------->			
																	 
																	 ParseServerHello

						<---------------------------- GeneratorClientHello	
			
			ParseClientHello		    
			                  
			GeneratorAck ------------------------------------------->			
																	ParseAck

			//////////////////////////////////////////////////////////////////////
			Centent En/Decryption Step
			//////////////////////////////////////////////////////////////////////
			EncryptContents------------------------------------------>
																	 DecryptContents			
*/

#ifndef __SAKEPAPI_H
#define __SAKEPAPI_H

#define __STDC_LIMIT_MACROS
#include <stdint.h>

//#include <android/log.h>

#include "CC_API.h"
#include "Util.h"
#include "base/aes.h"
#include "WhiteBox/SDWAP.h"
#include "WhiteBox/SDWAP_TblGen.h"
#include "WhiteBox/SWAPv2.h"
#include "WhiteBox/SWAPv2_defines.h"
#include "DRMLog.h"

#include "Wrapper_common.h"

typedef uint8_t u_int8_t;




#ifndef _WIN

	#define SPC_INTERNAL  __attribute__((visibility("hidden")))
#else
	#define SPC_INTERNAL  
#endif

//#define SPC_INTERNAL  

extern DRMLOG_CTX  SPCLogCTX;


//++ added
/*
#ifndef PRINT_LOG
#define PRINT_BUFFER(A, B, C)
#else
#define PRINT_LINE(format, ...)				printf(format, ##__VA_ARGS__); __android_log_print(ANDROID_LOG_INFO, "SPC_SWC", format, ##__VA_ARGS__)
#define PRINT_BUFFER(A, B, C)					PrintHexBYTE(A, B, C)
#endif
*/
//-- added

#ifndef PRINT_LOG
#define PRINT_BUFFER(A, B, C)
#else
#define PRINT_BUFFER	PrintBYTE
#endif




// Key Length
#define SAKEP_PRE_SK_MESSAGE_SIZE												396


//using debugging - print hexbyte
#define PrintHexBYTE(msg, Data, DataLen) {					\
	int idx;											\
	printf("%10s =\n", msg);								\
	for( idx=0; idx<(int)DataLen; idx++) {				\
		if( (idx!=0) && ((idx%16)==0) ) printf("\n");	\
		if((idx % 4) == 0)	printf(" 0x");				\
		printf("%.2x", Data[idx]);						\
	}													\
	printf("\n");										\
}



//Data Type
typedef enum{
	CLIENT_HELLO=0x01,
	SERVER_HELLO=0x02,
	SERVER_ACKNOWLEDGEMENT=0x03,
	CLIENT_ACKNOWLEDGEMENT=0x04,
	INITIALSETUP=0x05,
	UNEXPECTED_DATA=0x10,
	ENCRYPTED_DATA=0x11,
	ENCRYPTED_CREDENTAIL_DATA = 0x12
}DataType;

typedef enum{
	NO_INTEGRITY=0x00,
	CRC_32=0x01,
	SHA1=0x11,
	HMAC_SHA1=0x21
}IntegrityType;




typedef enum {
	NO_ENCRYPTION = 0x00,
	AES_E_CRT = 0x01
}PayloadEncAlg;


//#define SEQUENCE_NUM_MAX			4294967295

////////////////////////////////////////////////////////////////
//v2
/**
 * \brief	Big number structure
 *
 * used for big number representation
 */
typedef struct {						
	unsigned int sign;						/**<	0 for positive, 1 for negative number	*/
	unsigned int Length;						/**<	number of valid integers				*/
	unsigned int Size;						/**<	unsigned long size of allocated memory	*/
	unsigned int *pData;						/**<	unsigned long array					*/
} SAKEP_BIG_NUM;

////////////////////////////////////////////////////////////////////////////
// constant & context for DL BPKAS-SPEKE protocol
////////////////////////////////////////////////////////////////////////////
/**
 * \brief	DL BPKAS-SPEKE structure
 *
 * used for DL BPKAS-SPEKE parameters
 */
typedef struct {
	unsigned int PrimeLen;				/**<	length of prime	*/
	SDRM_BIG_NUM* p;					/**<	Prime			*/
	SDRM_BIG_NUM* g;					/**<	generator		*/
} SAKEP_BSContext;

typedef struct _SAKEPContainer
{
//	unsigned char pPiPrime[16];																				/**<	Algorithm	*/
	SAKEP_BSContext *ctx;																		/**<	Algorithm	*/
} SAKEPContainer;

////////////////////////////////////////////////////////////////

class SAkepApi
{

public:

		SPC_INTERNAL SAkepApi();
		SPC_INTERNAL 		SAkepApi(Handle_CTX* ctx,ModeType eMode);
		~SAkepApi();


		/**
		 * @fn		int GeneratorServerHello(Handle_CTX* ctx,unsigned char* pPwd,unsigned int nPwdLen,unsigned char* pUserID,unsigned int nUserIDLen,unsigned char* pOutMsg,unsigned int* nOutLen)
		 * @brief	Generate Server Hello Message
		 *
		 * @param	[in] ctx				Context Container
		 * @param	[in] pPwd				password 
		 * @param	[in] nPwdLen		password Length
		 * @param	[in] pUserID		UserID
		 * @param	[in] nUserIDLen	UserID Length
		 * @param	[out] pOutMsg		ClientHelloMessage result
		 * @param	[out] nOutLen		ClientHelloMessage Length
		 * @return	result of GeneratorServerHello
		 */
		SPC_INTERNAL int GeneratorServerHello(Handle_CTX* ctx,unsigned char* pPwd,unsigned int nPwdLen,unsigned char* pUserID,unsigned int nUserIDLen,unsigned char* pOutMsg,unsigned int* nOutLen);

		/**
		 * @fn		int GeneratorAck(Handle_CTX* ctx,unsigned char* pOutMsg,unsigned int* nOutLen)
		 * @brief	Generate ACK Message
		 *
		 * @param	[in] ctx			Context Container	
		 * @param	[out] pOutMsg		ClientHelloMessage result
		 * @param	[out] nOutLen		ClientHelloMessage Length
		 * @return	result of GeneratorAck
		 */
		SPC_INTERNAL int GeneratorServerAck(Handle_CTX* ctx,unsigned char* pOutMsg,unsigned int* nOutLen);



		/**
		 * @fn		int ParseAck(Handle_CTX* ctx,unsigned char* pMessage,unsigned int nInLen)
		 * @brief	Parse Ack Message
		 *
		 * @param	[in] ctx			Context Container
		 * @param	[in] pMessage		input Message
		 * @param	[in] nInLen			input Message len
		 * @return	result of ParseAck
		 */
		SPC_INTERNAL int ParserClientAck(Handle_CTX* ctx,unsigned char* pMessage,unsigned int nInLen);


		/**
		 * @fn		int ParseClientHello(Handle_CTX* ctx,unsigned char* pMessage,unsigned int nInLen)
		 * @brief	Parse Client Hello Message
		 *
		 * @param	[in/out] ctx			Context Container
		 * @param	[in] pMessage		input Message
		 * @param	[in] nInLen		input Message Length		 
		 * @return	result of ParseClientHello
		 */
		SPC_INTERNAL int ParseClientHello(Handle_CTX* ctx,unsigned char* pPwd, unsigned int nPwdLen,unsigned char* pMessage,unsigned int nInLen);


		/**
		 * @fn		GeneratorRecordMsg ( Handle_CTX* ctx,unsigned char* pPlainData , unsigned int uPlainDataLen , unsigned char* pEncryptedData , unsigned int* uEncryptedDataLen)
		 * @brief	Content Encrytion
		 *
		 * @param	[in] ctx					Context Container
		 * @param	[in] pPlainData				Plain Data(original data)
		 * @param	[in] uPlainDataLen			Plain Data Length
		 * @param	[out] pEncryptedData		Encrypted Message(including Header)
		 * @param	[out] uEncryptedDataLen				Encrypted Message length( Encrypted Data Length + Header length)
		 * @return	result of GeneratorRecordMsg
		 */		
		SPC_INTERNAL int GeneratorRecordMsg ( Handle_CTX* ctx,unsigned char* pPlainData , unsigned int uPlainDataLen , unsigned char* pEncryptedData , unsigned int* uEncryptedDataLen);

		/**
		 * @fn		int ParseRecordMsg ( Handle_CTX* ctx,unsigned char* pEncryptedData , unsigned int uEncryptedDataLen ,unsigned char* pPlainData , unsigned int* uPlainDataLen)
		 * @brief	Content Encrytion
		 *
		 * @param	[in] ctx					Context Container
		 * @param	[in] pEncryptedData				Encrypted Message(including Header)
		 * @param	[in] uEncryptedDataLen			Encrypted Message length( Encrypted Data Length + Header length)
		 * @param	[out] pPlainData				Decrypted Message(only payload Message) - (delete Header)
		 * @param	[out] uPlainDataLen				Decrypted Message length(only payload Message length)-- (delete Header)
		 * @return	result of ParseRecordMsg
		 */		
		SPC_INTERNAL int ParseRecordMsg ( Handle_CTX* ctx,unsigned char* pEncryptedData , unsigned int uEncryptedDataLen ,unsigned char* pPlainData , unsigned int* uPlainDataLen);

	
		
private : 	

		SPC_INTERNAL int GetGy(unsigned char *pPin,unsigned int nPinLen,unsigned char* pGy,unsigned char* py) ;
		SPC_INTERNAL int SetPrivatekeyY(unsigned char* pPrivateKey);
		SPC_INTERNAL int GetPrivatekeyY(unsigned char* pPrivatekey);
		SPC_INTERNAL int SetMac(unsigned char* pMac,unsigned int nMacLen);
		SPC_INTERNAL int GetMac(unsigned char* pMac,unsigned int nMacLen);
 		SPC_INTERNAL int GetPeerMacLen(unsigned int* pPeerMacLen);

		SPC_INTERNAL int SetPublicKeyY(unsigned char* pPublicKey);
		SPC_INTERNAL int GetPublicKeyY(unsigned char* pPublicKey);


		SPC_INTERNAL int SetWcValue(unsigned char* pWc);
		SPC_INTERNAL void* SAKEPMalloc(int siz);
		SPC_INTERNAL void SAKEPFree(void *ptr);
		SPC_INTERNAL SAKEPContainer* create_SAKEPContainer();
		SPC_INTERNAL void destroy_SAKEPContainer(SAKEPContainer* crt);
		SPC_INTERNAL int SAKEP_SetBSParam(SAKEPContainer* crt,const unsigned char* pPrime, unsigned int nPrimeLen,const unsigned char* pGenerator, unsigned int nGeneratorLen);
		SPC_INTERNAL int SAKEP_GenerateBSPublic(SAKEPContainer* crt, unsigned char *pPin,unsigned int nPinLen,unsigned char* pPriv/* x */, unsigned char* pPub/* g^x */);//,unsigned char* pWc,unsigned int* nWcLen); modified 0404
		SPC_INTERNAL int SAKEP_GetAuthClient(unsigned char* pPrivY,unsigned int nPrivYLen,unsigned char* pGX,unsigned int nGXLen,unsigned char* pSharedSecret,unsigned int *pSharedSecretlen);

		SPC_INTERNAL int GetMyMacLen(unsigned int* pMacLen);

		SPC_INTERNAL int ApplyPasswordTransform(unsigned char* pPwd, unsigned int nPwdLen, unsigned char* pTransPwd, unsigned int* pTransPwdLen);
		SPC_INTERNAL int ReversePasswordTransform(unsigned char* pTransPwd, unsigned int nTransPwdLen, unsigned char* pPwd, unsigned int* pPwdLen);
		SPC_INTERNAL void ReverseKeyTransform(unsigned char* in, unsigned char* out);
		SPC_INTERNAL void ApplyKeyTransform(unsigned char* in, unsigned char* out);  

		SPC_INTERNAL int EncryptGy(unsigned char* pPwd,unsigned int nPwdLen , unsigned char* pInGy, unsigned int nInGyLen, unsigned char* pOut, unsigned int* pOutLen);
		SPC_INTERNAL int DecryptGx(unsigned char* pPwd,unsigned int nPwdLen , unsigned char* pInEncryptedGx, unsigned int nInEncryptedGxLen, unsigned char* pOut, unsigned int* pOutLen);

		SPC_INTERNAL  int EncryptParameterDataWithWB(unsigned char* pIn,  unsigned char* pOut);
		SPC_INTERNAL  int DecryptParameterDataWithWB(unsigned char* pIn,  unsigned char* pOut);


	
		unsigned char m_pPrivatekeyY[SAKEP_DLBP_PAK_PARMETER_SIZE];
		unsigned char m_pPublickeyY[SAKEP_DLBP_PAK_PARMETER_SIZE];		
		unsigned char *m_pMac;
		unsigned int  m_nMyMacLen;		
		unsigned char m_pWc[SAKEP_DLBP_PAK_PARMETER_SIZE];


protected:



};

#endif
