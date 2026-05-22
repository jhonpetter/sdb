#include "SPCManager.h"
#include "log.h"
#include <map>

typedef struct _SessionInfo {
	int nSessionID;
	SPCHandle_CTX* pCtx;
	SPCApi* pApi;
} SessionInfo;

typedef std::map<int, SessionInfo> SessionInfoList;
SessionInfoList sessionInfoList;

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_USERID 20

int security_init(const int nSessionID, const char* pUserID)
{
	D("In");

	D("sessionInfoList.size() = [%d]", sessionInfoList.size());
	// If already exist, erase
	sessionInfoList.erase(nSessionID);

	// Add session info
	sessionInfoList[nSessionID].nSessionID = nSessionID;
	//sessionInfoList[nSessionID].pValue = NULL;
	D("sessionInfoList.size() = [%d]", sessionInfoList.size());
	D("sessionInfoList[nSessionID].nSessionID = [%d]", sessionInfoList[nSessionID].nSessionID);

	SPCHandle_CTX* pCtx = new SPCHandle_CTX();
	SPCApi* pApi = new SPCApi();

	sessionInfoList[nSessionID].pCtx = pCtx;
	sessionInfoList[nSessionID].pApi = pApi;

	unsigned char szTempUserID[MAX_USERID];
	memset(szTempUserID, 0x00, MAX_USERID);
	if(pUserID == NULL)
	{
		memcpy(szTempUserID, "USER", 4);
	} else {
		if( MAX_USERID < strlen(pUserID) ){
			D("USERID is too long");
			return -1;
		}
		memcpy(szTempUserID, pUserID, strlen(pUserID));
	}

	int reVal = 0;
	reVal = SPC_Init(pCtx, pApi, szTempUserID);
	if( reVal != 0 )
	{
		D("SPC handshake fail");
		return -1;
	}

	D("SPC handshake OK");
	return 1;
}

int security_gen_server_hello(const int nSessionID, unsigned char* pSrc, unsigned int* nSrcLen)
{
    if( pSrc == NULL || nSrcLen == NULL ) {
        D("Invalid argument : pSrc=[0x%p], pSrcLen=[0x%p]", pSrc, nSrcLen);
        return -1;
    }

	if ( !sessionInfoList[nSessionID].pApi || !sessionInfoList[nSessionID].pCtx)
	{
		D("Invalid session : sessionInfoList[nSessionID].pApi=[0x%p], sessionInfoList[nSessionID].pCtx=[0x%p]", sessionInfoList[nSessionID].pApi, sessionInfoList[nSessionID].pCtx);
		return -1;
	}

	int reVal = 0;
	reVal = SPC_GenServerHello(sessionInfoList[nSessionID].pApi, sessionInfoList[nSessionID].pCtx, pSrc, nSrcLen);
	if( reVal != 0 )
	{
		D("SPC Generate Server Hello Message fail");
		return 0;
	}

	return 1;
}

int security_parse_client_hello(const int nSessionID, unsigned char* pSrc, unsigned int* nSrcLen)
{
    if( pSrc == NULL || nSrcLen == NULL ) {
        D("Invalid argument : pSrc=[0x%p], pSrcLen=[0x%p]", pSrc, nSrcLen);
        return -1;
    }

	if ( !sessionInfoList[nSessionID].pApi || !sessionInfoList[nSessionID].pCtx)
	{
		D("Invalid session : sessionInfoList[nSessionID].pApi=[0x%p], sessionInfoList[nSessionID].pCtx=[0x%p]", sessionInfoList[nSessionID].pApi, sessionInfoList[nSessionID].pCtx);
		return -1;
	}

	int reVal = 0;
	reVal = SPC_ParseClientHello(sessionInfoList[nSessionID].pApi, sessionInfoList[nSessionID].pCtx, pSrc, nSrcLen);
	if( reVal != 0 )
	{
		D("SPC Parse Client Hello Message fail");
		return 0;
	}

	return 1;
}

int security_gen_server_ack(const int nSessionID, unsigned char* pSrc, unsigned int* nSrcLen)
{
    if( pSrc == NULL || nSrcLen == NULL ) {
        D("Invalid argument : pSrc=[0x%p], pSrcLen=[0x%p]", pSrc, nSrcLen);
        return -1;
    }

	if ( !sessionInfoList[nSessionID].pApi || !sessionInfoList[nSessionID].pCtx)
	{
		D("Invalid session : sessionInfoList[nSessionID].pApi=[0x%p], sessionInfoList[nSessionID].pCtx=[0x%p]", sessionInfoList[nSessionID].pApi, sessionInfoList[nSessionID].pCtx);
		return -1;
	}

	int reVal = 0;
	reVal = SPC_GenServerAck(sessionInfoList[nSessionID].pApi, sessionInfoList[nSessionID].pCtx, pSrc, nSrcLen);
	if( reVal != 0 )
	{
		D("SPC Generate Server Ack Message fail");
		return 0;
	}

	return 1;
}

int security_parse_client_ack(const int nSessionID, unsigned char* pSrc, unsigned int* nSrcLen)
{
    if( pSrc == NULL || nSrcLen == NULL ) {
        D("Invalid argument : pSrc=[0x%p], pSrcLen=[0x%p]", pSrc, nSrcLen);
        return -1;
    }

	if ( !sessionInfoList[nSessionID].pApi || !sessionInfoList[nSessionID].pCtx)
	{
		D("Invalid session : sessionInfoList[nSessionID].pApi=[0x%p], sessionInfoList[nSessionID].pCtx=[0x%p]", sessionInfoList[nSessionID].pApi, sessionInfoList[nSessionID].pCtx);
		return -1;
	}

	int reVal = 0;
	reVal = SPC_ParseClientAck(sessionInfoList[nSessionID].pApi, sessionInfoList[nSessionID].pCtx, pSrc, nSrcLen);
	if( reVal != 0 )
	{
		D("SPC Parse Client Ack Message fail");
		return 0;
	}

	return 1;
}

int security_deinit(const int nSessionID)
{
	if( sessionInfoList[nSessionID].pCtx ) {
		free(sessionInfoList[nSessionID].pCtx);
		sessionInfoList[nSessionID].pCtx = NULL;
	}
	else {
		return -1;
	}

	if( sessionInfoList[nSessionID].pApi ) {
		free(sessionInfoList[nSessionID].pApi);
		sessionInfoList[nSessionID].pCtx = NULL;
	}
	else {
		return -1;
	}

	return 1;
}

int security_encrypt(const int nSessionID, unsigned char* pSrc, unsigned int *nSrcLen)
{
    D("security_encrypt is called\n");
    if( pSrc == NULL || nSrcLen == NULL ) {
        D("Invalid argument : pSrc=[0x%p], pSrcLen=[0x%p]", pSrc, nSrcLen);
        return -1;
    }

    unsigned char *szTemp;
    szTemp = (unsigned char *)malloc(*nSrcLen + SAKEP_AKE_MSG_RECORD_FIXED_LEN + SAKEP_AES_ECB_ADDED_PADDING_SIZE);
    memset(szTemp, 0x00, *nSrcLen + SAKEP_AKE_MSG_RECORD_FIXED_LEN + SAKEP_AES_ECB_ADDED_PADDING_SIZE);
    unsigned int nDstLen = 0;

	if ( !sessionInfoList[nSessionID].pApi || !sessionInfoList[nSessionID].pCtx)
	{
		D("Invalid session : sessionInfoList[nSessionID].pApi=[0x%p], sessionInfoList[nSessionID].pCtx=[0x%p]", sessionInfoList[nSessionID].pApi, sessionInfoList[nSessionID].pCtx);
		return -1;
	}

	int reVal = 0;
    reVal = SPC_GenRecordMsg(sessionInfoList[nSessionID].pApi, sessionInfoList[nSessionID].pCtx,
            pSrc, *nSrcLen, szTemp, &nDstLen);
	if( reVal != 0 )
	{
		D("SPC Encryption fail");
		free(szTemp);
		return 0;
	}

    unsigned int i = 0;
    for(i = 0 ; i < nDstLen ; ++i) {
        pSrc[i] = szTemp[i];
    }
    *nSrcLen = nDstLen;
    free(szTemp);

	return 1;
}

int security_decrypt(const int nSessionID, unsigned char* pSrc, unsigned int *nSrcLen)
{
    if( pSrc == NULL || nSrcLen == NULL ) {
        D("Invalid argument : pSrc=[0x%p], pSrcLen=[0x%p]", pSrc, nSrcLen);
        return -1;
    }

    unsigned char *szTemp;
    szTemp = (unsigned char *) malloc(*nSrcLen);
    memset(szTemp, 0x00, *nSrcLen);
    unsigned int nDstLen = 0;

	int reVal = 0;
	reVal = SPC_ParseRecordMsg(sessionInfoList[nSessionID].pApi, sessionInfoList[nSessionID].pCtx,
	            pSrc, *nSrcLen, szTemp, &nDstLen);
	if( reVal != 0 )
	{
		D("SPC Decryption fail");
		free(szTemp);
		return 0;
	}

    unsigned int i = 0;
    for(i = 0 ; i < nDstLen ; ++i) {
        pSrc[i] = szTemp[i];
    }
    *nSrcLen = nDstLen;
    free(szTemp);

    return 1;
}

#ifdef __cplusplus
}
#endif




