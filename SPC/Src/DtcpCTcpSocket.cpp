// DtcpCTcpSocket.cpp: implementation of the DtcpCTcpSocket class.
//
//////////////////////////////////////////////////////////////////////
#include "DRMLog.h"
#include "DtcpCTcpSocket.h"
//#include "DtcpCUtil.h"

#ifndef _LINUX
#include <winsock2.h>
//#define _WSPIAPI_COUNTOF
#include <Ws2tcpip.h>
#endif

#define DEFAULT_TTL_VALUE 64
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
FILE*       logfile = NULL;
FILE*       msgfile = NULL;
DRMLOG_CTX  DtcpLogCTX;
 

/// tcpip 
#define	DTCP_TCPIP_SUCCESS					DTCP_SUCCESS
#define DTCP_TCPIP_SOCKET_CLOSED			DTCP_SUCCESS + 1
#define	DTCP_ERR_TCPIP_BIND					-151
#define	DTCP_ERR_TCPIP_CONNECT				-152
#define	DTCP_ERR_TCPIP_READ					-153
#define	DTCP_ERR_TCPIP_SEND					-154
#define	DTCP_ERR_TCPIP_CLOSE				-155
#define	DTCP_ERR_TCPIP_LISTEN				-156
#define	DTCP_ERR_TCPIP_ACCEPT				-157
#define DTCP_SOCKET_TIMEOUT					-158

/// common
#define DTCP_SUCCESS						0								/// Function succeeded
#define DTCP_FAILURE						-1								/// General failure

/*
#ifdef _WIN32_
int GetLocalIP (IN_ADDR* localHost)
#elif _LINUX
int GetLocalIP (struct in_addr* localHost)
#endif

{

	#ifndef _LINUX //anyview , win32
		WSADATA wsaData;
		if (0 == WSAStartup(MAKEWORD(2, 2), &wsaData))
		{
			if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
			{
				WSACleanup();				
				return DTCP_FAILURE;
			}
		}
		
		int reValue;	
		char aHostName [255];
		HOSTENT *pHost;
		
		memset(aHostName, 0x00, 255);
		gethostname(aHostName, 255);
		pHost = gethostbyname(aHostName);
		
		
		if(pHost==NULL)
		{
			reValue = DTCP_FAILURE;
		}
		else 
		{
			memcpy(localHost, pHost->h_addr, pHost->h_length);
			reValue = DTCP_SUCCESS;
		}
	 
		WSACleanup ();
#else //LINUX
	
		int reValue = DTCP_SUCCESS, s;	
	
		struct ifreq	ifr;
		struct sockaddr_in *sin = (struct sockaddr_in*)&ifr.ifr_addr;
		
		memset(&ifr,0, sizeof ifr);
		memset(localHost,0,sizeof(localHost));
		
		if(0 > (s = socket(AF_INET,SOCK_STREAM,0))){
			return DTCP_ERR_LOCALIP;
		}
	
		strcpy(ifr.ifr_name,"eth0");
		sin->sin_family = AF_INET;

		
		if(0 == ioctl(s,SIOCGIFADDR,&ifr)){
				if(!inet_aton(inet_ntoa(sin->sin_addr),localHost))
				return DTCP_ERR_LOCALIP;
		}
	 
		::close(s);
		  
	 
 #endif
	return reValue;
}	

*/

/**
*Constructor [DtcpCTcpSocket]
*	Parameters:
*	Return Value:
*/
#ifdef _DTCP_PLUS
DtcpCTcpSocket::DtcpCTcpSocket (bool bSetTTL)
#else
DtcpCTcpSocket::DtcpCTcpSocket ()
#endif 
{
	int iReuseAddr = 1;
	
	init();		

	if (0 == m_iFd)
		m_iFd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	DRMLOG_Msg (&DtcpLogCTX, LOG_DEBUG, "[Network] Socket m_iFd: %d\n",m_iFd);	

	if (0 != ::setsockopt(m_iFd, SOL_SOCKET, SO_REUSEADDR, 
                            (const char*)&iReuseAddr, sizeof(iReuseAddr)))
		DRMLOG_Msg (&DtcpLogCTX, LOG_ERROR,
                                    "[Network] %s \n","setsockopt Error");	
	else 
	{
#ifdef _DTCP_PLUS
		SetTTL (bSetTTL);		
#else
		SetTTL ();
#endif
	}

}

void 
#ifdef _DTCP_PLUS
DtcpCTcpSocket::SetTTL (bool bSetTTL)
#else
DtcpCTcpSocket::SetTTL ()
#endif
{
#ifdef _DTCP_PLUS
	if (bSetTTL == true)
#endif
	{
		int aTtl = 3;
		setsockopt (m_iFd, IPPROTO_IP, IP_TTL, (char*)&aTtl, sizeof (aTtl));		
	}
#ifdef _DTCP_PLUS
	else
	{
		int aTtl = DEFAULT_TTL_VALUE;
		setsockopt (m_iFd, IPPROTO_IP, IP_TTL, (char*)&aTtl, sizeof (aTtl));		
	}
#endif
}

/**
* Constructor [DtcpCTcpSocket with parameter]
*	Parameters:
*			uFd
*				[in] Socket handle (File descriptor)
*	Return Value:
*/
#ifdef _DTCP_PLUS
DtcpCTcpSocket::DtcpCTcpSocket(cc_u32 uFd, bool bSetTTL)
#else
DtcpCTcpSocket::DtcpCTcpSocket(cc_u32 uFd)
#endif
{
	int iReuseAddr = 1;

	init();		
	
	m_iFd = uFd;	
	DRMLOG_Msg (&DtcpLogCTX, LOG_DEBUG,"[Network] Socket m_iFd: %d\n",m_iFd);

	if (0 != ::setsockopt(m_iFd, 
						SOL_SOCKET, 
						SO_REUSEADDR, 
						(const char*)&iReuseAddr, 
						sizeof(iReuseAddr)))
	{
		printf("DtcpCTcpSocket==> setsockopt Error!\n");

	}
	else 
	{
#ifdef _DTCP_PLUS
		SetTTL (bSetTTL);		
#else
		SetTTL ();
#endif
	}

}

DtcpCTcpSocket::~DtcpCTcpSocket()
{

	//printf ("~DtcpCTcpSocket::DtcpCTcpSocket \n");
	
	closeSocket();
#ifdef _WIN32_
	::WSACleanup();
#elif _ANYVIEW
	::WSACleanup();
#endif

}

#ifdef _WIN32_
static int iWinSockInit = FALSE;
#elif _ANYVIEW
static int iWinSockInit = FALSE;
#endif


/**
*	Initialize socket
*	Parameters:
*	Return Value:
*/
int DtcpCTcpSocket::init()
{
#ifdef _WIN32_
	if (TRUE == iWinSockInit)
		return (DTCP_TCPIP_SUCCESS);
	
	else
	{
		WSADATA wsaData;
		
		
		if (0 == ::WSAStartup(MAKEWORD(2, 2), &wsaData))
		{
			if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
			{
				::WSACleanup();				
			}
		}
	}
#elif _ANYVIEW
	if (TRUE == iWinSockInit)
		return (DTCP_TCPIP_SUCCESS);
	
	else
	{
		WSADATA wsaData;
		
		if (0 == ::WSAStartup(MAKEWORD(2, 2), &wsaData))
		{
			if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
			{
				::WSACleanup();
			}
		}
	}	
#endif
	
	::memset(&m_AddrLocal, 0, sizeof(struct sockaddr_in));
	::memset(&m_AddrDest, 0, sizeof(struct sockaddr_in));
	m_iFd = 0;
	m_bNonBlocking = false;

	
	return DTCP_TCPIP_SUCCESS;
}

/**	
*Bind a socket to a specified port and IP address
*	Parameters:
*		pAddr
*			[in] Pointer to a sockaddr structure
*	Return Value:
*/
int 
DtcpCTcpSocket::bindSocket(sockaddr_in* pAddr)
{
	m_AddrLocal.sin_family		= AF_INET;
	m_AddrLocal.sin_port		= pAddr->sin_port;
	m_AddrLocal.sin_addr.s_addr = pAddr->sin_addr.s_addr;

	int reValue = ::bind(m_iFd, (struct sockaddr *)&m_AddrLocal, sizeof(struct sockaddr_in));
	if (0 != reValue )
	{
		DRMLOG_Msg (&DtcpLogCTX, LOG_ERROR,
                "Bind Error [Address %s, Port %d ] \n", 
				inet_ntoa(m_AddrLocal.sin_addr), ntohs (pAddr->sin_port)
        );
		return DTCP_ERR_TCPIP_BIND;
	}

	SetTTL ();
	
	return DTCP_TCPIP_SUCCESS;
}

/**
*	Estabilish a connection to a specified socket (to a remote computer)
*	Parameters:
*		pDest
*			[in] Pointer to a sockaddr structure
*	Return Value:
*/
long 
DtcpCTcpSocket::connectSocket(sockaddr_in* pDest)
{
	m_AddrDest.sin_family		= AF_INET;
	m_AddrDest.sin_port			= pDest->sin_port;
	m_AddrDest.sin_addr.s_addr	= pDest->sin_addr.s_addr;
	
	//////////////////////////////////////////////////////////////////
	// for TTL Setting 
	// юс╫ц..
	
#ifndef _LINUX
	IN_ADDR 	inLocalAddr;
	GetLocalIP (&inLocalAddr);
	
	sockaddr_in	LocalAddr;
	LocalAddr.sin_family		= AF_INET;
	LocalAddr.sin_addr.s_addr	= inLocalAddr.s_addr;
	LocalAddr.sin_port			= htons(0);
	
	bindSocket (&LocalAddr);
#endif

	if (0 != ::connect(m_iFd, (struct sockaddr *)&m_AddrDest, sizeof(m_AddrDest)))
	{
		printf ("After connect \n");
#ifdef _WIN32_
		cc_u32 i = WSAGetLastError();
#elif _ANYVIEW
		cc_u32 i = WSAGetLastError();
#endif
	
		DRMLOG_Msg (&DtcpLogCTX, LOG_ERROR,"[Network] %s\n", "Connect Error");
		return DTCP_ERR_TCPIP_CONNECT;
	}
	
	SetTTL ();	
	return DTCP_TCPIP_SUCCESS;
}
/**
*	Read char-typed data from a connected or bound socket
*	Parameters:
*		pchBuf
*			[out] char-typed Buffer for incoming data
*		dwBufLen
*			[in] Length of buffer
*		pdwRcvLen
*			[out] Received length
*		dwMsec
*			[in] timeout
*	Return Value:
*/
/*
int 
DtcpCTcpSocket::read(cc_u8* pchBuf, 
						cc_u32 dwBufLen, 
						cc_u32* pdwRcvLen, 
						cc_u32 dwMsec)
{
	// Synchronization I/O

	if (INFINITE_32 != dwMsec)
	{
		int iRes = 0;
		
		fd_set	readset;
		timeval t;
		
		t.tv_sec	= dwMsec/1000;
		t.tv_usec	= (dwMsec%1000) * 1000;
		
		FD_ZERO(&readset);
		FD_SET(m_iFd, &readset);

#ifdef _DTCP_DEBUG_VER		
		LOG_DEBUG(&DtcpLogCTX), "[network] DtcpCTcpSocket::read ==> m_iFd: %d\n",m_iFd);
	//	printf("DtcpCTcpSocket::read ==> m_iFd: %d\n", m_iFd);
#endif

		iRes = select(m_iFd+1, &readset, 0, 0, NULL);
		if (-1 == iRes)
		{
#ifdef _DTCP_DEBUG_VER		
			LOG_INFO(&DtcpLogCTX), "[network] %s\n","DtcpCTcpSocket::read ==> select error!");
			printf("DtcpCTcpSocket::read ==> select error!\n");
#endif	
			return DTCP_ERR_TCPIP_READ;
		}		
		else if (0 == iRes)
		{
#ifdef _DTCP_DEBUG_VER		
			LOG_INFO(&DtcpLogCTX), "[network]%s\n","DtcpCTcpSocket::read ==> select error!, Time-out");
			//printf("DtcpCTcpSocket::read ==> select error!, Time-out\n");
#endif
			//return DTCP_ERR_TCPIP_READ;
		}
			
		if (0 == FD_ISSET(m_iFd, &readset))
		{
#ifdef _DTCP_DEBUG_VER		
			LOG_INFO(&DtcpLogCTX), "[network] %s\n","DtcpCTcpSocket::read ==> FD_ISSET error!");
			//printf("DtcpCTcpSocket::read ==> FD_ISSET error!\n");
#endif		
			return DTCP_ERR_TCPIP_READ;
		}
	}

#ifdef _DTCP_DEBUG_VER
	LOG_INFO(&DtcpLogCTX), "[network] %s\n","DtcpCTcpSocket::read ==> before ::recv!");
	//printf("DtcpCTcpSocket::read ==> before ::recv\n");
#endif

	*pdwRcvLen = ::recv(m_iFd, (char *)pchBuf, dwBufLen, 0);


#ifdef _DTCP_DEBUG_VER
	LOG_INFO(&DtcpLogCTX), "[network] DtcpCTcpSocket::read ==> after ::recv, ReceivedLength: %d\n",*pdwRcvLen);
//	printf("DtcpCTcpSocket::read ==> after ::recv, ReceivedLength: %d\n", dwBufLen);
#endif	

	
	if (*pdwRcvLen == (unsigned)-1)
	{
		*pdwRcvLen = 0;

#ifdef _DTCP_DEBUG_VER
		LOG_INFO(&DtcpLogCTX), "[network] %s\n","DtcpCTcpSocket::read ==> Recv Error !");
		//printf("DtcpCTcpSocket::read ==> Recv Error !\n");
#endif	

		return DTCP_ERR_TCPIP_READ;
	}
	else if (0 == *pdwRcvLen)
		return DTCP_TCPIP_SOCKET_CLOSED;


#ifdef _DTCP_DEBUG_VER
	LOG_INFO(&DtcpLogCTX), "[network] %s\n","DtcpCTcpSocket::read ==> Recv Success !");
	//printf("DtcpCTcpSocket::read ==> Recv Success \n");
#endif	

	return DTCP_TCPIP_SUCCESS;
}
*/

#if 0
int 
DtcpCTcpSocket::read(cc_u8* pbyBuf, 
					 cc_u32 dwBufLen, 
					 cc_u32* pdwRcvLen, 
					 cc_u32 dwMsec)
{

//	cc_u32 t0=GetTickCount();
	//*pdwRcvLen = ::recv(m_iFd, (char *)pbyBuf, dwBufLen, 0);
	*pdwRcvLen = ::recv(m_iFd, (char *)pbyBuf, dwBufLen, 0);
	/*
#ifdef _WIN32_
	*pdwRcvLen = ::recv(m_iFd, (char *)pbyBuf, dwBufLen, 0);	

#elif _ANYVIEW
	*pdwRcvLen = ::recv(m_iFd, (char *)pbyBuf, dwBufLen, 0);	
#else
	*pdwRcvLen = ::recv(m_iFd, (char *)pbyBuf, dwBufLen, 0);
#endif
*/
/*
    cc_u32 t1=GetTickCount();
	if( (t1 - t0 )>= dwMsec)
	{
		printf(" Time out!\n");
		return DTCP_ERR_TCPIP_READ;
	}
	else
		printf(" %ld \n",(t1-t0));
*/
	if (*pdwRcvLen == (unsigned)-1)
	{
		*pdwRcvLen = 0;
		return DTCP_ERR_TCPIP_READ;
	}
	else if (0 == *pdwRcvLen)
		return DTCP_TCPIP_SOCKET_CLOSED;

	return DTCP_TCPIP_SUCCESS;
}

#endif 
int 
DtcpCTcpSocket::read(cc_u8* pbyBuf, 
					 cc_u32 dwBufLen, 
					 cc_u32* pdwRcvLen, 
					 cc_u32 dwMsec)
{

	*pdwRcvLen = 0;
	cc_u32 uRecvLen = 0 ;

	fd_set fds ;
    int n ;
    struct timeval tv ;

    // Set up the file descriptor set.
    FD_ZERO(&fds) ;
    FD_SET(m_iFd, &fds) ;

    // Set up the struct timeval for the timeout.
    tv.tv_sec = dwMsec/1000 ;
    tv.tv_usec = 0 ;

    // Wait until timeout or data received.
    n = select ( m_iFd+1, &fds, NULL, NULL, &tv ) ;
    if ( n == 0  ) 
    {
		printf ("TimeOut \n");
		return DTCP_SOCKET_TIMEOUT;
		
    }
    else if (n == 1)
    {
		uRecvLen = ::recv(m_iFd, (char *)pbyBuf, dwBufLen, 0);
		*pdwRcvLen = uRecvLen;

		if (uRecvLen != dwBufLen)
		{
			DRMLOG_Msg (&DtcpLogCTX, LOG_INFO,
                    "Requested length %d, Read length %d \n",dwBufLen,uRecvLen);
		}
		
    }
    else 
    {
		printf ("Error \n");
		return DTCP_FAILURE;		
    }
    
	/*

	do 
	{
		uRecvLen = ::recv(m_iFd, (char *)pbyBuf, dwBufLen, 0);

		if (uRecvLen != -1)
			*pdwRcvLen += uRecvLen;
		
		uEndTime = timeGetTime ();
		if (uEndTime - uStartTime > dwMsec)
		{
			printf ("TimeOut !!! \n");
			break;
		}
	}while (dwBufLen < *pdwRcvLen);
	*/
	//DRMLOG_Msg(&DtcpLogCTX,LOG_ERROR,"*pdwRcvLen %d , %d \n", *pdwRcvLen, (uEndTime - uStartTime));

	
//	cc_u32 t0=GetTickCount();
	//*pdwRcvLen = ::recv(m_iFd, (char *)pbyBuf, dwBufLen, 0);
	//*pdwRcvLen = ::recv(m_iFd, (char *)pbyBuf, dwBufLen, 0);
	/*
#ifdef _WIN32_
	*pdwRcvLen = ::recv(m_iFd, (char *)pbyBuf, dwBufLen, 0);	

#elif _ANYVIEW
	*pdwRcvLen = ::recv(m_iFd, (char *)pbyBuf, dwBufLen, 0);	
#else
	*pdwRcvLen = ::recv(m_iFd, (char *)pbyBuf, dwBufLen, 0);
#endif
*/
/*
    cc_u32 t1=GetTickCount();
	if( (t1 - t0 )>= dwMsec)
	{
		printf(" Time out!\n");
		return DTCP_ERR_TCPIP_READ;
	}
	else
		printf(" %ld \n",(t1-t0));
*/
	if (*pdwRcvLen == (unsigned)-1)
	{
		*pdwRcvLen = 0;
		return DTCP_ERR_TCPIP_READ;
	}
	else if (0 == *pdwRcvLen)
		return DTCP_TCPIP_SOCKET_CLOSED;

	return DTCP_TCPIP_SUCCESS;
}


/**
*	Query TCP socket to see how many bytes are in read buffer
*	Parameters:
*		iBufLen
*			[out] Length of buffer
*	Return Value:
*/
long 
DtcpCTcpSocket::readBufLen(int* iBufLen)
{
    if (NULL != iBufLen)
    {
#ifdef _WIN32_
        if (0 != ioctlsocket(
#elif _ANYVIEW
        if (0 != ioctlsocket(
#else
        if (ioctl(
#endif
                m_iFd, 
                FIONREAD, 
#ifdef _WIN32_
                (u_long *)iBufLen))
#elif _ANYVIEW
                (cc_u32 *)iBufLen))
#else
                iBufLen))
#endif
            return DTCP_ERR_TCPIP_READ;
       
    }
    else
        return DTCP_ERR_TCPIP_READ;    

    return DTCP_TCPIP_SUCCESS;	
}

/*
*	Send char-typed data on a connected socket
*	Parameters:
*		pchBuf
*			[in] char-typed Buffer containing the data to be transmitted
*		dwBufLen
*			[in] Length of buffer
*		pdwSndLen
*			[out] 
*	Return Value:
*/
int 
DtcpCTcpSocket::send(const char* pchBuf, cc_u32 dwBufLen, cc_u32* pdwSndLen)
{

#ifdef _DTCP_DEBUG_VER
#ifdef _DTCP_FILE_LOG
	if (pchBuf[0] == 0x01)
	{ 
		fprintf (msgfile, "\n\n*** Send Msg ***");
		PrintAkeMessage ((cc_u8 *)pchBuf, dwBufLen);	
	}
#endif     
#endif

#ifdef _WIN32_	
	cc_u32 iFlags = 0;
	*pdwSndLen = ::send(m_iFd, pchBuf, dwBufLen, iFlags);
	
#elif _ANYVIEW
	cc_u32 iFlags;
	*pdwSndLen = ::send(m_iFd, pchBuf, dwBufLen, iFlags);
#elif _LINUX
	*pdwSndLen = write(m_iFd,pchBuf,dwBufLen);
#endif



	if ((unsigned)-1 == *pdwSndLen)
	{
		*pdwSndLen = 0;

		return DTCP_ERR_TCPIP_SEND;
	}

	return DTCP_TCPIP_SUCCESS;
}

/**
*	Send cc_u8-typed data on a connected socket
*	Parameters:
*		pbyBuf
*			[in] cc_u8-typed Buffer containing the data to be transmitted
*		dwBufLen
*			[in] Length of buffer
*		pdwSndLen
*			[out] 
*	Return Value:
*/
/*
int 
DtcpCTcpSocket::send(const cc_u8* pbyBuf, cc_u32 dwBufLen, cc_u32* pdwSndLen)
{

	int iFlags = 0;

#ifdef _WIN32
	*pdwSndLen = ::send(m_iFd, (char *)pbyBuf, dwBufLen, iFlags);
#else
	*pdwSndLen = ::send(m_iFd, pbyBuf, dwBufLen, iFlags);
#endif

	if ((unsigned)-1 == *pdwSndLen)
	{
		*pdwSndLen = 0;

		return DTCP_ERR_TCPIP_SEND;
	}
	else if (0 == *pdwSndLen)
		return DTCP_TCPIP_SOCKET_CLOSED;

	return DTCP_TCPIP_SUCCESS;
}
*/
/**
*	Set non-blocking mode
*	Parameters:
*	Return Value:
*/
bool 
DtcpCTcpSocket::setNonBlocking(bool bNonBlocking)
{
	m_bNonBlocking = bNonBlocking;
	
	return true;
}

/**
*	Close an exiting socket
*	Parameters:
*	Return Value:
*/
int 
DtcpCTcpSocket::closeSocket(void)
{
	if (m_iFd == 0)
	{
		return DTCP_ERR_TCPIP_CLOSE;
	}
	
	DRMLOG_Msg (&DtcpLogCTX, LOG_DEBUG,"[Network] closesocket %d\n",m_iFd);

	int reValue = 0;
#ifdef _WIN32_	
	reValue = ::closesocket(m_iFd);
#elif _ANYVIEW
	reValue = ::closesocket(m_iFd); 
#else
	reValue = ::shutdown (m_iFd,SHUT_RDWR);
	if (reValue == 0)
	{
		reValue = ::close(m_iFd);
	}
#endif

	m_iFd = 0;
	if (reValue != 0)
	{
		return DTCP_ERR_TCPIP_CLOSE;
	}
	else 
	{
		return DTCP_TCPIP_SUCCESS;
	}
}



/**
*	Listen
*	Parameters:
*	Return Value:
*/
int 
DtcpCTcpSocket::listen(void)
{
	int reValue = ::listen(m_iFd, SOMAXCONN); 
	if (reValue != 0)
	{
		DRMLOG_Msg (&DtcpLogCTX, LOG_ERROR,
                " Listen Error [ErrorCode :%d] \n",reValue);
	}
	
	return reValue;

	//return (0 != ::listen(m_iFd, SOMAXCONN) ? DTCP_ERR_TCPIP_LISTEN : DTCP_TCPIP_SUCCESS);
}

/**
*	Permit an incoming connection attempt on a socket
*	(Block waiting for a remote connection on a bound socket)
*	Parameters:
*	Return Value:
*/
DtcpCTcpSocket* 
DtcpCTcpSocket::accept()
{
	struct sockaddr destAddr;
#ifdef _WIN32_
	int iDestSize 		= sizeof(destAddr);
#elif _ANYVIEW
	int iDestSize 		= sizeof(destAddr);
#else
	socklen_t iDestSize	= sizeof(destAddr);
#endif

	int iFd = -1;
	while (1)
	{
		iFd = ::accept(m_iFd, &destAddr, &iDestSize);

		if (-1 == iFd)
		{
			DRMLOG_Msg (&DtcpLogCTX, LOG_ERROR,
                                        "[Network] %s\n","Accept FAILURE\n");
			return NULL;
		}
		else
		{
			DRMLOG_Msg (&DtcpLogCTX, LOG_INFO,
                                "[Network] accept socketId m_iFd: %d\n",m_iFd);
		}
		break;
	}
	
	DtcpCTcpSocket* ptSocket = new DtcpCTcpSocket((cc_u32)iFd);

	memcpy(&ptSocket->m_AddrDest, &destAddr, sizeof(m_AddrLocal));
	memcpy(&ptSocket->m_AddrLocal, &m_AddrLocal, sizeof(m_AddrLocal));
	
#ifdef _DTCP_PLUS
		SetTTL (true);		
#else
		SetTTL ();
#endif

	return ptSocket;
}



