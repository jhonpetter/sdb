/**
 * \file	DtcpCTcpSocket.h
 * \brief	DtcpCTcpSocket class
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Soyoung Lee, Sangsu Choi
 * Dept : Core S/W Component Lab, Digital Media Laboratory
 * Creation date : 2008/09/02 
 */

#ifndef __DTCPCTCPSOCKET_H
#define __DTCPCTCPSOCKET_H


#ifdef _WIN32_ 
// <windows.h>가 <winsock.h>를 include하고 
// common C++가 <winsock2.h>를 include해서 struct redefinition problem이 발생
// 하므로 다음 literal을 추가
#define _WINSOCKAPI_ 
        #include <windows.h>
        #include <winsock2.h>
        #include <windef.h>
#elif defined _ANYVIEW
// <windows.h>가 <winsock.h>를 include하고 
// common C++가 <winsock2.h>를 include해서 struct redefinition problem이 발생
// 하므로 다음 literal을 추가
#define _WINSOCKAPI_ 
        #include <windows.h>
        #include <winsock2.h>
        #include <windef.h>
#elif  _LINUX  
        #include <unistd.h>
        #include <sys/socket.h>
		#include <sys/ioctl.h>
        #include <arpa/inet.h>
        #include <fcntl.h>
#endif
#include <cstdio>

#include "CC_Type.h"
//#include "DtcpCConstants.h"
//#include "DtcpCErrorCode.h"

////////////////////////////////////////////////////////////////////////////////
// Constants
////////////////////////////////////////////////////////////////////////////////
#define DTCP_QUE_LIMIT		5		// Maximum outstanding connection requests
#define INFINITE_32			0xffffffff

/**
* DtcpCTcpSocket class
*/
class DtcpCTcpSocket  
{
public:

#ifndef _DTCP_PLUS
	/**
	constructor
	*/
	DtcpCTcpSocket();
	/**
	constructor 
	@param uFd (Input) - File descriptor
	*/
	DtcpCTcpSocket(cc_u32 uFd);

#else
	/**
	constructor
	*/
	DtcpCTcpSocket(bool bSetTTL = true);
	/**
	constructor 
	@param uFd (Input) - File descriptor
	*/
	DtcpCTcpSocket(cc_u32 uFd, bool bSetTTL = true);
#endif

	/**
	destructor
	*/
	virtual ~DtcpCTcpSocket();

	/**
	Bind 수행 
	@param pAddr (Input) - sockaddr structure의 포인터 
	@return Errorcode
	*/
	int					bindSocket(sockaddr_in* pAddr);

	/**
	Connect 함수 수행 
	@param pDest (Input) - sockaddr structure의 포인터 
	*/
	long				connectSocket(sockaddr_in* pDest);

	/**
	close socket 함수 실행
	@return Errorcode
	*/
	int					closeSocket(void);

	/**
	TTL 설정 
	*/
#ifdef _DTCP_PLUS
	void			SetTTL (bool bSetTTL = true);
#else
	void			SetTTL ();
#endif
	
	/**
	read method
	@param	pbyBuf (Output)- 읽은 메시지의 pointer
	@param	dwBufLen (Input)- 버퍼의 크기 
	@param	pdwRcvLen (Output)- 읽은 메시지의 크기 
	@param	dwMsec (Input) - timeout의 시간 

	@return	Errorcode 		
	*/	
	int read(cc_u8* pbyBuf, 
			  cc_u32 dwBufLen, 
			  cc_u32* pdwRcvLen, 
			  cc_u32 dwMsec);		
		
	/*
	//read in non-blocking mode 
	inline cc_u32 readNB(char* pchBuf, 
					  cc_u32 dwBufLen, 
					  cc_u32* pdwRcvLen)
	{
		return read(pchBuf, dwBufLen, pdwRcvLen, 0);
	};
	
	  */
	
	// query TCP socket to see how many bytes are in read buffer
	/**
	read buffer안에 읽을 바이트가 있는지 확인
	@param iBufLen (Output)- 읽을 메시지의 bytes
	@return Errorcode
	*/
	long readBufLen(int* iBufLen);

	/**	

	@param	pchBuf (Input) - 보낼 메시지의 포인터
	@param	dwBufLen (Input) - 보낼 메시지의 길이 
	@param	pdwSndLen (Output) - 보낸 메시지의 길이 

	@return	Errorcode
	*/
	int send(const char* pchBuf, 
			 cc_u32 dwBufLen, 
			 cc_u32* pdwSndLen);

	/*int send(const cc_u8* pbyBuf, 
			 cc_u32 dwBufLen, 
			 cc_u32* pdwSndLen);

	*/

		
	/**
	file descriptor 얻기 
	@return file descriptor value
	*/
	inline int getFd(void) const {return m_iFd;};
		
	//////////////////////////////////////////////////////////////////////
	// Address(member attributes) interface functions
	/**
	local Address 얻기
	@return address
	*/
	inline cc_u32			getLocalAddr(void) const {return ntohl(m_AddrLocal.sin_addr.s_addr);};

	/**
	local port host byte형태 얻기   
	@return port
	*/
	inline cc_u16	getLocalPort(void) const {return ntohs(m_AddrLocal.sin_port);};

	/**
	목적지 host byte형태의 주소 얻기 
	@return address
	*/
	inline cc_u32			getDestAddr(void) const {return ntohl(m_AddrDest.sin_addr.s_addr);};

	/**
	목적지 host byte형태의 port 얻기 
	@return port
	*/
	inline cc_u16	getDestPort(void) const {return ntohs(m_AddrDest.sin_port);};
	
	/**
	local address를 string으로 얻기 
	@return address의 sting
	*/
	inline char* getLocalAddrStr(void) {return inet_ntoa(m_AddrLocal.sin_addr);};

	/**
	목적지의 address를 string으로 얻기 
	@return address의 string 
	*/
	inline char* getLocalDestStr(void) {return inet_ntoa(m_AddrDest.sin_addr);};

	//////////////////////////////////////////////////////////////////////
	// Non-blocking
	/**
	nonblocking 인지 검사
	@return nonblocking flag 값
	*/
	inline bool isNonBlocking(void) const {return m_bNonBlocking;};

	/**
	nonblocking flag설정 
	@param bNonBlocking (Input) - nonbloking flag
	@return  설정 성공 여부 
	*/
	bool 		setNonBlocking(bool bNonBlocking);

	/**
	listen 함수 
	@return Errorcode
	*/
	int 			listen(void);
	
	/**
	accept 함수 
	@return 새로운 socket pointer
	*/
	DtcpCTcpSocket*	accept(void);
protected:	

private:
	/**
	socket을  통신을 위한 초기화(file descriptor,address copy)
	@return Errorcode
	*/
	int		init(void);

//Variable
public:
protected:
private:
#ifdef _WIN32_
		SOCKET			m_iFd;
#elif  _ANYVIEW
		SOCKET			m_iFd;
#else
		int 			m_iFd;
#endif
		struct			sockaddr_in m_AddrLocal;	
		struct			sockaddr_in m_AddrDest;

		bool			m_bNonBlocking;
#ifdef _DTCP_PLUS		
		bool			m_bSetTTL; 
#endif
};

#endif 
