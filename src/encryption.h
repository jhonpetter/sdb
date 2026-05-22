#ifndef __SECURITY_H__
#define __SECURITY_H__

#ifdef __cplusplus
extern "C" {
#endif

int security_init(const int nSessionID, const char* pUserID);
int security_deinit(const int nSessionID);
int security_gen_server_hello(const int nSessionID, unsigned char* pSrc, unsigned int* nSrcLen);
int security_parse_client_hello(const int nSessionID, unsigned char* pSrc, unsigned int* nSrcLen);
int security_gen_server_ack(const int nSessionID, unsigned char* pSrc, unsigned int* nSrcLen);
int security_parse_client_ack(const int nSessionID, unsigned char* pSrc, unsigned int* nSrcLen);
int security_encrypt(const int nSessionID, unsigned char* pSrc, unsigned int* nSrcLen);
int security_decrypt(const int nSessionID, unsigned char* pSrc, unsigned int* nSrcLen);

#ifdef __cplusplus
}
#endif

#endif
