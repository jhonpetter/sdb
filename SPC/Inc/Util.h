

/*
#ifdef _LINUX
	unsigned long long timeGetTime();
#endif
*/
/**
4byte unsinged char * 를 unsigned int 로 변환.
@param pData (Input) - 변환할 unsigned char 의 시작 포인터 
@param uData (Output) - 변환된 unsigned int Data 
*/
void ConvertUint8ToUint32 (unsigned char* pData, unsigned int* uData);

/**
unsigned int 를 4byte unsigned char *로 변환 
@param uData (Input) - 변환할 unsigned int Data 
@param pData (Output) - 변환된 unsigned char 의 시작 포인터 
*/
void ConvertUint32ToUint8 (unsigned int uData, unsigned char* pData);

/**
 * @fn		GetFileLength(FILE *pFp,int *nFileLen)
 * @brief	Get File length
 *
 * @param	[in] pOutMsg		Input File pointer
 * @param	[out] nOutLen		file total length
 * @return	result of GetFileLength
*/
int GetFileLength(FILE *pFp,int *nFileLen);