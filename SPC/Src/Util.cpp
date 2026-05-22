#include <stdio.h>

/**
4byte unsinged char * 를 unsigned int 로 변환.
@param pData (Input) - 변환할 unsigned char 의 시작 포인터 
@param uData (Output) - 변환된 unsigned int Data 
*/
void ConvertUint8ToUint32 (unsigned char* pData, unsigned int* uData)
{	
	*uData = pData[0] << 24 | pData [1] << 16 | 
					pData [2] << 8 | pData [3];
}

/**
unsigned int 를 4byte unsigned char *로 변환 
@param uData (Input) - unsigned int Data to convert
@param pData (Output) - 변환된 unsigned char 의 시작 포인터 
*/
void ConvertUint32ToUint8 (unsigned int uData, unsigned char* pData)
{
	pData [0] = (unsigned char) (uData >> 24);
	pData [1] = (unsigned char) (uData >> 16);
	pData [2] = (unsigned char) (uData >> 8);
	pData [3] = (unsigned char) (uData);
}

/**
 * @fn		GetFileLength(FILE *pFp,int *nFileLen)
 * @brief	Get File length
 *
 * @param	[in] pOutMsg		Input File pointer
 * @param	[out] nOutLen		file total length
 * @return	result of GetFileLength
*/
int GetFileLength(FILE *pFp,int *nFileLen)
{
	int reVal = 0;

	fseek(pFp,0,SEEK_END);

	*nFileLen = ftell(pFp);

    fseek(pFp,0,SEEK_SET);

	return reVal;
}