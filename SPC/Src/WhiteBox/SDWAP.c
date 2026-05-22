/**
 * @file	SDWAP.c
 * @brief	Dynamic white box AES module for SSA(Samsung Security Architecture)
 * @author	Samsung Dynamic WhiteBox AES 
 *				- Chul Lee(chuls.lee@samsung.com)
 *				- Dept : Software R&D Center / Cloud Computing Lab.
 *
 * @see		SDWAP
 * @date	2013-01-10
 * @version	1.0
 * @par		Copyright:
 * Copyright 2013 by Samsung Electronics, Inc.,
 * This software is the confiedential and properietary information 
 * of Samsung Elctronics, Inc. ("Confidential Information"). You 
 * shall not disclose such Confidential Information and shall use 
 * it only in accordance with the term of the lice agreement 
 * you entered into with Samsung.
 * @par		Warning:
 * This code sould not be exported out of Samsung Electronics.
 * This code cannot be inserted in any customer device.
 * The logic of dynamic whitebox table generation is confidential.
 */



////////////////////////////////////////////////////////////////////////////
// including header files
////////////////////////////////////////////////////////////////////////////
#include <memory.h>
#include <stdio.h>
#include "SDWAP_defines.h"
#include "SDWAP.h"


////////////////////////////////////////////////////////////////////////////
// function implementations
////////////////////////////////////////////////////////////////////////////
/*
 * @fn		static void SDWAP_Encryption(SDWAP_TBOX *pTBox, SDWAP_PBOX *pPBox, unsigned int Nr, unsigned char* in, unsigned char* out, unsigned int isLittleEndian)
 * @brief	SDWAP Encryption function.
 *
 * @param	[in] pTBox			T-Box
 * @param	[in] pPBox			P-Box
 * @param	[in] pWPBox			word(4byte) permutation box
 * @param	[in] pBPBox			bit permutation box
 * @param	[in] Nr				number of rounds
 * @param	[in] in				input bytes(16-byte length)
 * @param	[out] out			output bytes(16-byte length)
 * @param	[in] isLittleEndian	flag for little endian
 * @return	void
 */
static void SDWAP_Encryption(SDWAP_TBOX *pTBox, SDWAP_KEY_LOOKUP *pKeyLookup, SDWAP_PBOX *pPBox, SDWAP_WORD_PBOX* pWPBox, SDWAP_BIT_PBOX* pBPBox, unsigned int Nr, unsigned char* in, unsigned char* out, unsigned int isLittleEndian)
{
	unsigned int i;
	unsigned int idx = 0;
	unsigned int idx16;
	unsigned char idx_wps[16];
	unsigned char state[16];	//state
	unsigned char rk_xor[16] = {0x00,};
	SDWAP_WORD* itmdt[16];		//intermediate value

	//3. Process initial permutation
	idx_wps[(pPBox[0][0][0]) & 0x0f] = state[(pPBox[0][0][0]) & 0x0f] = in[ 0] ^ (*pKeyLookup)[0][0] ^ (*pKeyLookup)[0][4] ^ (*pKeyLookup)[0][8];
	idx_wps[(pPBox[0][0][1]) & 0x0f] = state[(pPBox[0][0][1]) & 0x0f] = in[ 1] ^ (*pKeyLookup)[1][0] ^ (*pKeyLookup)[1][4] ^ (*pKeyLookup)[1][8];
	idx_wps[(pPBox[0][0][2]) & 0x0f] = state[(pPBox[0][0][2]) & 0x0f] = in[ 2] ^ (*pKeyLookup)[2][0] ^ (*pKeyLookup)[2][4] ^ (*pKeyLookup)[2][8];
	idx_wps[(pPBox[0][0][3]) & 0x0f] = state[(pPBox[0][0][3]) & 0x0f] = in[ 3] ^ (*pKeyLookup)[3][0] ^ (*pKeyLookup)[3][4] ^ (*pKeyLookup)[3][8];
	idx_wps[(pPBox[0][0][4]) & 0x0f] = state[(pPBox[0][0][4]) & 0x0f] = in[ 4] ^ (*pKeyLookup)[0][1] ^ (*pKeyLookup)[0][5] ^ (*pKeyLookup)[0][9];
	idx_wps[(pPBox[0][0][5]) & 0x0f] = state[(pPBox[0][0][5]) & 0x0f] = in[ 5] ^ (*pKeyLookup)[1][1] ^ (*pKeyLookup)[1][5] ^ (*pKeyLookup)[1][9];
	idx_wps[(pPBox[0][0][6]) & 0x0f] = state[(pPBox[0][0][6]) & 0x0f] = in[ 6] ^ (*pKeyLookup)[2][1] ^ (*pKeyLookup)[2][5] ^ (*pKeyLookup)[2][9];
	idx_wps[(pPBox[0][0][7]) & 0x0f] = state[(pPBox[0][0][7]) & 0x0f] = in[ 7] ^ (*pKeyLookup)[3][1] ^ (*pKeyLookup)[3][5] ^ (*pKeyLookup)[3][9];
	idx_wps[(pPBox[0][1][0]) & 0x0f] = state[(pPBox[0][1][0]) & 0x0f] = in[ 8] ^ (*pKeyLookup)[0][2] ^ (*pKeyLookup)[0][6] ^ (*pKeyLookup)[0][10];
	idx_wps[(pPBox[0][1][1]) & 0x0f] = state[(pPBox[0][1][1]) & 0x0f] = in[ 9] ^ (*pKeyLookup)[1][2] ^ (*pKeyLookup)[1][6] ^ (*pKeyLookup)[1][10];
	idx_wps[(pPBox[0][1][2]) & 0x0f] = state[(pPBox[0][1][2]) & 0x0f] = in[10] ^ (*pKeyLookup)[2][2] ^ (*pKeyLookup)[2][6] ^ (*pKeyLookup)[2][10];
	idx_wps[(pPBox[0][1][3]) & 0x0f] = state[(pPBox[0][1][3]) & 0x0f] = in[11] ^ (*pKeyLookup)[3][2] ^ (*pKeyLookup)[3][6] ^ (*pKeyLookup)[3][10];
	idx_wps[(pPBox[0][1][4]) & 0x0f] = state[(pPBox[0][1][4]) & 0x0f] = in[12] ^ (*pKeyLookup)[0][3] ^ (*pKeyLookup)[0][7] ^ (*pKeyLookup)[0][11];
	idx_wps[(pPBox[0][1][5]) & 0x0f] = state[(pPBox[0][1][5]) & 0x0f] = in[13] ^ (*pKeyLookup)[1][3] ^ (*pKeyLookup)[1][7] ^ (*pKeyLookup)[1][11];
	idx_wps[(pPBox[0][1][6]) & 0x0f] = state[(pPBox[0][1][6]) & 0x0f] = in[14] ^ (*pKeyLookup)[2][3] ^ (*pKeyLookup)[2][7] ^ (*pKeyLookup)[2][11];
	idx_wps[(pPBox[0][1][7]) & 0x0f] = state[(pPBox[0][1][7]) & 0x0f] = in[15] ^ (*pKeyLookup)[3][3] ^ (*pKeyLookup)[3][7] ^ (*pKeyLookup)[3][11];

	//4. Process each rounds
	do
	{
		idx16 = (idx << 4);

		itmdt[ 0] = (SDWAP_WORD*)pTBox[idx16 +  0][state[ 0] >> 4][state[ 0] &  0xf];
		itmdt[ 1] = (SDWAP_WORD*)pTBox[idx16 +  1][state[ 1] >> 4][state[ 1] &  0xf];
		itmdt[ 2] = (SDWAP_WORD*)pTBox[idx16 +  2][state[ 2] >> 4][state[ 2] &  0xf];
		itmdt[ 3] = (SDWAP_WORD*)pTBox[idx16 +  3][state[ 3] >> 4][state[ 3] &  0xf];
		itmdt[ 4] = (SDWAP_WORD*)pTBox[idx16 +  4][state[ 4] >> 4][state[ 4] &  0xf];
		itmdt[ 5] = (SDWAP_WORD*)pTBox[idx16 +  5][state[ 5] >> 4][state[ 5] &  0xf];
		itmdt[ 6] = (SDWAP_WORD*)pTBox[idx16 +  6][state[ 6] >> 4][state[ 6] &  0xf];
		itmdt[ 7] = (SDWAP_WORD*)pTBox[idx16 +  7][state[ 7] >> 4][state[ 7] &  0xf];
		itmdt[ 8] = (SDWAP_WORD*)pTBox[idx16 +  8][state[ 8] >> 4][state[ 8] &  0xf];
		itmdt[ 9] = (SDWAP_WORD*)pTBox[idx16 +  9][state[ 9] >> 4][state[ 9] &  0xf];
		itmdt[10] = (SDWAP_WORD*)pTBox[idx16 + 10][state[10] >> 4][state[10] &  0xf];
		itmdt[11] = (SDWAP_WORD*)pTBox[idx16 + 11][state[11] >> 4][state[11] &  0xf];
		itmdt[12] = (SDWAP_WORD*)pTBox[idx16 + 12][state[12] >> 4][state[12] &  0xf];
		itmdt[13] = (SDWAP_WORD*)pTBox[idx16 + 13][state[13] >> 4][state[13] &  0xf];
		itmdt[14] = (SDWAP_WORD*)pTBox[idx16 + 14][state[14] >> 4][state[14] &  0xf];
		itmdt[15] = (SDWAP_WORD*)pTBox[idx16 + 15][state[15] >> 4][state[15] &  0xf];

		idx++;

		//Key-Lookup XOR
		state[ pPBox[idx][0][0] & 0x0f ] = (*itmdt[ pPBox[idx][0][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][4] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][0][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][5] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][0][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][6] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][0][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][7] & 0x0f ] &  0xf) % 4 ]][0] ];
		state[ pPBox[idx][0][1] & 0x0f ] = (*itmdt[ pPBox[idx][0][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][4] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][0][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][5] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][0][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][6] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][0][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][7] & 0x0f ] &  0xf) % 4 ]][1] ];
		state[ pPBox[idx][0][2] & 0x0f ] = (*itmdt[ pPBox[idx][0][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][4] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][0][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][5] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][0][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][6] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][0][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][7] & 0x0f ] &  0xf) % 4 ]][2] ];
		state[ pPBox[idx][0][3] & 0x0f ] = (*itmdt[ pPBox[idx][0][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][4] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][0][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][5] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][0][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][6] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][0][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][7] & 0x0f ] &  0xf) % 4 ]][3] ];

		state[ pPBox[idx][1][0] & 0x0f ] = (*itmdt[ pPBox[idx][1][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][4] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][1][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][5] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][1][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][6] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][1][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][7] & 0x0f ] &  0xf) % 4 ]][0] ];
		state[ pPBox[idx][1][1] & 0x0f ] = (*itmdt[ pPBox[idx][1][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][4] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][1][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][5] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][1][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][6] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][1][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][7] & 0x0f ] &  0xf) % 4 ]][1] ];
		state[ pPBox[idx][1][2] & 0x0f ] = (*itmdt[ pPBox[idx][1][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][4] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][1][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][5] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][1][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][6] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][1][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][7] & 0x0f ] &  0xf) % 4 ]][2] ];
		state[ pPBox[idx][1][3] & 0x0f ] = (*itmdt[ pPBox[idx][1][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][4] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][1][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][5] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][1][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][6] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][1][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][7] & 0x0f ] &  0xf) % 4 ]][3] ];

		state[ pPBox[idx][2][0] & 0x0f ] = (*itmdt[ pPBox[idx][2][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][4] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][2][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][5] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][2][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][6] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][2][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][7] & 0x0f ] &  0xf) % 4 ]][0] ];
		state[ pPBox[idx][2][1] & 0x0f ] = (*itmdt[ pPBox[idx][2][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][4] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][2][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][5] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][2][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][6] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][2][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][7] & 0x0f ] &  0xf) % 4 ]][1] ];
		state[ pPBox[idx][2][2] & 0x0f ] = (*itmdt[ pPBox[idx][2][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][4] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][2][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][5] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][2][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][6] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][2][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][7] & 0x0f ] &  0xf) % 4 ]][2] ];
		state[ pPBox[idx][2][3] & 0x0f ] = (*itmdt[ pPBox[idx][2][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][4] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][2][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][5] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][2][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][6] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][2][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][7] & 0x0f ] &  0xf) % 4 ]][3] ];

		state[ pPBox[idx][3][0] & 0x0f ] = (*itmdt[ pPBox[idx][3][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][4] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][3][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][5] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][3][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][6] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][3][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][7] & 0x0f ] &  0xf) % 4 ]][0] ];
		state[ pPBox[idx][3][1] & 0x0f ] = (*itmdt[ pPBox[idx][3][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][4] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][3][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][5] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][3][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][6] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][3][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][7] & 0x0f ] &  0xf) % 4 ]][1] ];
		state[ pPBox[idx][3][2] & 0x0f ] = (*itmdt[ pPBox[idx][3][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][4] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][3][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][5] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][3][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][6] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][3][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][7] & 0x0f ] &  0xf) % 4 ]][2] ];
		state[ pPBox[idx][3][3] & 0x0f ] = (*itmdt[ pPBox[idx][3][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][4] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][3][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][5] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][3][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][6] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][3][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][7] & 0x0f ] &  0xf) % 4 ]][3] ];

		rk_xor[ 0] = ((*(pKeyLookup + idx))[0][0] ^ (*(pKeyLookup + idx))[0][4] ^ (*(pKeyLookup + idx))[0][ 8] ^ (*(pKeyLookup + idx))[0][12]) ^ (*(pKeyLookup + (idx - 1)))[0][15];
		rk_xor[ 1] = ((*(pKeyLookup + idx))[1][0] ^ (*(pKeyLookup + idx))[1][4] ^ (*(pKeyLookup + idx))[1][ 8] ^ (*(pKeyLookup + idx))[1][12]) ^ (*(pKeyLookup + (idx - 1)))[1][15];
		rk_xor[ 2] = ((*(pKeyLookup + idx))[2][0] ^ (*(pKeyLookup + idx))[2][4] ^ (*(pKeyLookup + idx))[2][ 8] ^ (*(pKeyLookup + idx))[2][12]) ^ (*(pKeyLookup + (idx - 1)))[2][15];
		rk_xor[ 3] = ((*(pKeyLookup + idx))[3][0] ^ (*(pKeyLookup + idx))[3][4] ^ (*(pKeyLookup + idx))[3][ 8] ^ (*(pKeyLookup + idx))[3][12]) ^ (*(pKeyLookup + (idx - 1)))[3][15];

		rk_xor[ 4] = ((*(pKeyLookup + idx))[0][1] ^ (*(pKeyLookup + idx))[0][5] ^ (*(pKeyLookup + idx))[0][ 9] ^ (*(pKeyLookup + idx))[0][13]) ^ (*(pKeyLookup + (idx - 1)))[0][15];
		rk_xor[ 5] = ((*(pKeyLookup + idx))[1][1] ^ (*(pKeyLookup + idx))[1][5] ^ (*(pKeyLookup + idx))[1][ 9] ^ (*(pKeyLookup + idx))[1][13]) ^ (*(pKeyLookup + (idx - 1)))[1][15];
		rk_xor[ 6] = ((*(pKeyLookup + idx))[2][1] ^ (*(pKeyLookup + idx))[2][5] ^ (*(pKeyLookup + idx))[2][ 9] ^ (*(pKeyLookup + idx))[2][13]) ^ (*(pKeyLookup + (idx - 1)))[2][15];
		rk_xor[ 7] = ((*(pKeyLookup + idx))[3][1] ^ (*(pKeyLookup + idx))[3][5] ^ (*(pKeyLookup + idx))[3][ 9] ^ (*(pKeyLookup + idx))[3][13]) ^ (*(pKeyLookup + (idx - 1)))[3][15];

		rk_xor[ 8] = ((*(pKeyLookup + idx))[0][2] ^ (*(pKeyLookup + idx))[0][6] ^ (*(pKeyLookup + idx))[0][10] ^ (*(pKeyLookup + idx))[0][14]) ^ (*(pKeyLookup + (idx - 1)))[0][15];
		rk_xor[ 9] = ((*(pKeyLookup + idx))[1][2] ^ (*(pKeyLookup + idx))[1][6] ^ (*(pKeyLookup + idx))[1][10] ^ (*(pKeyLookup + idx))[1][14]) ^ (*(pKeyLookup + (idx - 1)))[1][15];
		rk_xor[10] = ((*(pKeyLookup + idx))[2][2] ^ (*(pKeyLookup + idx))[2][6] ^ (*(pKeyLookup + idx))[2][10] ^ (*(pKeyLookup + idx))[2][14]) ^ (*(pKeyLookup + (idx - 1)))[2][15];
		rk_xor[11] = ((*(pKeyLookup + idx))[3][2] ^ (*(pKeyLookup + idx))[3][6] ^ (*(pKeyLookup + idx))[3][10] ^ (*(pKeyLookup + idx))[3][14]) ^ (*(pKeyLookup + (idx - 1)))[3][15];

		rk_xor[12] = ((*(pKeyLookup + idx))[0][3] ^ (*(pKeyLookup + idx))[0][7] ^ (*(pKeyLookup + idx))[0][11] ^ (*(pKeyLookup + idx))[0][16] ^ (*(pKeyLookup + (idx - 1)))[0][15]);
		rk_xor[13] = ((*(pKeyLookup + idx))[1][3] ^ (*(pKeyLookup + idx))[1][7] ^ (*(pKeyLookup + idx))[1][11] ^ (*(pKeyLookup + idx))[1][16] ^ (*(pKeyLookup + (idx - 1)))[1][15]);
		rk_xor[14] = ((*(pKeyLookup + idx))[2][3] ^ (*(pKeyLookup + idx))[2][7] ^ (*(pKeyLookup + idx))[2][11] ^ (*(pKeyLookup + idx))[2][16] ^ (*(pKeyLookup + (idx - 1)))[2][15]);
		rk_xor[15] = ((*(pKeyLookup + idx))[3][3] ^ (*(pKeyLookup + idx))[3][7] ^ (*(pKeyLookup + idx))[3][11] ^ (*(pKeyLookup + idx))[3][16] ^ (*(pKeyLookup + (idx - 1)))[3][15]);

		for(i = 0; i < 4; i++)
		{
			state[ pPBox[idx][i][0] & 0x0f ] ^= rk_xor[ pPBox[idx][i][0] & 0x0f ];
			state[ pPBox[idx][i][1] & 0x0f ] ^= rk_xor[ pPBox[idx][i][1] & 0x0f ];
			state[ pPBox[idx][i][2] & 0x0f ] ^= rk_xor[ pPBox[idx][i][2] & 0x0f ];
			state[ pPBox[idx][i][3] & 0x0f ] ^= rk_xor[ pPBox[idx][i][3] & 0x0f ];
		}

		for(i = 0; i < 16; i++)
		{
			idx_wps[i] = state[i];
		}
	} while(idx < (Nr - 1));

	idx16 = (idx << 4);


	//5. Process final round
	rk_xor[ 0] = ((*(pKeyLookup + Nr))[0][0] ^ (*(pKeyLookup + Nr))[0][4] ^ (*(pKeyLookup + Nr))[0][ 8] ^ (*(pKeyLookup + Nr))[0][12]) ^ (*(pKeyLookup + (Nr - 1)))[0][15];
	rk_xor[ 1] = ((*(pKeyLookup + Nr))[1][0] ^ (*(pKeyLookup + Nr))[1][4] ^ (*(pKeyLookup + Nr))[1][ 8] ^ (*(pKeyLookup + Nr))[1][12]) ^ (*(pKeyLookup + (Nr - 1)))[1][15];
	rk_xor[ 2] = ((*(pKeyLookup + Nr))[2][0] ^ (*(pKeyLookup + Nr))[2][4] ^ (*(pKeyLookup + Nr))[2][ 8] ^ (*(pKeyLookup + Nr))[2][12]) ^ (*(pKeyLookup + (Nr - 1)))[2][15];
	rk_xor[ 3] = ((*(pKeyLookup + Nr))[3][0] ^ (*(pKeyLookup + Nr))[3][4] ^ (*(pKeyLookup + Nr))[3][ 8] ^ (*(pKeyLookup + Nr))[3][12]) ^ (*(pKeyLookup + (Nr - 1)))[3][15];

	rk_xor[ 4] = ((*(pKeyLookup + Nr))[0][1] ^ (*(pKeyLookup + Nr))[0][5] ^ (*(pKeyLookup + Nr))[0][ 9] ^ (*(pKeyLookup + Nr))[0][13]) ^ (*(pKeyLookup + (Nr - 1)))[0][15];
	rk_xor[ 5] = ((*(pKeyLookup + Nr))[1][1] ^ (*(pKeyLookup + Nr))[1][5] ^ (*(pKeyLookup + Nr))[1][ 9] ^ (*(pKeyLookup + Nr))[1][13]) ^ (*(pKeyLookup + (Nr - 1)))[1][15];
	rk_xor[ 6] = ((*(pKeyLookup + Nr))[2][1] ^ (*(pKeyLookup + Nr))[2][5] ^ (*(pKeyLookup + Nr))[2][ 9] ^ (*(pKeyLookup + Nr))[2][13]) ^ (*(pKeyLookup + (Nr - 1)))[2][15];
	rk_xor[ 7] = ((*(pKeyLookup + Nr))[3][1] ^ (*(pKeyLookup + Nr))[3][5] ^ (*(pKeyLookup + Nr))[3][ 9] ^ (*(pKeyLookup + Nr))[3][13]) ^ (*(pKeyLookup + (Nr - 1)))[3][15];

	rk_xor[ 8] = ((*(pKeyLookup + Nr))[0][2] ^ (*(pKeyLookup + Nr))[0][6] ^ (*(pKeyLookup + Nr))[0][10] ^ (*(pKeyLookup + Nr))[0][14]) ^ (*(pKeyLookup + (Nr - 1)))[0][15];
	rk_xor[ 9] = ((*(pKeyLookup + Nr))[1][2] ^ (*(pKeyLookup + Nr))[1][6] ^ (*(pKeyLookup + Nr))[1][10] ^ (*(pKeyLookup + Nr))[1][14]) ^ (*(pKeyLookup + (Nr - 1)))[1][15];
	rk_xor[10] = ((*(pKeyLookup + Nr))[2][2] ^ (*(pKeyLookup + Nr))[2][6] ^ (*(pKeyLookup + Nr))[2][10] ^ (*(pKeyLookup + Nr))[2][14]) ^ (*(pKeyLookup + (Nr - 1)))[2][15];
	rk_xor[11] = ((*(pKeyLookup + Nr))[3][2] ^ (*(pKeyLookup + Nr))[3][6] ^ (*(pKeyLookup + Nr))[3][10] ^ (*(pKeyLookup + Nr))[3][14]) ^ (*(pKeyLookup + (Nr - 1)))[3][15];

	rk_xor[12] = ((*(pKeyLookup + Nr))[0][3] ^ (*(pKeyLookup + Nr))[0][7] ^ (*(pKeyLookup + Nr))[0][11] ^ (*(pKeyLookup + Nr))[0][16] ^ (*(pKeyLookup + (Nr - 1)))[0][15]);
	rk_xor[13] = ((*(pKeyLookup + Nr))[1][3] ^ (*(pKeyLookup + Nr))[1][7] ^ (*(pKeyLookup + Nr))[1][11] ^ (*(pKeyLookup + Nr))[1][16] ^ (*(pKeyLookup + (Nr - 1)))[1][15]);
	rk_xor[14] = ((*(pKeyLookup + Nr))[2][3] ^ (*(pKeyLookup + Nr))[2][7] ^ (*(pKeyLookup + Nr))[2][11] ^ (*(pKeyLookup + Nr))[2][16] ^ (*(pKeyLookup + (Nr - 1)))[2][15]);
	rk_xor[15] = ((*(pKeyLookup + Nr))[3][3] ^ (*(pKeyLookup + Nr))[3][7] ^ (*(pKeyLookup + Nr))[3][11] ^ (*(pKeyLookup + Nr))[3][16] ^ (*(pKeyLookup + (Nr - 1)))[3][15]);

	//make output
	out[pPBox[Nr][0][0] & 0x0f] = pTBox[ idx16 +  0 ][ state[ 0] >> 4 ][ state[ 0] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[ 0] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][0][0] & 0x0f ];
	out[pPBox[Nr][0][1] & 0x0f] = pTBox[ idx16 +  1 ][ state[ 1] >> 4 ][ state[ 1] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[ 1] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][0][1] & 0x0f ];
	out[pPBox[Nr][0][2] & 0x0f] = pTBox[ idx16 +  2 ][ state[ 2] >> 4 ][ state[ 2] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[ 2] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][0][2] & 0x0f ];
	out[pPBox[Nr][0][3] & 0x0f] = pTBox[ idx16 +  3 ][ state[ 3] >> 4 ][ state[ 3] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[ 3] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][0][3] & 0x0f ];
	out[pPBox[Nr][0][4] & 0x0f] = pTBox[ idx16 +  4 ][ state[ 4] >> 4 ][ state[ 4] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[ 4] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][0][4] & 0x0f ];
	out[pPBox[Nr][0][5] & 0x0f] = pTBox[ idx16 +  5 ][ state[ 5] >> 4 ][ state[ 5] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[ 5] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][0][5] & 0x0f ];
	out[pPBox[Nr][0][6] & 0x0f] = pTBox[ idx16 +  6 ][ state[ 6] >> 4 ][ state[ 6] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[ 6] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][0][6] & 0x0f ];
	out[pPBox[Nr][0][7] & 0x0f] = pTBox[ idx16 +  7 ][ state[ 7] >> 4 ][ state[ 7] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[ 7] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][0][7] & 0x0f ];
	out[pPBox[Nr][1][0] & 0x0f] = pTBox[ idx16 +  8 ][ state[ 8] >> 4 ][ state[ 8] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[ 8] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][1][0] & 0x0f ];
	out[pPBox[Nr][1][1] & 0x0f] = pTBox[ idx16 +  9 ][ state[ 9] >> 4 ][ state[ 9] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[ 9] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][1][1] & 0x0f ];
	out[pPBox[Nr][1][2] & 0x0f] = pTBox[ idx16 + 10 ][ state[10] >> 4 ][ state[10] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[10] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][1][2] & 0x0f ];
	out[pPBox[Nr][1][3] & 0x0f] = pTBox[ idx16 + 11 ][ state[11] >> 4 ][ state[11] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[11] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][1][3] & 0x0f ];
	out[pPBox[Nr][1][4] & 0x0f] = pTBox[ idx16 + 12 ][ state[12] >> 4 ][ state[12] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[12] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][1][4] & 0x0f ];
	out[pPBox[Nr][1][5] & 0x0f] = pTBox[ idx16 + 13 ][ state[13] >> 4 ][ state[13] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[13] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][1][5] & 0x0f ];
	out[pPBox[Nr][1][6] & 0x0f] = pTBox[ idx16 + 14 ][ state[14] >> 4 ][ state[14] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[14] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][1][6] & 0x0f ];
	out[pPBox[Nr][1][7] & 0x0f] = pTBox[ idx16 + 15 ][ state[15] >> 4 ][ state[15] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[15] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][1][7] & 0x0f ];
}


/**
 * @var static const SDWAP_SBOX inv_s_box
 * @brief inverse of S-box defined int FIPS-197
 */
SPC_INTERNAL SDWAP_SBOX sdwap_inv_s_box_ = 
{
	{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
	{0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
	{0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
	{0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
	{0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
	{0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
	{0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
	{0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
	{0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
	{0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
	{0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
	{0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
	{0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
	{0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
	{0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
	{0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
};

static const unsigned char sdwap_inv_sr_matrix_[16] =
	{0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};


/*
 * @fn		static void SDWAP_Decryption(SDWAP_TBOX *pTBox, SDWAP_KEY_LOOKUP *pKeyLookup, SDWAP_PBOX *pPBox, SDWAP_WORD_PBOX* pWPBox, SDWAP_BIT_PBOX* pBPBox, unsigned int Nr, unsigned char* in, unsigned char* out, unsigned int isLittleEndian)
 * @brief	SDWAP Decryption function.
 *
 * @param	[in] pTBox			T-Box
 * @param	[in] pkeyLookup		Round-key lookup table
 * @param	[in] pPBox			P-Box
 * @param	[in] pWPBox			word(4byte) permutation box
 * @param	[in] pBPBox			bit permutation box
 * @param	[in] Nr				number of rounds
 * @param	[in] in				input bytes(16-byte length)
 * @param	[out] out			output bytes(16-byte length)
 * @param	[in] isLittleEndian	flag for little endian
 * @return	void
 */
static void SDWAP_Decryption(SDWAP_TBOX *pTBox, SDWAP_KEY_LOOKUP *pKeyLookup, SDWAP_PBOX *pPBox, SDWAP_WORD_PBOX* pWPBox, SDWAP_BIT_PBOX* pBPBox, unsigned int Nr, unsigned char* in, unsigned char* out, unsigned int isLittleEndian)
{
	unsigned int i;
	unsigned int idx = 0;
	unsigned int idx16;
	unsigned char temp;
	unsigned char idx_wps[16];
	unsigned char state[16];	//state
	unsigned char rk_xor[16];
	SDWAP_WORD* itmdt[16];		//intermediate value


	//3. Process initial permutation
	idx_wps[(pPBox[0][0][0]) & 0x0f] = state[(pPBox[0][0][0]) & 0x0f] = in[ 0] ^ ((*(pKeyLookup + Nr))[0][0] ^ (*(pKeyLookup + Nr))[0][4] ^ (*(pKeyLookup + Nr))[0][ 8] ^ (*(pKeyLookup + Nr))[0][12]) ^ (*(pKeyLookup + (Nr - 1)))[0][15];
	idx_wps[(pPBox[0][0][1]) & 0x0f] = state[(pPBox[0][0][1]) & 0x0f] = in[ 1] ^ ((*(pKeyLookup + Nr))[1][0] ^ (*(pKeyLookup + Nr))[1][4] ^ (*(pKeyLookup + Nr))[1][ 8] ^ (*(pKeyLookup + Nr))[1][12]) ^ (*(pKeyLookup + (Nr - 1)))[1][15];
	idx_wps[(pPBox[0][0][2]) & 0x0f] = state[(pPBox[0][0][2]) & 0x0f] = in[ 2] ^ ((*(pKeyLookup + Nr))[2][0] ^ (*(pKeyLookup + Nr))[2][4] ^ (*(pKeyLookup + Nr))[2][ 8] ^ (*(pKeyLookup + Nr))[2][12]) ^ (*(pKeyLookup + (Nr - 1)))[2][15];
	idx_wps[(pPBox[0][0][3]) & 0x0f] = state[(pPBox[0][0][3]) & 0x0f] = in[ 3] ^ ((*(pKeyLookup + Nr))[3][0] ^ (*(pKeyLookup + Nr))[3][4] ^ (*(pKeyLookup + Nr))[3][ 8] ^ (*(pKeyLookup + Nr))[3][12]) ^ (*(pKeyLookup + (Nr - 1)))[3][15];
	idx_wps[(pPBox[0][0][4]) & 0x0f] = state[(pPBox[0][0][4]) & 0x0f] = in[ 4] ^ ((*(pKeyLookup + Nr))[0][1] ^ (*(pKeyLookup + Nr))[0][5] ^ (*(pKeyLookup + Nr))[0][ 9] ^ (*(pKeyLookup + Nr))[0][13]) ^ (*(pKeyLookup + (Nr - 1)))[0][15];
	idx_wps[(pPBox[0][0][5]) & 0x0f] = state[(pPBox[0][0][5]) & 0x0f] = in[ 5] ^ ((*(pKeyLookup + Nr))[1][1] ^ (*(pKeyLookup + Nr))[1][5] ^ (*(pKeyLookup + Nr))[1][ 9] ^ (*(pKeyLookup + Nr))[1][13]) ^ (*(pKeyLookup + (Nr - 1)))[1][15];
	idx_wps[(pPBox[0][0][6]) & 0x0f] = state[(pPBox[0][0][6]) & 0x0f] = in[ 6] ^ ((*(pKeyLookup + Nr))[2][1] ^ (*(pKeyLookup + Nr))[2][5] ^ (*(pKeyLookup + Nr))[2][ 9] ^ (*(pKeyLookup + Nr))[2][13]) ^ (*(pKeyLookup + (Nr - 1)))[2][15];
	idx_wps[(pPBox[0][0][7]) & 0x0f] = state[(pPBox[0][0][7]) & 0x0f] = in[ 7] ^ ((*(pKeyLookup + Nr))[3][1] ^ (*(pKeyLookup + Nr))[3][5] ^ (*(pKeyLookup + Nr))[3][ 9] ^ (*(pKeyLookup + Nr))[3][13]) ^ (*(pKeyLookup + (Nr - 1)))[3][15];
	idx_wps[(pPBox[0][1][0]) & 0x0f] = state[(pPBox[0][1][0]) & 0x0f] = in[ 8] ^ ((*(pKeyLookup + Nr))[0][2] ^ (*(pKeyLookup + Nr))[0][6] ^ (*(pKeyLookup + Nr))[0][10] ^ (*(pKeyLookup + Nr))[0][14]) ^ (*(pKeyLookup + (Nr - 1)))[0][15];
	idx_wps[(pPBox[0][1][1]) & 0x0f] = state[(pPBox[0][1][1]) & 0x0f] = in[ 9] ^ ((*(pKeyLookup + Nr))[1][2] ^ (*(pKeyLookup + Nr))[1][6] ^ (*(pKeyLookup + Nr))[1][10] ^ (*(pKeyLookup + Nr))[1][14]) ^ (*(pKeyLookup + (Nr - 1)))[1][15];
	idx_wps[(pPBox[0][1][2]) & 0x0f] = state[(pPBox[0][1][2]) & 0x0f] = in[10] ^ ((*(pKeyLookup + Nr))[2][2] ^ (*(pKeyLookup + Nr))[2][6] ^ (*(pKeyLookup + Nr))[2][10] ^ (*(pKeyLookup + Nr))[2][14]) ^ (*(pKeyLookup + (Nr - 1)))[2][15];
	idx_wps[(pPBox[0][1][3]) & 0x0f] = state[(pPBox[0][1][3]) & 0x0f] = in[11] ^ ((*(pKeyLookup + Nr))[3][2] ^ (*(pKeyLookup + Nr))[3][6] ^ (*(pKeyLookup + Nr))[3][10] ^ (*(pKeyLookup + Nr))[3][14]) ^ (*(pKeyLookup + (Nr - 1)))[3][15];
	idx_wps[(pPBox[0][1][4]) & 0x0f] = state[(pPBox[0][1][4]) & 0x0f] = in[12] ^ ((*(pKeyLookup + Nr))[0][3] ^ (*(pKeyLookup + Nr))[0][7] ^ (*(pKeyLookup + Nr))[0][11] ^ (*(pKeyLookup + Nr))[0][16] ^ (*(pKeyLookup + (Nr - 1)))[0][15]);
	idx_wps[(pPBox[0][1][5]) & 0x0f] = state[(pPBox[0][1][5]) & 0x0f] = in[13] ^ ((*(pKeyLookup + Nr))[1][3] ^ (*(pKeyLookup + Nr))[1][7] ^ (*(pKeyLookup + Nr))[1][11] ^ (*(pKeyLookup + Nr))[1][16] ^ (*(pKeyLookup + (Nr - 1)))[1][15]);
	idx_wps[(pPBox[0][1][6]) & 0x0f] = state[(pPBox[0][1][6]) & 0x0f] = in[14] ^ ((*(pKeyLookup + Nr))[2][3] ^ (*(pKeyLookup + Nr))[2][7] ^ (*(pKeyLookup + Nr))[2][11] ^ (*(pKeyLookup + Nr))[2][16] ^ (*(pKeyLookup + (Nr - 1)))[2][15]);
	idx_wps[(pPBox[0][1][7]) & 0x0f] = state[(pPBox[0][1][7]) & 0x0f] = in[15] ^ ((*(pKeyLookup + Nr))[3][3] ^ (*(pKeyLookup + Nr))[3][7] ^ (*(pKeyLookup + Nr))[3][11] ^ (*(pKeyLookup + Nr))[3][16] ^ (*(pKeyLookup + (Nr - 1)))[3][15]);

	//4. Process each rounds
	do
	{
		idx16 = (idx << 4);

		idx++;

		//calc round key
		rk_xor[ 0] = ((*(pKeyLookup + (Nr - idx)))[0][0] ^ (*(pKeyLookup + (Nr - idx)))[0][4] ^ (*(pKeyLookup + (Nr - idx)))[0][ 8] ^ (*(pKeyLookup + (Nr - idx)))[0][12]) ^ (*(pKeyLookup + ((Nr - idx) - 1)))[0][15];
		rk_xor[ 1] = ((*(pKeyLookup + (Nr - idx)))[1][0] ^ (*(pKeyLookup + (Nr - idx)))[1][4] ^ (*(pKeyLookup + (Nr - idx)))[1][ 8] ^ (*(pKeyLookup + (Nr - idx)))[1][12]) ^ (*(pKeyLookup + ((Nr - idx) - 1)))[1][15];
		rk_xor[ 2] = ((*(pKeyLookup + (Nr - idx)))[2][0] ^ (*(pKeyLookup + (Nr - idx)))[2][4] ^ (*(pKeyLookup + (Nr - idx)))[2][ 8] ^ (*(pKeyLookup + (Nr - idx)))[2][12]) ^ (*(pKeyLookup + ((Nr - idx) - 1)))[2][15];
		rk_xor[ 3] = ((*(pKeyLookup + (Nr - idx)))[3][0] ^ (*(pKeyLookup + (Nr - idx)))[3][4] ^ (*(pKeyLookup + (Nr - idx)))[3][ 8] ^ (*(pKeyLookup + (Nr - idx)))[3][12]) ^ (*(pKeyLookup + ((Nr - idx) - 1)))[3][15];
		rk_xor[ 4] = ((*(pKeyLookup + (Nr - idx)))[0][1] ^ (*(pKeyLookup + (Nr - idx)))[0][5] ^ (*(pKeyLookup + (Nr - idx)))[0][ 9] ^ (*(pKeyLookup + (Nr - idx)))[0][13]) ^ (*(pKeyLookup + ((Nr - idx) - 1)))[0][15];
		rk_xor[ 5] = ((*(pKeyLookup + (Nr - idx)))[1][1] ^ (*(pKeyLookup + (Nr - idx)))[1][5] ^ (*(pKeyLookup + (Nr - idx)))[1][ 9] ^ (*(pKeyLookup + (Nr - idx)))[1][13]) ^ (*(pKeyLookup + ((Nr - idx) - 1)))[1][15];
		rk_xor[ 6] = ((*(pKeyLookup + (Nr - idx)))[2][1] ^ (*(pKeyLookup + (Nr - idx)))[2][5] ^ (*(pKeyLookup + (Nr - idx)))[2][ 9] ^ (*(pKeyLookup + (Nr - idx)))[2][13]) ^ (*(pKeyLookup + ((Nr - idx) - 1)))[2][15];
		rk_xor[ 7] = ((*(pKeyLookup + (Nr - idx)))[3][1] ^ (*(pKeyLookup + (Nr - idx)))[3][5] ^ (*(pKeyLookup + (Nr - idx)))[3][ 9] ^ (*(pKeyLookup + (Nr - idx)))[3][13]) ^ (*(pKeyLookup + ((Nr - idx) - 1)))[3][15];
		rk_xor[ 8] = ((*(pKeyLookup + (Nr - idx)))[0][2] ^ (*(pKeyLookup + (Nr - idx)))[0][6] ^ (*(pKeyLookup + (Nr - idx)))[0][10] ^ (*(pKeyLookup + (Nr - idx)))[0][14]) ^ (*(pKeyLookup + ((Nr - idx) - 1)))[0][15];
		rk_xor[ 9] = ((*(pKeyLookup + (Nr - idx)))[1][2] ^ (*(pKeyLookup + (Nr - idx)))[1][6] ^ (*(pKeyLookup + (Nr - idx)))[1][10] ^ (*(pKeyLookup + (Nr - idx)))[1][14]) ^ (*(pKeyLookup + ((Nr - idx) - 1)))[1][15];
		rk_xor[10] = ((*(pKeyLookup + (Nr - idx)))[2][2] ^ (*(pKeyLookup + (Nr - idx)))[2][6] ^ (*(pKeyLookup + (Nr - idx)))[2][10] ^ (*(pKeyLookup + (Nr - idx)))[2][14]) ^ (*(pKeyLookup + ((Nr - idx) - 1)))[2][15];
		rk_xor[11] = ((*(pKeyLookup + (Nr - idx)))[3][2] ^ (*(pKeyLookup + (Nr - idx)))[3][6] ^ (*(pKeyLookup + (Nr - idx)))[3][10] ^ (*(pKeyLookup + (Nr - idx)))[3][14]) ^ (*(pKeyLookup + ((Nr - idx) - 1)))[3][15];
		rk_xor[12] = ((*(pKeyLookup + (Nr - idx)))[0][3] ^ (*(pKeyLookup + (Nr - idx)))[0][7] ^ (*(pKeyLookup + (Nr - idx)))[0][11] ^ (*(pKeyLookup + (Nr - idx)))[0][16] ^ (*(pKeyLookup + ((Nr - idx) - 1)))[0][15]);
		rk_xor[13] = ((*(pKeyLookup + (Nr - idx)))[1][3] ^ (*(pKeyLookup + (Nr - idx)))[1][7] ^ (*(pKeyLookup + (Nr - idx)))[1][11] ^ (*(pKeyLookup + (Nr - idx)))[1][16] ^ (*(pKeyLookup + ((Nr - idx) - 1)))[1][15]);
		rk_xor[14] = ((*(pKeyLookup + (Nr - idx)))[2][3] ^ (*(pKeyLookup + (Nr - idx)))[2][7] ^ (*(pKeyLookup + (Nr - idx)))[2][11] ^ (*(pKeyLookup + (Nr - idx)))[2][16] ^ (*(pKeyLookup + ((Nr - idx) - 1)))[2][15]);
		rk_xor[15] = ((*(pKeyLookup + (Nr - idx)))[3][3] ^ (*(pKeyLookup + (Nr - idx)))[3][7] ^ (*(pKeyLookup + (Nr - idx)))[3][11] ^ (*(pKeyLookup + (Nr - idx)))[3][16] ^ (*(pKeyLookup + ((Nr - idx) - 1)))[3][15]);

		if(idx <= 1)
		{
			for (i = 0; i < 16; i++)
			{
				temp = sdwap_inv_s_box_[state[i] >> 4][state[i] & 0xf] ^ rk_xor[sdwap_inv_sr_matrix_[i]];
				itmdt[i] = (SDWAP_WORD*)pTBox[idx16 + i][temp >> 4][temp &  0xf];
			}
		}
		else
		{
			for (i = 0; i < 16; i++)
			{
				temp = sdwap_inv_s_box_[state[i] >> 4][state[i] & 0xf] ^ rk_xor[i];
				itmdt[i] = (SDWAP_WORD*)pTBox[idx16 + i][temp >> 4][temp &  0xf];
			}
		}

		state[ pPBox[idx][0][0] & 0x0f ] = (*itmdt[ pPBox[idx][0][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][4] & 0x0f ] &  0xf) % 4 ]][0] ]
					   					 ^ (*itmdt[ pPBox[idx][0][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][5] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][0][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][6] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][0][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][7] & 0x0f ] &  0xf) % 4 ]][0] ];
		state[ pPBox[idx][0][1] & 0x0f ] = (*itmdt[ pPBox[idx][0][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][4] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][0][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][5] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][0][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][6] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][0][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][7] & 0x0f ] &  0xf) % 4 ]][1] ];
		state[ pPBox[idx][0][2] & 0x0f ] = (*itmdt[ pPBox[idx][0][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][4] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][0][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][5] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][0][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][6] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][0][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][7] & 0x0f ] &  0xf) % 4 ]][2] ];
		state[ pPBox[idx][0][3] & 0x0f ] = (*itmdt[ pPBox[idx][0][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][4] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][0][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][5] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][0][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][6] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][0][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][0][7] & 0x0f ] &  0xf) % 4 ]][3] ];

		state[ pPBox[idx][1][0] & 0x0f ] = (*itmdt[ pPBox[idx][1][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][4] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][1][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][5] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][1][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][6] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][1][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][7] & 0x0f ] &  0xf) % 4 ]][0] ];
		state[ pPBox[idx][1][1] & 0x0f ] = (*itmdt[ pPBox[idx][1][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][4] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][1][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][5] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][1][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][6] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][1][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][7] & 0x0f ] &  0xf) % 4 ]][1] ];
		state[ pPBox[idx][1][2] & 0x0f ] = (*itmdt[ pPBox[idx][1][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][4] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][1][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][5] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][1][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][6] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][1][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][7] & 0x0f ] &  0xf) % 4 ]][2] ];
		state[ pPBox[idx][1][3] & 0x0f ] = (*itmdt[ pPBox[idx][1][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][4] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][1][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][5] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][1][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][6] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][1][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][1][7] & 0x0f ] &  0xf) % 4 ]][3] ];

		state[ pPBox[idx][2][0] & 0x0f ] = (*itmdt[ pPBox[idx][2][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][4] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][2][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][5] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][2][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][6] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][2][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][7] & 0x0f ] &  0xf) % 4 ]][0] ];
		state[ pPBox[idx][2][1] & 0x0f ] = (*itmdt[ pPBox[idx][2][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][4] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][2][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][5] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][2][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][6] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][2][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][7] & 0x0f ] &  0xf) % 4 ]][1] ];
		state[ pPBox[idx][2][2] & 0x0f ] = (*itmdt[ pPBox[idx][2][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][4] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][2][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][5] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][2][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][6] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][2][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][7] & 0x0f ] &  0xf) % 4 ]][2] ];
		state[ pPBox[idx][2][3] & 0x0f ] = (*itmdt[ pPBox[idx][2][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][4] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][2][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][5] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][2][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][6] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][2][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][2][7] & 0x0f ] &  0xf) % 4 ]][3] ];

		state[ pPBox[idx][3][0] & 0x0f ] = (*itmdt[ pPBox[idx][3][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][4] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][3][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][5] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][3][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][6] & 0x0f ] &  0xf) % 4 ]][0] ]
										 ^ (*itmdt[ pPBox[idx][3][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][7] & 0x0f ] &  0xf) % 4 ]][0] ];
		state[ pPBox[idx][3][1] & 0x0f ] = (*itmdt[ pPBox[idx][3][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][4] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][3][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][5] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][3][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][6] & 0x0f ] &  0xf) % 4 ]][1] ]
										 ^ (*itmdt[ pPBox[idx][3][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][7] & 0x0f ] &  0xf) % 4 ]][1] ];
		state[ pPBox[idx][3][2] & 0x0f ] = (*itmdt[ pPBox[idx][3][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][4] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][3][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][5] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][3][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][6] & 0x0f ] &  0xf) % 4 ]][2] ]
										 ^ (*itmdt[ pPBox[idx][3][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][7] & 0x0f ] &  0xf) % 4 ]][2] ];
		state[ pPBox[idx][3][3] & 0x0f ] = (*itmdt[ pPBox[idx][3][4] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][4] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][3][5] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][5] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][3][6] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][6] & 0x0f ] &  0xf) % 4 ]][3] ]
										 ^ (*itmdt[ pPBox[idx][3][7] & 0x0f ])[ byte_pMatrix[(*pWPBox)[idx - 1][ (idx_wps[ pPBox[idx][3][7] & 0x0f ] &  0xf) % 4 ]][3] ];

		for(i = 0; i < 16; i++)
		{
			idx_wps[i] = state[i];
		}

	} while(idx < (Nr - 1));

	idx16 = (idx << 4);

	//5. Process final round
	rk_xor[ 0] = (*pKeyLookup)[0][0] ^ (*pKeyLookup)[0][4] ^ (*pKeyLookup)[0][ 8];
	rk_xor[ 1] = (*pKeyLookup)[1][0] ^ (*pKeyLookup)[1][4] ^ (*pKeyLookup)[1][ 8];
	rk_xor[ 2] = (*pKeyLookup)[2][0] ^ (*pKeyLookup)[2][4] ^ (*pKeyLookup)[2][ 8];
	rk_xor[ 3] = (*pKeyLookup)[3][0] ^ (*pKeyLookup)[3][4] ^ (*pKeyLookup)[3][ 8];
	rk_xor[ 4] = (*pKeyLookup)[0][1] ^ (*pKeyLookup)[0][5] ^ (*pKeyLookup)[0][ 9];
	rk_xor[ 5] = (*pKeyLookup)[1][1] ^ (*pKeyLookup)[1][5] ^ (*pKeyLookup)[1][ 9];
	rk_xor[ 6] = (*pKeyLookup)[2][1] ^ (*pKeyLookup)[2][5] ^ (*pKeyLookup)[2][ 9];
	rk_xor[ 7] = (*pKeyLookup)[3][1] ^ (*pKeyLookup)[3][5] ^ (*pKeyLookup)[3][ 9];
	rk_xor[ 8] = (*pKeyLookup)[0][2] ^ (*pKeyLookup)[0][6] ^ (*pKeyLookup)[0][10];
	rk_xor[ 9] = (*pKeyLookup)[1][2] ^ (*pKeyLookup)[1][6] ^ (*pKeyLookup)[1][10];
	rk_xor[10] = (*pKeyLookup)[2][2] ^ (*pKeyLookup)[2][6] ^ (*pKeyLookup)[2][10];
	rk_xor[11] = (*pKeyLookup)[3][2] ^ (*pKeyLookup)[3][6] ^ (*pKeyLookup)[3][10];
	rk_xor[12] = (*pKeyLookup)[0][3] ^ (*pKeyLookup)[0][7] ^ (*pKeyLookup)[0][11];
	rk_xor[13] = (*pKeyLookup)[1][3] ^ (*pKeyLookup)[1][7] ^ (*pKeyLookup)[1][11];
	rk_xor[14] = (*pKeyLookup)[2][3] ^ (*pKeyLookup)[2][7] ^ (*pKeyLookup)[2][11];
	rk_xor[15] = (*pKeyLookup)[3][3] ^ (*pKeyLookup)[3][7] ^ (*pKeyLookup)[3][11];


	//make output
	out[pPBox[Nr][0][0] & 0x0f] = pTBox[ idx16 +  0 ][ state[ 0] >> 4 ][ state[ 0] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[ 0] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][0][0] & 0x0f ];
	out[pPBox[Nr][0][1] & 0x0f] = pTBox[ idx16 +  1 ][ state[ 1] >> 4 ][ state[ 1] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[ 1] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][0][1] & 0x0f ];
	out[pPBox[Nr][0][2] & 0x0f] = pTBox[ idx16 +  2 ][ state[ 2] >> 4 ][ state[ 2] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[ 2] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][0][2] & 0x0f ];
	out[pPBox[Nr][0][3] & 0x0f] = pTBox[ idx16 +  3 ][ state[ 3] >> 4 ][ state[ 3] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[ 3] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][0][3] & 0x0f ];
	out[pPBox[Nr][0][4] & 0x0f] = pTBox[ idx16 +  4 ][ state[ 4] >> 4 ][ state[ 4] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[ 4] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][0][4] & 0x0f ];
	out[pPBox[Nr][0][5] & 0x0f] = pTBox[ idx16 +  5 ][ state[ 5] >> 4 ][ state[ 5] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[ 5] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][0][5] & 0x0f ];
	out[pPBox[Nr][0][6] & 0x0f] = pTBox[ idx16 +  6 ][ state[ 6] >> 4 ][ state[ 6] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[ 6] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][0][6] & 0x0f ];
	out[pPBox[Nr][0][7] & 0x0f] = pTBox[ idx16 +  7 ][ state[ 7] >> 4 ][ state[ 7] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[ 7] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][0][7] & 0x0f ];
	out[pPBox[Nr][1][0] & 0x0f] = pTBox[ idx16 +  8 ][ state[ 8] >> 4 ][ state[ 8] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[ 8] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][1][0] & 0x0f ];
	out[pPBox[Nr][1][1] & 0x0f] = pTBox[ idx16 +  9 ][ state[ 9] >> 4 ][ state[ 9] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[ 9] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][1][1] & 0x0f ];
	out[pPBox[Nr][1][2] & 0x0f] = pTBox[ idx16 + 10 ][ state[10] >> 4 ][ state[10] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[10] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][1][2] & 0x0f ];
	out[pPBox[Nr][1][3] & 0x0f] = pTBox[ idx16 + 11 ][ state[11] >> 4 ][ state[11] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[11] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][1][3] & 0x0f ];
	out[pPBox[Nr][1][4] & 0x0f] = pTBox[ idx16 + 12 ][ state[12] >> 4 ][ state[12] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[12] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][1][4] & 0x0f ];
	out[pPBox[Nr][1][5] & 0x0f] = pTBox[ idx16 + 13 ][ state[13] >> 4 ][ state[13] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[13] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][1][5] & 0x0f ];
	out[pPBox[Nr][1][6] & 0x0f] = pTBox[ idx16 + 14 ][ state[14] >> 4 ][ state[14] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[14] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][1][6] & 0x0f ];
	out[pPBox[Nr][1][7] & 0x0f] = pTBox[ idx16 + 15 ][ state[15] >> 4 ][ state[15] & 0x0f ][ byte_pMatrix[(*pWPBox)[idx][(state[15] & 0x0f) % 4]][0] ] ^ rk_xor[ pPBox[Nr][1][7] & 0x0f ];

	return;
}



/**
 * @fn		SDWAP_RETURN_VAL SDWAP_Process(unsigned char *Table, unsigned int TableLen, unsigned char* in, unsigned char* out, unsigned int OptimizLev)
 * @brief	processing encryption or decryption according to the table
 *
 * @param	[in] Table		look-up table for SDWAP
 * @param	[in] TableLen	byte-length of look-up table
 * @param	[in] in			input bytes(16-byte length)
 * @param	[out] out		output bytes(16-byte length)
 * @return	SDWAP_RETURN_VAL
 */
SPC_INTERNAL SDWAP_RETURN_VAL SDWAP_Process(unsigned char *Table, unsigned int TableLen, unsigned char* in, unsigned char* out, unsigned int isEncryption)
{
	unsigned int Nr;
	unsigned int Nk;
	unsigned int TBoxSize;
	unsigned int PBoxSize;
	unsigned int WPBoxSize;
	unsigned int BPBoxSize;

	SDWAP_TBOX *pTBox = NULL;
	SDWAP_PBOX *pPBox = NULL;
	SDWAP_WORD_PBOX *pWPBox = NULL;
	SDWAP_BIT_PBOX *pBPBox = NULL;
	SDWAP_KEY_LOOKUP *pKeyLookup = NULL;

	unsigned char isLittleEndian;

	{
		//get little endian flag
		unsigned int EndianTestVector = 1;
		isLittleEndian = *(unsigned char*)(&EndianTestVector);
	}

	//1. Parameter checking
	if ((Table == NULL) || (in == NULL) || (out == NULL))
	{
		return SDWAP_RETURN_INVALID_PARAMETER;				//invalid parameter
	}

	//2. Get Nr(Number of Rounds)
	switch(TableLen)
	{
		case (SDWAP_T_TABLE_ROUND_SIZE * SDWAP_128_ROUNDS) + (SDWAP_P_TABLE_ROUND_SIZE * (SDWAP_128_ROUNDS + 1)):
			//AES128
			Nr = SDWAP_128_ROUNDS;
			Nk = 16 / SDWAP_WORD_SIZE;
			break;
		case (SDWAP_T_TABLE_ROUND_SIZE * SDWAP_192_ROUNDS) + (SDWAP_P_TABLE_ROUND_SIZE * (SDWAP_192_ROUNDS + 1)):
			//AES192
			Nr = SDWAP_192_ROUNDS;
			Nk = 24 / SDWAP_WORD_SIZE;
			break;
		case (SDWAP_T_TABLE_ROUND_SIZE * SDWAP_256_ROUNDS) + (SDWAP_P_TABLE_ROUND_SIZE * (SDWAP_256_ROUNDS + 1)):
			//AES256
			Nr = SDWAP_256_ROUNDS;
			Nk = 32 / SDWAP_WORD_SIZE;
			break;
		default :
			return SDWAP_RETURN_INVALID_TBLSIZE;				//invalid parameter
	}

	//Get pointer of P-Box
	pTBox = (SDWAP_TBOX*)Table;
	TBoxSize = SDWAP_T_TABLE_ROUND_SIZE * Nr;

	pPBox = (SDWAP_PBOX*)((unsigned char*)pTBox + TBoxSize);
	PBoxSize = SDWAP_P_TABLE_ROUND_SIZE * (Nr + 1);
	WPBoxSize = SDWAP_WP_TABLE_ROUND_SIZE * (Nr);
	BPBoxSize = SDWAP_BP_TABLE_ROUND_SIZE * Nr;

	pWPBox = (SDWAP_WORD_PBOX*)(((unsigned char*)pTBox) + TBoxSize + PBoxSize);
	pBPBox = (SDWAP_BIT_PBOX*)(((unsigned char*)pTBox) + TBoxSize + PBoxSize + WPBoxSize);
	pKeyLookup = (SDWAP_KEY_LOOKUP*)((unsigned char*)pTBox + TBoxSize + PBoxSize + WPBoxSize + BPBoxSize);

	if(isEncryption)
	{
		SDWAP_Encryption(pTBox, pKeyLookup, pPBox, pWPBox, pBPBox, Nr, in, out, isLittleEndian);
	}
	else
	{
		SDWAP_Decryption(pTBox, pKeyLookup, pPBox, pWPBox, pBPBox, Nr, in, out, isLittleEndian);
	}

	return SDWAP_RETURN_SUCCESS;
}

////////////////////////// End of File //////////////////////////
