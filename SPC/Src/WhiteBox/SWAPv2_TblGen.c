/**
 * @file	SWAPv2_TblGen.c
 * @brief	white box AES table generation module for SSA(Samsung Security Architecture)
 * @author	Samsung WhiteBox AES Version 2 (SWAPv1 based)
 *				- Chul Lee(chuls.lee@samsung.com)
 *				- Dept : Software R&D Center / Cloud Computing Lab.
 *
 *			Samsung WhiteBox AES Version 1
 *				 - Jisoon Park(js00n.park@samsung.com)
 *				 - Dept: DMC R&D Center/Convergence Software Lab.
 *			
 *
 * @see		SWAPv2
 * @date	2012-10-05
 * @version	2.0
 * @par		Copyright:
 * Copyright 2012 by Samsung Electronics, Inc.,
 * This software is the confiedential and properietary information 
 * of Samsung Elctronics, Inc. ("Confidential Information"). You 
 * shall not disclose such Confidential Information and shall use 
 * it only in accordance with the term of the lice agreement 
 * you entered into with Samsung.
 * @par		Warning:
 * This code sould not be exported out of Samsung Electronics.
 * This code cannot be inserted in any customer device.
 * The logic of whitebox table generation is confidential.
 */

////////////////////////////////////////////////////////////////////////////
// including header files
////////////////////////////////////////////////////////////////////////////
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include "SWAPv2_defines.h"
#include "SWAPv2_TblGen.h"

////////////////////////////////////////////////////////////////////////////
// static type definitions
////////////////////////////////////////////////////////////////////////////
/*! Table generation types */
typedef enum _SWAPv2_TABLE_TYPE
{
	SWAPv2_TABLE_TYPE_ENCRYPTION = 0,		/*!< Table for encryption */
	SWAPv2_TABLE_TYPE_DECRYPTION = 1		/*!< Table for decryption */
} SWAPv2_TABLE_TYPE;

////////////////////////////////////////////////////////////////////////////
// static global variables
////////////////////////////////////////////////////////////////////////////
/**
 * @var static const SWAPv2_SBOX s_box
 * @brief S-box value defined int FIPS-197
 */
SWAPv2_SBOX s_box = 
{
	{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
	{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
	{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
	{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
	{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
	{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
	{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
	{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
	{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
	{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
	{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
	{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
	{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
	{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
	{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
	{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
};

/**
 * @var static const SWAPv2_SBOX inv_s_box
 * @brief inverse of S-box defined int FIPS-197
 */
SWAPv2_SBOX inv_s_box = 
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

SWAPv2_SBOX* pSBox;
SWAPv2_SBOX* pInvSBox;

/**
 * @var static const unsigned char sr_matrix[16]
 * @brief look-up matrix for ShiftRows
 */
static const unsigned char sr_matrix[16] =
	{0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3};

/**
 * @var static const unsigned char inv_sr_matrix[16]
 * @brief look-up matrix for InvShiftRows, inverse of sr_matrix
 */
static const unsigned char inv_sr_matrix[16] =
	{0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};



////////////////////////////////////////////////////////////////////////////
// function implementations
////////////////////////////////////////////////////////////////////////////
/**
 * @fn		static unsigned char XTIMEs(unsigned char x, unsigned char b)
 * @brief	calc byte to byte multiplication defined in FIPS-197
 *
 * @param	[in] x	polynomial x
 * @param	[in] b	byte
 * @return	result of multiplication
 */
static unsigned char XTIMEs(unsigned char x, unsigned char b)
{
	int i;
	unsigned char mul = 0;

	for (i = 0; i < 8; i++)
	{
		if (x & 1)
		{
			//when x is odd
			mul ^= b;
		}

		//calculate next xtime func
		if (b & 0x80)
		{
			//shift left
			b <<= 1;

			//xor 0x1b
			b ^= 0x1b;
		}
		else
		{
			//shift left
			b <<= 1;
		}

		//shift right
		x >>= 1;
	}

	//return result
	return mul;
}

/**
 * @fn		static void SubWord(SWAPv2_WORD buf)
 * @brief	SubWord function for Round Key calculation
 *
 * @param	[in,out] buf	4-byte word for SubWord
 * @return	void
 */
static void SubWord(SWAPv2_WORD buf)
{
	int i;
	for (i = 0; i < SWAPv2_WORD_SIZE; i++)
	{
		//calc SubWord
		buf[i] = s_box[buf[i] >> 4][buf[i] & 0x0F];
	}

	return;
}

/**
 * @fn		static void RotWord(SWAPv2_WORD buf)
 * @brief	RotWord function for Round Key calculation
 *
 * @param	[in,out] buf	4-byte word for RotWord
 * @return	void
 */
static void RotWord(SWAPv2_WORD buf)
{
	unsigned char temp = buf[0];

	//calc RotWord
	buf[0] = buf[1];
	buf[1] = buf[2];
	buf[2] = buf[3];
	buf[3] = temp;

	return;
}

/**
 * @fn		static void KeySched(SWAPv2_WORD key[], unsigned int lines, SWAPv2_WORD rk[], unsigned int rounds)
 * @brief	calculate round keys from given key bytes
 *
 * @param	[in] key		user key (cipher key)
 * @param	[in] lines		number of 32-bit words comprising the cipher key
 * @param	[out] rk		round key
 * @param	[in] rounds		number of rounds
 * @return	void
 */
static void KeySched(SWAPv2_WORD key[], unsigned int lines, SWAPv2_WORD rk[], unsigned int rounds)
{
	unsigned char Rcon = 1;
	unsigned char temp[SWAPv2_WORD_SIZE];
	unsigned int i;
	unsigned int j;

	for (i = 0; i < lines; i++)
	{
		//set first 1 set
		for (j = 0; j < SWAPv2_WORD_SIZE; j++)
		{
			rk[i][j] = key[i][j];
		}
	}

	for (i = lines; i < (SWAPv2_COLUMNS * (rounds + 1)); i++)
	{
		for (j = 0; j < SWAPv2_WORD_SIZE; j++)
		{
			temp[j] = rk[i - 1][j];
		}

		if ((i % lines) == 0)
		{
			//calc first row of next set
			RotWord(temp);
			SubWord(temp);
			temp[0] ^= Rcon;

			Rcon = XTIMEs(2, Rcon);
		}
		else if ((lines > 6) && ((i % lines) == 4))
		{
			SubWord(temp);
		}

		//clac next row
		for (j = 0; j < SWAPv2_WORD_SIZE; j++)
		{
			rk[i][j] = rk[i - lines][j] ^ temp[j];
		}
	}

	//clear temporary memory
	memset(temp, 0, sizeof(temp));

	return;
}

/**
 * @fn		void BitPermutation(unsigned char* pVal, unsigned char* bTable)
 * @brief	Calculate permutation bits in byte
 *
 * @param	[out]	pVal			byte value
 * @param	[in]	bTable			bit permutation indx
 * @return	void
 */
SPC_INTERNAL void BitPermutation(unsigned char* pVal, unsigned char* pTable)
{
	int i = 0;
	unsigned char oriVal = NULL;
	unsigned char tmp[8];

	if(pVal == NULL || pTable == NULL)
	{
		return;
	}
	
	oriVal = *pVal;

	for(i = 0; i < 8; i++)
	{
		tmp[i] = GETBIT_U8(oriVal, i);
	}

	for(i = 0; i < 8; i++)
	{
		*pVal = SETBIT_U8(*pVal, pTable[i], tmp[i]);
	}
}


/**
 * @fn		static void ProcessBitPBox(SWAPv2_BIT_PBOX* bpTable, unsigned int Nr)
 * @brief	Generate table for bit-permutation & apply bit permutation.
 *
 * @param	[out] bpTable	bit-permutation table
 * @param	[in] Nr			number of rounds
 * @return	void
 */
SPC_INTERNAL void ProcessBitPBox(SWAPv2_TBOX* pTBox, SWAPv2_BIT_PBOX* bpTable, unsigned int Nr)
{
	unsigned char i, j, k, l;
	unsigned char idx, row, col;
	unsigned int idxtmp;
	SWAPv2_TBOX* pCurTBox = NULL;
	SWAPv2_TBOX* pNxtTBox = NULL;
	SWAPv2_TBOX* pTmpTBox;

	if(pTBox == NULL || bpTable == NULL)
	{
		return;
	}

	//[Nr][8]
	//make random bit-permutaion order for each round
	for(i = 0; i < (Nr - 1); i++)
	{
		for(j = 0; j < 8; j++)
		{
			bpTable[i][j] = rand() % 8;

			for(idxtmp = 0; idxtmp < j; idxtmp++)
			{
				if(bpTable[i][idxtmp] == bpTable[i][j])
				{
					j--;
					break;
				}
			}
		}

		pCurTBox = (SWAPv2_TBOX*)((unsigned char*)pTBox + (i * SWAPv2_T_TABLE_ROUND_SIZE));

		for(idxtmp = 0; idxtmp < SWAPv2_T_TABLE_ROUND_SIZE; idxtmp += SWAPv2_WORD_SIZE)
		{
			BitPermutation(&(((unsigned char*)pCurTBox)[idxtmp    ]), bpTable[0]);
			BitPermutation(&(((unsigned char*)pCurTBox)[idxtmp + 1]), bpTable[0]);
			BitPermutation(&(((unsigned char*)pCurTBox)[idxtmp + 2]), bpTable[0]);
			BitPermutation(&(((unsigned char*)pCurTBox)[idxtmp + 3]), bpTable[0]);
		}
	}

	pTmpTBox = (SWAPv2_TBOX*)malloc(SWAPv2_T_TABLE_ROUND_SIZE);

	//replace T-Box order for each round
	for(i = 0; i < (Nr - 1); i++)
	{
		pNxtTBox = (SWAPv2_TBOX*)((unsigned char*)pTBox + ((i + 1) * SWAPv2_T_TABLE_ROUND_SIZE));

		for(j = 0; j < 16; j++)
		{
			for(k = 0; k < 16; k++)
			{
				for(l = 0; l < 16; l++)
				{
					idx = (k * 16) + l;
					BitPermutation(&idx, bpTable[0]);

					row = idx >> 4;
					col = idx & 0x0f;

					memcpy(pTmpTBox[j][row][col], pNxtTBox[j][k][l], SWAPv2_WORD_SIZE);
				}
			}
		}

		memcpy(pNxtTBox, pTmpTBox, SWAPv2_T_TABLE_ROUND_SIZE);
	}

	free(pTmpTBox);
}


/**
 * @fn		static void BytePermutation(SWAPv2_TBOX* tbox, SWAPv2_WORD* pwbox)
 * @brief	Calculate permutation word
 *
 * @param	[out] tbox		
 * @param	[in] pwbox		order of permutation
 * @return	void
 */
static void BytePermutation(SWAPv2_TBOX* tbox, SWAPv2_WORD* pwbox)
{
	unsigned int i;
	SWAPv2_WORD tmp;

	for(i = 0; i < SWAPv2_T_TABLE_ROUND_SIZE; i += (SWAPv2_WORD_SIZE * 4)) //word * 4
	{
		tmp[ byte_pMatrix[ ((unsigned char*)pwbox)[0] ][0] ] = ((unsigned char*)tbox)[i + 0];
		tmp[ byte_pMatrix[ ((unsigned char*)pwbox)[0] ][1] ] = ((unsigned char*)tbox)[i + 1];
		tmp[ byte_pMatrix[ ((unsigned char*)pwbox)[0] ][2] ] = ((unsigned char*)tbox)[i + 2];
		tmp[ byte_pMatrix[ ((unsigned char*)pwbox)[0] ][3] ] = ((unsigned char*)tbox)[i + 3];
		memcpy(((unsigned char*)tbox) + i, tmp, SWAPv2_WORD_SIZE);

		tmp[ byte_pMatrix[ ((unsigned char*)pwbox)[1] ][0] ] = ((unsigned char*)tbox)[i + 4];
		tmp[ byte_pMatrix[ ((unsigned char*)pwbox)[1] ][1] ] = ((unsigned char*)tbox)[i + 5];
		tmp[ byte_pMatrix[ ((unsigned char*)pwbox)[1] ][2] ] = ((unsigned char*)tbox)[i + 6];
		tmp[ byte_pMatrix[ ((unsigned char*)pwbox)[1] ][3] ] = ((unsigned char*)tbox)[i + 7];
		memcpy(((unsigned char*)tbox) + (i + 4), tmp, SWAPv2_WORD_SIZE);

		tmp[ byte_pMatrix[ ((unsigned char*)pwbox)[2] ][0] ] = ((unsigned char*)tbox)[i + 8];
		tmp[ byte_pMatrix[ ((unsigned char*)pwbox)[2] ][1] ] = ((unsigned char*)tbox)[i + 9];
		tmp[ byte_pMatrix[ ((unsigned char*)pwbox)[2] ][2] ] = ((unsigned char*)tbox)[i + 10];
		tmp[ byte_pMatrix[ ((unsigned char*)pwbox)[2] ][3] ] = ((unsigned char*)tbox)[i + 11];
		memcpy(((unsigned char*)tbox) + (i + 8), tmp, SWAPv2_WORD_SIZE);

		tmp[ byte_pMatrix[ ((unsigned char*)pwbox)[3] ][0] ] = ((unsigned char*)tbox)[i + 12];
		tmp[ byte_pMatrix[ ((unsigned char*)pwbox)[3] ][1] ] = ((unsigned char*)tbox)[i + 13];
		tmp[ byte_pMatrix[ ((unsigned char*)pwbox)[3] ][2] ] = ((unsigned char*)tbox)[i + 14];
		tmp[ byte_pMatrix[ ((unsigned char*)pwbox)[3] ][3] ] = ((unsigned char*)tbox)[i + 15];
		memcpy(((unsigned char*)tbox) + (i + 12), tmp, SWAPv2_WORD_SIZE);
	}
}

/**
 * @fn		static void ProcessBytePBox(SWAPv2_WORD_PBOX *pwTable, SWAPv2_TBOX *pTBox, unsigned int Nr)
 * @brief	Generate table for 4-byte permutation & apply byte permutation.
 *
 * @param	[out] pwTable	Table for permutation word of T-box table
 * @param	[in] pTBox		transform table for each round
 * @param	[in] Nr			number of rounds
 * @return	void
 */
static void ProcessBytePBox(SWAPv2_TBOX *pTBox, SWAPv2_WORD_PBOX *pwTable, unsigned int Nr)
{
	int i, j, k;

	//make random permutaion order for each round
	for(i = 0; i < Nr; i++)
	{
		for(j = 0; j < 4; j++)
		{
			(*pwTable)[i][j] = (rand() & 0x0f) % 24;

			for(k = 0; k < j; k++)
			{
				if((*pwTable)[i][j] == (*pwTable)[i][k])
				{
					j--;
					break;
				}
			}
		}

		BytePermutation((SWAPv2_TBOX*)((unsigned char*)pTBox + (i * SWAPv2_T_TABLE_ROUND_SIZE)), &(*pwTable)[i]);
	}
}

/**
 * @fn		static void InitalizeMicBox(SWAPv2_MIX_COLUMN_BOX MicBox[4], SWAPv2_TABLE_TYPE mode)
 * @brief	Calculate MixColumns Matrix MC0, MC1, MC2, MC3
 *
 * @param	[out] MicBox	Matrix for MixColumns
 * @param	[in] mode		flag which means encryption or decryption
 * @return	void
 */
static void InitalizeMicBox(SWAPv2_MIX_COLUMN_BOX MicBox[4], SWAPv2_TABLE_TYPE mode)
{
	//MicMatrix
	static const unsigned char MicMatrix[4][4] = 
	{
		{0x02, 0x01, 0x01, 0x03},
		{0x03, 0x02, 0x01, 0x01},
		{0x01, 0x03, 0x02, 0x01},
		{0x01, 0x01, 0x03, 0x02}
	};

	//Inverse MicMatrix
	static const unsigned char InvMicMatrix[4][4] = 
	{
		{0x0e, 0x09, 0x0d, 0x0b},
		{0x0b, 0x0e, 0x09, 0x0d},
		{0x0d, 0x0b, 0x0e, 0x09},
		{0x09, 0x0d, 0x0b, 0x0e}
	};

	unsigned int i;
	unsigned int j;
	unsigned int k;
	unsigned int l;

	//for each bytre of the word
	for (i = 0; i <  SWAPv2_WORD_SIZE; i++)
	{
		//sbox row
		for (j = 0; j <  16; j++)
		{
			//sbox col
			for (k = 0; k < 16; k++)
			{
				//xor MicMatrix
				for (l = 0; l < 4; l++)
				{
					if (mode == SWAPv2_TABLE_TYPE_ENCRYPTION)
					{
						//for encryption
						MicBox[i][j][k][l] = XTIMEs((j * 16 + k), MicMatrix[i][l]);
					}
					else
					{
						//for decryption
						MicBox[i][j][k][l] = XTIMEs((j * 16 + k), InvMicMatrix[i][l]);
					}
				}
			}
		}
	}

	return;
}

/**
 * @fn		static void AddMicBox(unsigned char val, SWAPv2_WORD* word, unsigned int idx, SWAPv2_WORD rnd, SWAPv2_TABLE_TYPE mode)
 * @brief	Applying MC box to the each element of T-box
 *
 * @param	[in] val		polynomial, each value of S-box
 * @param	[out] word		MixColumn-applied word
 * @param	[in] idx		index
 * @param	[in] rnd		random number for MixColumn randomizing
 * @param	[in] mode		flag which means encryption or decryption
 * @return	void
 */
static void AddMicBox(unsigned char val, SWAPv2_WORD* word, unsigned int idx, SWAPv2_WORD rnd, SWAPv2_TABLE_TYPE mode)
{
	static SWAPv2_MIX_COLUMN_BOX MicBox[4];				//MicBox
	static SWAPv2_MIX_COLUMN_BOX InvMicBox[4];			//Inverse MicBox
	static unsigned char MicBoxInitialFlag = 0;			//MicBox Initialize flag

	unsigned int i;

	//if flag is not set
	if (MicBoxInitialFlag == 0)
	{
		//calc MicBox
		InitalizeMicBox(MicBox, SWAPv2_TABLE_TYPE_ENCRYPTION);

		//calc Inverse MicBox
		InitalizeMicBox(InvMicBox, SWAPv2_TABLE_TYPE_DECRYPTION);

		//set flag
		MicBoxInitialFlag = 1;
	}

	for (i = 0; i < SWAPv2_WORD_SIZE; i++)
	{
		//add MicBox for encryption
		if (mode == SWAPv2_TABLE_TYPE_ENCRYPTION)
		{
			(*word)[i] = MicBox[idx][val >> 4][val & 0x0f][i] ^ rnd[i];
		}
		else
		{
			//add MicBox for decryption
			(*word)[i] = InvMicBox[idx][val >> 4][val & 0x0f][i] ^ rnd[i];
		}
	}

	return;
}

/**
 * @fn		static void MakeEachTBox(unsigned char mul, unsigned char xor, SWAPv2_TBOX* tbox, unsigned int idx, SWAPv2_WORD rnd, SWAPv2_TABLE_TYPE mode)
 * @brief	Claculating masked and expanded s-box
 *
 * @param	[in] mul		value to be multiplicated
 * @param	[in] xor		value to be added
 * @param	[out] tbox		T-box for each round key byte
 * @param	[in] idx		column index
 * @param	[in] rnd		random number for MixColumn randomizing
 * @param	[in] mode		flag which means encryption or decryption
 * @return	void
 */
static void MakeEachTBox(unsigned char mul, unsigned char xor, SWAPv2_TBOX* tbox, unsigned int idx, SWAPv2_WORD rnd, SWAPv2_TABLE_TYPE mode)
{
	unsigned int i;
	unsigned int j;
	unsigned char mul_row = (mul >> 4);
	unsigned char mul_col = (mul & 0x0f);

	//S-Box row
	for (i = 0; i < 16; i++)
	{
		//S-Box col
		for (j = 0; j < 16; j++)
		{
			if (mode == SWAPv2_TABLE_TYPE_ENCRYPTION)
			{
				//add MicBox for encryption
				AddMicBox(s_box[i ^ mul_row][j ^ mul_col] ^ xor, &(*tbox)[i][j], idx, rnd, mode);
			}
			else
			{
				//add MicBox for decryption
				AddMicBox(inv_s_box[i ^ mul_row][j ^ mul_col] ^ xor, &(*tbox)[i][j], idx, rnd, mode);
			}
		}
	}

	return;
}

/**
 * @fn		static void SBOX_Xor(unsigned char mul, unsigned char xor, SWAPv2_TBOX* tbox, SWAPv2_TABLE_TYPE mode)
 * @brief	Claculating masked s-box
 *
 * @param	[in] mul		value to be multiplicated
 * @param	[in] xor		value to be added
 * @param	[in] tbox		T-box for each round key byte
 * @param	[in] mode		flag which means encryption or decryption
 * @return	void
 */
static void SBOX_Xor(unsigned char mul, unsigned char xor, SWAPv2_TBOX* tbox, SWAPv2_TABLE_TYPE mode)
{
	unsigned int i;
	unsigned int j;
	unsigned char mul_row = mul >> 4;
	unsigned char mul_col = mul & 0x0f;

	//S-Box row
	for (i = 0; i < 16; i++)
	{
		//S-Box col
		for (j = 0; j < 16; j++)
		{
			if (mode == SWAPv2_TABLE_TYPE_ENCRYPTION)
			{
				//clac T-box for encryption
				(*tbox)[i][j][0] = s_box[i ^ mul_row][j ^ mul_col] ^ xor;
			}
			else
			{
				//calc T-box for decryption
				(*tbox)[i][j][0] = inv_s_box[i ^ mul_row][j ^ mul_col] ^ xor;
			}

			//fill empty bytes with random numbers
			(*tbox)[i][j][1] = rand() & 0xff;
			(*tbox)[i][j][2] = rand() & 0xff;
			(*tbox)[i][j][3] = rand() & 0xff;
		}
	}

	return;
}

/**
 * @fn		static void CalcTBox(SWAPv2_RK_BOX* RK, SWAPv2_TBOX* pTable, unsigned int Nr)
 * @brief	Calculate T-box table for encryption
 *
 * @param	[in] RK			round key
 * @param	[out] pTable	T-box, transform table
 * @param	[in] Nr			number of rounds
 * @return	void
 */
static void CalcTBox(SWAPv2_RK_BOX* RK, SWAPv2_TBOX* pTable, unsigned int Nr)
{
	unsigned int i;
	unsigned int j;
	unsigned int k;
	unsigned char mask[16] = {0};

	SWAPv2_WORD rnd[16];

	//1. make T-box for each rounds
	for (i = 0; i < (Nr - 1); i++)
	{
		//make random masking
		for (j = 0; j < 16; j++)
		{
			for (k = 0; k < 4; k++)
			{
				rnd[j][k] = rand() & 0xff;
			}
		}

		//for each col
		for (j = 0; j < SWAPv2_COLUMNS; j++)
		{
			for (k = 0; k < SWAPv2_WORD_SIZE; k++)
			{
				//make each TBox
				MakeEachTBox(RK[i][j][k] ^ mask[j * 4 + k], 0, &pTable[i * 16 + j * 4 + k], k, rnd[j * 4 + k], SWAPv2_TABLE_TYPE_ENCRYPTION);
			}
		}

		for (j = 0; j < 4; j++)
		{
			for (k = 0; k < 4; k++)
			{
				//apply random masking
				mask[j * 4 + k] = rnd[inv_sr_matrix[j * 4    ]][k] ^
								  rnd[inv_sr_matrix[j * 4 + 1]][k] ^ 
								  rnd[inv_sr_matrix[j * 4 + 2]][k] ^ 
								  rnd[inv_sr_matrix[j * 4 + 3]][k];

			}
		}
	}

	//2. make T-box for last round
	for (j = 0; j < SWAPv2_COLUMNS; j++)
	{
		for (k = 0; k < SWAPv2_WORD_SIZE; k++)
		{
			unsigned char temp = sr_matrix[j * SWAPv2_WORD_SIZE + k];
			SBOX_Xor(RK[i][j][k] ^ mask[j * 4 + k], RK[i + 1][temp >> 4][temp & 0x0f], &pTable[i * 16 + j * 4 + k], SWAPv2_TABLE_TYPE_ENCRYPTION);
		}
	}

	return;
}

/**
 * @fn		static void CalcInvTBox(SWAPv2_RK_BOX* RK, SWAPv2_TBOX* pTable, unsigned int Nr)
 * @brief	Calculate T-box table for decryption
 *
 * @param	[in] RK		round key
 * @param	[in] pTable	T-box, transform table
 * @param	[in] Nr		number of rounds
 * @return	void
 */
static void CalcInvTBox(SWAPv2_RK_BOX* RK, SWAPv2_TBOX* pTable, unsigned int Nr)
{
	unsigned int i;
	unsigned int j;
	unsigned int k;
	unsigned char mask[16] = {0};

	SWAPv2_WORD rnd[16];

	//1. make T-box for each rounds
	for (i = 0; i < (Nr - 1); i++)
	{
		//make random masking
		for (j = 0; j < 16; j++)
		{
			for (k = 0; k < 4; k++)
			{
				rnd[j][k] = rand() & 0xff;
			}
		}

		//for each col
		for (j = 0; j < SWAPv2_COLUMNS; j++)
		{
			for (k = 0; k < SWAPv2_WORD_SIZE; k++)
			{
				if (i == 0)
				{
					//make first T-Box
					unsigned char temp = inv_sr_matrix[j * SWAPv2_WORD_SIZE + k];
					MakeEachTBox(RK[Nr][j][k], RK[Nr - 1][temp >> 4][temp & 0x0f], &pTable[j * 4 + k], k, rnd[j * 4 + k], SWAPv2_TABLE_TYPE_DECRYPTION);
				}
				else
				{
					//make each T-Box
					MakeEachTBox(mask[j * 4 + k], RK[Nr - i - 1][j][k], &pTable[i * 16 + j * 4 + k], k, rnd[j * 4 + k], SWAPv2_TABLE_TYPE_DECRYPTION);
				}
			}
		}

		for (j = 0; j < 4; j++)
		{
			for (k = 0; k < 4; k++)
			{
				if (i == 0)
				{
					//apply random mask for 1st T-Box
					const unsigned char conv_matrix[16] =
						{0, 7, 10, 13, 1, 4, 11, 14, 2, 5, 8, 15, 3, 6, 9, 12};
					mask[inv_sr_matrix[j * 4 + k]] = rnd[conv_matrix[j * 4    ]][k] ^
													 rnd[conv_matrix[j * 4 + 1]][k] ^ 
													 rnd[conv_matrix[j * 4 + 2]][k] ^ 
													 rnd[conv_matrix[j * 4 + 3]][k];
				}
				else
				{
					//apply random mask
					mask[inv_sr_matrix[j * 4 + k]] = rnd[j * 4    ][k] ^
													 rnd[j * 4 + 1][k] ^ 
													 rnd[j * 4 + 2][k] ^ 
													 rnd[j * 4 + 3][k];
				}
			}
		}
	}

	//2. make T-box for last round
	for (j = 0; j < SWAPv2_COLUMNS; j++)
	{
		for (k = 0; k < SWAPv2_WORD_SIZE; k++)
		{
			SBOX_Xor(mask[j * 4 + k], RK[0][j][k], &pTable[i * 16 + j * 4 + k], SWAPv2_TABLE_TYPE_DECRYPTION);
		}
	}

	return;
}

/**
 * @fn		static void ProcessInitalPermutation(SWAPv2_PBOX *Table, SWAPv2_PVECTOR* PVector)
 * @brief	process initial permutation
 *
 * @param	[in,out] Table		P-box, permutation table
 * @param 	[in] PVector		permutation vector
 * @return	void
 */
static void ProcessInitalPermutation(SWAPv2_PBOX *Table, SWAPv2_PVECTOR* PVector)
{
	unsigned int j;
	unsigned int k;

	for (j = 0; j < 2; j++)
	{
		for (k = 0; k < 8; k++)
		{
			//make initial permutation table
			Table[0][j][k] = PVector[0][j * 8 + k];
		}
	}

	for (; j < 4; j++)
	{
		for (k = 0; k < 8; k++)
		{
			//fill empty bytes with random numbers
			Table[0][j][k] = rand() & 0xff;
		}
	}

	return;
}

/**
 * @fn		static void ProcessFinalPermutation(SWAPv2_PBOX *Table, SWAPv2_PVECTOR* PVector, unsigned int Nr, SWAPv2_TABLE_TYPE mode)
 * @brief	process final permutation
 *
 * @param	[in,out] Table	P-box, permutation table
 * @param	[in] PVector	permutation vector
 * @param	[in] Nr			number of rounds
 * @param	[in] mode		flag which means encryption or decryption
 * @return	void
 */
static void ProcessFinalPermutation(SWAPv2_PBOX *Table, SWAPv2_PVECTOR* PVector, unsigned int Nr, SWAPv2_TABLE_TYPE mode)
{
	unsigned int i;
	unsigned int j;
	unsigned int k;

	for (j = 0; j < 2; j++)
	{
		for (k = 0; k < 8; k++)
		{
			if (mode == SWAPv2_TABLE_TYPE_ENCRYPTION)
			{
				Table[Nr][PVector[Nr - 1][j * 8 + k] / 8][PVector[Nr - 1][j * 8 + k] % 8] = sr_matrix[j * 8 + k];
			}
			else
			{
				Table[Nr][PVector[Nr - 1][j * 8 + k] / 8][PVector[Nr - 1][j * 8 + k] % 8] = j * 8 + k;
			}
		}
	}

	//fill empty bytes with random numbers
	for (; j < 4; j++)
	{
		for (k = 0; k < 8; k++)
		{
			Table[Nr][j][k] = rand() & 0xff;
		}
	}

	//add random to permutation table (ex. 0x0d 0x0c ==> 0x4d 0x7c)
	for (i = 0; i <= Nr; i++)
	{
		for (j = 0; j < 4; j++)
		{
			for (k = 0; k < 8; k++)
			{
				unsigned char rnd = rand() % 16;
				Table[i][j][k] ^= (rnd << 4);
			}
		}
	}

	return;
}

/**
 * @fn		 static void MakePTable(SWAPv2_PBOX *Table, unsigned int round, unsigned char itmdt[16][4])
 * @brief	Calculate P-box for each round
 *
 * @param	[in,out] Table	P-box, permutation table
 * @param	[in] round		current round
 * @param	[in] itmdt		intermediate value
 * @return	void
 */
static void MakePTable(SWAPv2_PBOX *Table, unsigned int round, unsigned char itmdt[16][4])
{
	unsigned int j;
	unsigned int k;
	unsigned int idx[4] = {0};

	//fill P-Table with 0xff
	memset(&Table[round], 0xff, sizeof(SWAPv2_PBOX));

	for (j = 0; j < 16; j++)
	{
		for (k = 0; k < 4; k++)
		{
			if (Table[round][k][0] == 0xff)
			{
				//if the key value is not added yet, add key value and 1st index
				memcpy(&Table[round][k], &itmdt[j], sizeof(SWAPv2_WORD));
				idx[k] = 0;
				Table[round][k][4 + idx[k]] = j;

				break;
			}
			else if (memcmp(&itmdt[j], &Table[round][k], SWAPv2_WORD_SIZE) == 0)
			{
				//if the index already exists, just add index
				idx[k]++;
				Table[round][k][4 + idx[k]] = j;

				break;
			}
		}
	}

	return;
}

/**
 * @fn		static void CalcPBox(SWAPv2_PBOX *Table, SWAPv2_PVECTOR* PVector, unsigned int Nr)
 * @brief	Calculate P-box table for encryption
 *
 * @param	[out] Table		P-box, permutation table
 * @param	[in] PVector	permutation vector
 * @param	[in] Nr			number of rounds
 * @return	void
 */
static void CalcPBox(SWAPv2_PBOX *Table, SWAPv2_PVECTOR* PVector, unsigned int Nr)
{
	unsigned int i;
	unsigned int j;
	unsigned int k;
	unsigned int temp;
	
	unsigned char InvMix[16];
	unsigned char itmdt[16][4];

	//1. make initial permutation
	ProcessInitalPermutation(Table, PVector);

	//2. make permutation table
	for (i = 1; i < Nr; i++)
	{
		//calc Intermideate table
		for (j = 0; j < 16; j++)
		{
			InvMix[PVector[i - 1][j]] = j;
		}

		for (j = 0; j < 16; j++)
		{
			for (k = 0; k < 4; k++)
			{
				temp = (sr_matrix[InvMix[j]] / 4) * 4 + k;
				itmdt[j][k] = PVector[i][temp];
			}
		}

		MakePTable(Table, i, itmdt);
	}

	//3. make final permutation
	ProcessFinalPermutation(Table, PVector, Nr, SWAPv2_TABLE_TYPE_ENCRYPTION);

	return;
}

/**
 * @fn		static void CalcInvPBox(SWAPv2_PBOX *Table, SWAPv2_PVECTOR* PVector, unsigned int Nr)
 * @brief	Calculate P-box table for decryption
 *
 * @param 	[out] Table		P-box, permutation table
 * @param	[in] PVector	permutation vector
 * @param	[in] Nr			number of rounds
 * @return	void
 */
static void CalcInvPBox(SWAPv2_PBOX *Table, SWAPv2_PVECTOR* PVector, unsigned int Nr)
{
	unsigned int i;
	unsigned int j;
	unsigned int k;
	unsigned int temp;
	
	unsigned char InvMix[16];
	unsigned char itmdt[16][4];

	//1. make initial permutation
	ProcessInitalPermutation(Table, PVector);

	//2. make permutation table
	for (i = 1; i < Nr; i++)
	{
		for (j = 0; j < 16; j++)
		{
			InvMix[PVector[i - 1][j]] = j;
		}

		//calc Intermideate table
		for (j = 0; j < 16; j++)
		{
			for (k = 0; k < 4; k++)
			{
				if (i == 1)
				{
					temp = inv_sr_matrix[(inv_sr_matrix[InvMix[j]] / 4) * 4 + k];
					itmdt[j][k] = PVector[i][temp];
				}
				else
				{
					temp = inv_sr_matrix[(InvMix[j] / 4) * 4 + k];
					itmdt[j][k] = PVector[i][temp];
				}
			}
		}

		MakePTable(Table, i, itmdt);
	}

	//3. make final permutation
	ProcessFinalPermutation(Table, PVector, Nr, SWAPv2_TABLE_TYPE_DECRYPTION);

	return;
}

/**
 * @fn		static void GeneratePVector(unsigned int Nr, SWAPv2_PVECTOR* PVector)
 * @brief	generate permutation vector
 *
 * @param	[in] Nr			number of rounds
 * @param	[out] PVector	permutation vector
 * @return	void
 */
static void GeneratePVector(unsigned int Nr, SWAPv2_PVECTOR* PVector)
{
	unsigned int rnd;
	unsigned char flag[16];
	unsigned char sequence[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	unsigned int i;
	unsigned int j;

	for (i = 0; i < Nr; i++)
	{
		//make 16 byte random sequence for each round
		memcpy(flag, sequence, sizeof(flag));
		for (j = 0; j < 16; j++)
		{
			rnd = rand() % (16 - j);
			PVector[i][j] = flag[rnd];
			flag[rnd] = flag[16 - j - 1];
		}
	}

	return;
}

/**
 * @fn		static void ShuffleTBox(SWAPv2_TBOX* pTBox, SWAPv2_PVECTOR* PVector, unsigned int Nr)
 * @brief	shuffle T-box according to the permutation vector
 *
 * @param	[in,out] pTBox	T-box, transform table
 * @param	[in] PVector	permutation vector
 * @param	[in] Nr			number of rounds
 * @return	void
 */
static void ShuffleTBox(SWAPv2_TBOX* pTBox, SWAPv2_PVECTOR* PVector, unsigned int Nr)
{
	unsigned int i;
	unsigned int j;
	SWAPv2_TBOX* pCurrentTBox = pTBox;
	SWAPv2_TBOX temp[16];

	for (i = 0; i < Nr; i++)
	{
		//temp = current TBox
		memcpy(&temp, pCurrentTBox, sizeof(SWAPv2_TBOX) * 16);

		for (j = 0; j < 16; j++)
		{
			//Shuffle each item of T-Box
			memcpy(&pCurrentTBox[PVector[i][j]], temp[j], sizeof(SWAPv2_TBOX));
		}

		//current TBox = temp
		pCurrentTBox = &pCurrentTBox[16];
	}

	return ;
}

/**
 * @fn		static void GeneratePVector_fst(unsigned int Nr, SWAPv2_PVECTOR* PVector)
 * @brief	generate permutation vector for fast implementation
 *
 * @param	[in] Nr			number of rounds
 * @param	[out] PVector	permutation vector
 * @return	void
 */
static void GeneratePVector_fst(unsigned int Nr, SWAPv2_PVECTOR* PVector)
{
	unsigned int rnd;
	unsigned int sfl;
	unsigned char flag[4];
	unsigned char sequence[4] = {0, 1, 2, 3};
	unsigned int i;
	unsigned int j;
	unsigned int k;

	//shuffle table
	unsigned char sflTable[4][4] = 
	{
		{0x00, 0x01, 0x02, 0x03},
		{0x01, 0x02, 0x03, 0x00},
		{0x02, 0x03, 0x00, 0x01},
		{0x03, 0x00, 0x01, 0x02}
	};

	//calculate PVector
	for (i = 0; i < Nr; i++)
	{
		memcpy(flag, sequence, sizeof(flag));
		for (j = 0; j < 4; j++)
		{
			rnd = rand() % (4 - j);
			sfl = rand() % 4;
			for (k = 0; k < 4; k++)
			{
				PVector[i][j * 4 + k] = flag[rnd] * 4 + sflTable[sfl][k];
			}
			flag[rnd] = flag[4 - j - 1];
		}
	}

	return;
}

/**
 * @fn		static void GenerateInvPVector_fst(unsigned int Nr, SWAPv2_PVECTOR* PVector)
 * @brief	generate permutation vector for fast decryption
 *
 * @param	[in] Nr			number of rounds
 * @param	[out] PVector	permutation vector
 * @return	void
 */
static void GenerateInvPVector_fst(unsigned int Nr, SWAPv2_PVECTOR* PVector)
{
	unsigned int rnd;
	unsigned int sfl;
	unsigned char flag[4];
	unsigned char sequence[4] = {0, 1, 2, 3};
	unsigned int i;
	unsigned int j;
	unsigned int k;

	//shuffle table
	unsigned char sflTable[4][4] = 
	{
		{0x00, 0x01, 0x02, 0x03},
		{0x01, 0x02, 0x03, 0x00},
		{0x02, 0x03, 0x00, 0x01},
		{0x03, 0x00, 0x01, 0x02}
	};

	//calculate inverse PVector
	for (i = 0; i < Nr; i++)
	{
		memcpy(flag, sequence, sizeof(flag));
		for (j = 0; j < 4; j++)
		{
			rnd = rand() % (4 - j);
			sfl = rand() % 4;
			for (k = 0; k < 4; k++)
			{
				PVector[i][inv_sr_matrix[j * 4 + k]] = flag[rnd] * 4 + sflTable[sfl][k];
			}
			flag[rnd] = flag[4 - j - 1];
		}
	}

	return;
}

/**
 * @fn		static void GenerateInvPVector_fstest(unsigned int Nr, SWAPv2_PVECTOR* PVector)
 * @brief	generate permutation vector for fastest decryption
 *
 * @param	[in] Nr			number of rounds
 * @param	[out] PVector	permutation vector
 * @return	void
 */
static void GenerateInvPVector_fstest(unsigned int Nr, SWAPv2_PVECTOR* PVector)
{
	unsigned int i;
	unsigned int j;

	//Actually, no permutation is applied
	for (i = 0; i < 16; i++)
	{
		PVector[0][i] = i;
	}

	for (i = 1; i < Nr; i++)
	{
		for (j = 0; j < 16; j++)
		{
			PVector[i][inv_sr_matrix[j]] = j;
		}
	}

	return;
}

/**
 * @fn		static void ConvertPBox(SWAPv2_PBOX *Table, unsigned int Nr)
 * @brief	convert PBox for simple permutation
 *
 * @param	[in,out] Table	PBox
 * @param	[out] Nr		number of rounds
 * @return	void
 */
static void ConvertPBox(SWAPv2_PBOX *Table, unsigned int Nr)
{
	unsigned int i;
	unsigned int j;
	unsigned char t;

	for (i = 1; i < Nr; i++)
	{
		for (j = 0; j < 4; j++)
		{
			//calculate each table and fill empty bits with random mask
			t = Table[i][j][0] & 0x0f;
			Table[i][j][0] = (t / 4) + (0x00 & 0xfc); //(t / 4) + (rand() & 0xfc);
			Table[i][j][1] = ((t % 4) * 8) + (0x00 & 0xe0); //((t % 4) * 8) + (rand() & 0xe0)
			Table[i][j][2] = rand() & 0xff;
			Table[i][j][3] = rand() & 0xff;
		}
	}
}

/**
 * @fn		static void RandomizePBox(SWAPv2_PBOX *Table, unsigned int Nr)
 * @brief	fill the PBox with random numbers
 *
 * @param	[in,out] Table	PBox
 * @param	[out] Nr		number of rounds
 * @return	void
 */
static void RandomizePBox(SWAPv2_PBOX *Table, unsigned int Nr)
{
	unsigned int i;
	unsigned int j;
	unsigned int k;

	for (i = 0; i <= Nr; i++)
	{
		for (j = 0; j < 4; j++)
		{
			for (k = 0; k < 8; k++)
			{
				//fill the table with random numbers
				Table[i][j][k] = rand() & 0xff;
			}
		}
	}
}

/**
 * @fn		unsigned int SWAPv2_GenerateTable(unsigned char* Key, unsigned char KeyLen, unsigned int seed, unsigned char **Table, unsigned int *TableLen, int isEncryption, unsigned int OptimizLev)
 * @brief	derivate look-up table from given key
 *
 * @param	[in] Key			user key (cipher key)
 * @param	[in] KeyLen			byte-length of cipher key
 * @param	[in] seed			random seed
 * @param	[out] Table			look-up table for SWAPv2
 * @param	[out] TableLen		byte-length of look-up table
 * @param	[in] isEncryption	flag ordering encryption or decryption
 * @return	SWAPv2_TBLGEN_RETURN_VAL
 */
SPC_INTERNAL unsigned int SWAPv2_GenerateTable(unsigned char* Key, unsigned char KeyLen, unsigned int seed, unsigned char **Table, unsigned int *TableLen, int isEncryption)
{
	SWAPv2_TBLGEN_RETURN_VAL retVal = SWAPv2_TBLGEN_RETURN_SUCCESS;
	unsigned int Nr = 0;
	unsigned int Nk = 0;
	unsigned char *RoundKey = NULL;
	unsigned int RoundKeySize = 0;
	unsigned int TBoxSize = 0;
	unsigned int PBoxSize = 0;
	unsigned int WPBoxSize = 0;
	unsigned int BPBoxSize = 0;
	SWAPv2_TBOX *pTBox = NULL;
	SWAPv2_PBOX *pPBox = NULL;
	SWAPv2_WORD_PBOX *pBytePBox = NULL;
	SWAPv2_BIT_PBOX *pBitPBox = NULL;
	SWAPv2_PVECTOR PVector[SWAPv2_256_ROUNDS + 1];

	//1. Argument Check
	if ((Key == NULL) || (Table == NULL))
	{
		retVal = SWAPv2_TBLGEN_RETURN_INVALID_PARAMETER;			//invalid input
		goto ERROR_PROC;
	}

	//2. Set Number of rounds
	switch(KeyLen)						//find Nr
	{
		case 16:
			//AES128
			Nr = 10;
			break;
		case 24:
			//AES192
			Nr = 12;
			break;
		case 32:
			//AES256
			Nr = 14;
			break;
		default:
			retVal = SWAPv2_TBLGEN_RETURN_INVALID_KEYLEN;			//invalid key length
			goto ERROR_PROC;
	}

	//calculate round key size
	RoundKeySize = SWAPv2_COLUMNS * SWAPv2_WORD_SIZE * (Nr + 1);	//Nb * word size * (number of rounds + 1)

	//allocate memory for round key
	RoundKey = (unsigned char*)malloc(RoundKeySize);
	if (RoundKey == NULL)
	{
		retVal = SWAPv2_TBLGEN_RETURN_MEM_ALLOC_FAILED;			//memory allocation failed
		goto ERROR_PROC;
	}

	//calculate TBox and PBox size
	TBoxSize = SWAPv2_T_TABLE_ROUND_SIZE * Nr;				//each byte of round key has its own s-box table
	PBoxSize = SWAPv2_P_TABLE_ROUND_SIZE * (Nr + 1);		//Permutation table for each round, and initial permutation
	WPBoxSize = SWAPv2_WP_TABLE_ROUND_SIZE * Nr;			//Permutation word of transform table for each round
	BPBoxSize = SWAPv2_BP_TABLE_ROUND_SIZE * Nr;			//Permutation bit of transform table for each round

	//allocate memory for TBox and PBox
	pTBox = (SWAPv2_TBOX*)malloc(TBoxSize + PBoxSize + WPBoxSize + BPBoxSize);

	if (pTBox == NULL)
	{
		retVal = SWAPv2_TBLGEN_RETURN_MEM_ALLOC_FAILED;			//memory allocation failed
		goto ERROR_PROC;
	}

	pPBox = (SWAPv2_PBOX*)((unsigned char*)pTBox + TBoxSize);
	pBytePBox = (SWAPv2_WORD_PBOX*)((unsigned char*)pTBox + TBoxSize + PBoxSize);
	pBitPBox = (SWAPv2_BIT_PBOX*)((unsigned char*)pTBox + TBoxSize + PBoxSize + WPBoxSize);
	
	//calculate Nk
	Nk = KeyLen / SWAPv2_WORD_SIZE;								//Nk is the word size of given key

	//seed random seed
	srand(seed);

	//3. Calc Round Key
	KeySched((SWAPv2_WORD*)Key, Nk, (SWAPv2_WORD*)RoundKey, Nr);

	if (isEncryption)
	{
		//4. Generate permutation vector and PBox
		GeneratePVector(Nr, PVector);
		CalcPBox(pPBox, PVector, Nr);

		//5. Generate table for calc AddRoundKey, SubBytes and MixColumn
		CalcTBox((SWAPv2_RK_BOX*)RoundKey, pTBox, Nr);
	}
	else
	{
		//4. Generate permutation vector and PBox

		GeneratePVector(Nr, PVector);
		CalcInvPBox(pPBox, PVector, Nr);

		//5. Generate table for calc AddRoundKey, SubBytes and MixColumn
		CalcInvTBox((SWAPv2_RK_BOX*)RoundKey, pTBox, Nr);
	}

	//6. Create bit-permutation table & apply bit-permutation
	ProcessBitPBox(pTBox, pBitPBox, Nr);

	//7. Generate byte-permutation table & apply byte-permutation
	ProcessBytePBox(pTBox, pBytePBox, Nr);

	//8. Shuffle TBox according to the permutation vector
	ShuffleTBox(pTBox, PVector, Nr);

	//9. Set output
	*Table = (unsigned char*)pTBox;
	//set pTbox to preventing free
	pTBox = NULL;

	//set table length
	if (TableLen != NULL)
	{
		*TableLen = TBoxSize + PBoxSize + WPBoxSize + BPBoxSize;
	}
	
ERROR_PROC:
	//clear memory
	memset(PVector, 0x00, sizeof(PVector));

	//free roundkey
	if (RoundKey != NULL)
	{
		//clear before free
		memset(RoundKey, 0x00, RoundKeySize);
		free(RoundKey);
	}
#if 0
	//free TBox if not null
	if (pTBox != NULL)
	{
		//clear before free
		memset(pTBox, 0x00, TBoxSize + PBoxSize + WPBoxSize + BPBoxSize);
		free(pTBox);
	}
#endif

	if(pSBox != NULL)
	{
		memset(pSBox, 0x00, sizeof(SWAPv2_SBOX) * Nr);
		free(pSBox);
	}

	if(pInvSBox != NULL)
	{
		memset(pInvSBox, 0x00, sizeof(SWAPv2_SBOX) * Nr);
		free(pInvSBox);
	}

	return retVal;
}
////////////////////////// End of File //////////////////////////
