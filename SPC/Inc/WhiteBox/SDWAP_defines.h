/**
 * @file	SDWAP_defines.h
 * @brief	defines the constants, types and macros used in SDWAP(Samsung Dynamic Whitebox AES Project version2)
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
 * The logic of whitebox table generation is confidential.
 */

#ifndef _SDWAP_DEFINES_H_
#define _SDWAP_DEFINES_H_

#ifndef _WIN

	#define SPC_INTERNAL  __attribute__((visibility("hidden")))
#else
	#define SPC_INTERNAL  
#endif


////////////////////////////////////////////////////////////////////////////
// Constants
////////////////////////////////////////////////////////////////////////////
#define SDWAP_WORD_SIZE			4			/*!< Each word has 4-byte length, defined in FIPS-197  */
#define SDWAP_COLUMNS			4			/*!< Number of columns comprising the State. Defined as Nb in FIPS-197  */

#define SDWAP_128_ROUNDS		10			/*!< Number of rounds, for AES-128  */
#define SDWAP_192_ROUNDS		12			/*!< Number of rounds, for AES-192  */
#define SDWAP_256_ROUNDS		14			/*!< Number of rounds, for AES-256  */

////////////////////////////////////////////////////////////////////////////
// Types
////////////////////////////////////////////////////////////////////////////
typedef unsigned char		SDWAP_WORD[SDWAP_WORD_SIZE];					//!< SDWAP_WORD represents each word
typedef unsigned char		SDWAP_RK_BOX[SDWAP_COLUMNS][SDWAP_WORD_SIZE];	//!< SDWAP_RK_BOX represents round keys for one round
typedef SDWAP_WORD			SDWAP_MIX_COLUMN_BOX[16][16];					//!< SDWAP_MIX_COLUMN_BOX represents each MC box
typedef unsigned char		SDWAP_SBOX[16][16];								//!< SDWAP_SBOX represents each S-box
typedef SDWAP_WORD			SDWAP_TBOX[16][16];								//!< SDWAP_TBOX represents transform table for each byte of round key
typedef unsigned char		SDWAP_PBOX[4][8];								//!< SDWAP_PBOX represents permutation table for each round
typedef unsigned char		SDWAP_PVECTOR[16];								//!< SDWAP_PVECTOR represents permutation vector for each round
typedef SDWAP_WORD			SDWAP_WORD_PBOX[16];							//!< SDWAP_WORD_PBOX represents permutation word of transform table for each round
typedef unsigned char		SDWAP_BIT_PBOX[8];								//!< SDWAP_BIT_PBOX represents permutation word of transform table for each round

typedef unsigned char		SDWAP_KEY_LOOKUP[4][17];						//!< SDWAP_KEY_LOOKUP represents transform table for each column of round key
typedef unsigned char		SDWAP_KEY_RANDOM_MASK[5][4];
typedef unsigned char		SDWAP_KEY_BYTE_PBOX[17];						//!< SDWAP_KEY_BYTE_PBOX represents permutation word of transform table for each round
typedef unsigned char		SDWAP_KEY_BIT_PBOX[8];							//!< SDWAP_KEY_BIT_PBOX represents permutation word of transform table for each round

////////////////////////////////////////////////////////////////////////////
// Macros
////////////////////////////////////////////////////////////////////////////
#define SBOX_SIZ						(16 * 16)												/*! SBOX_SIZ represents the size of S-box(16x16 matrix), for 4bit-4bit lookup */
#define SDWAP_T_TABLE_ROUND_SIZE		(sizeof(SDWAP_TBOX) * SDWAP_COLUMNS * SDWAP_WORD_SIZE)	/*! SDWAP_T_TABLE_ROUND_SIZE represents the size of transform table for one round */
#define SDWAP_P_TABLE_ROUND_SIZE		(sizeof(SDWAP_PBOX))									/*! SDWAP_P_TABLE_ROUND_SIZE represents the size of permutation table for one round */
#define SDWAP_WP_TABLE_ROUND_SIZE		SDWAP_WORD_SIZE * 4										/*! SDWAP_WP_TABLE_ROUND_SIZE represents the size of permutation word of transform table for one round */
#define SDWAP_BP_TABLE_ROUND_SIZE		8														/*! SDWAP_BP_TABLE_ROUND_SIZE represents the size of permutation bit of transform table for one round */

#define SDWAP_KEY_LOOKUP_COLUMN_SIZE	17 * 4													/*! SDWAP_KEY_LOOKUP_SIZE represents the size of key lookup table for one round */
#define SDWAP_KEY_RANDOM_MASK_SIZE		sizeof(SDWAP_KEY_RANDOM_MASK)

#define SETBIT_U8(val, idx, bit)	bit == 1 ?	(unsigned char) ( val | (1 << idx) ) :	(unsigned char) ( val & (~(1 << idx)) )		/*! set a bit */ 
#define GETBIT_U8(val, idx)			(val & (1 << idx)) >> idx																		/*! get a bit */


/**
 * @var static const unsigned char byte_pMatrix[24][4]
 * @brief look-up matrix for CalcPWTBox, Calculate Word-Permutation T-Box
 */
static const unsigned char byte_pMatrix[24][4] = 
{
	{0, 1, 2, 3}, {0, 1, 3, 2}, {0, 2, 1, 3}, {0, 2, 3, 1}, {0, 3, 1, 2}, {0, 3, 2, 1},
	{1, 0, 2, 3}, {1, 0, 3, 2}, {1, 2, 0, 3}, {1, 2, 3, 0}, {1, 3, 0, 2}, {1, 3, 2, 0},
	{2, 0, 1, 3}, {2, 0, 3, 1}, {2, 1, 0, 3}, {2, 1, 3, 0}, {2, 3, 0, 1}, {2, 3, 1, 0},
	{3, 0, 1, 2}, {3, 0, 2, 1}, {3, 1, 0, 2}, {3, 1, 2, 0}, {3, 2, 0, 1}, {3, 2, 1, 0}
};

#endif //_SDWAP_DEFINES_H_
