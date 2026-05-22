/**
 * @file	SWAPv2_TblGen.h
 * @brief	white box AES table generation module for SSA(Samsung Security Architecture)
 * @author	Samsung WhiteBox AES Version 2 (SWAPv1 based)
 *				- Chul Lee(chuls.lee@samsung.com)
 *				- Dept : Software R&D Center / Cloud Computing Lab.
 *
 *			Samsung WhiteBox AES Version 1
 *				 - Jisoon Park(js00n.park@samsung.com)
 *				 - Dept: DMC R&D Center/Convergence Software Lab.
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
 */

/**
 * @interface	SWPAv2_TblGen
 * @brief		table generator of SWAPv2(Samsung Whitebox AES Project Version 2)
 *
 * @par Features :
 * # Functionality1 : table generator of SWAPv2
 * @date 2012-10-05
 * @version 2.0
 */

#ifndef _SWAPv2_TABLE_GENERATOR_H_
#define _SWAPv2_TABLE_GENERATOR_H_

#ifdef __cplusplus
extern "C"
{
#endif //__cplusplus

#ifndef _WIN

	#define SPC_INTERNAL  __attribute__((visibility("hidden")))
#else
	#define SPC_INTERNAL  
#endif

/*! SWAPv2 table generator return values */
typedef enum
{
	SWAPv2_TBLGEN_RETURN_SUCCESS =					0x00000000,		/*!< success case */
	SWAPv2_TBLGEN_RETURN_INVALID_PARAMETER =			0x80000011,		/*!< null parameter */
	SWAPv2_TBLGEN_RETURN_INVALID_KEYLEN =				0x80000012,		/*!< invalid key length */
	SWAPv2_TBLGEN_RETURN_INVALID_OTMZ_LEVEL = 		0x80000013,		/*!< invalid optimization level */
	SWAPv2_TBLGEN_RETURN_MEM_ALLOC_FAILED =			0x80000014		/*!< memory allocation failed */
} SWAPv2_TBLGEN_RETURN_VAL;

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
unsigned int SWAPv2_GenerateTable(unsigned char* Key, unsigned char KeyLen, unsigned int seed, unsigned char **Table, unsigned int *TableLen, int isEncryption);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //_SWAPv2_TABLE_GENERATOR_H_

