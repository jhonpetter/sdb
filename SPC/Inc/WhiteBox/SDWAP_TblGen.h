/**
 * @file	SDWAP_TblGen.h
 * @brief	Dynamic white box AES table generation module for SSA(Samsung Security Architecture)
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


/**
 * @interface	SWPAv2_TblGen
 * @brief		table generator of SDWAP(Samsung Dynamic Whitebox AES Project Version 2)
 *
 * @par Features :
 * # Functionality1 : table generator of SDWAP
 * @date 2012-11-15
 * @version 1.0
 */

#ifndef _SDWAP_TABLE_GENERATOR_H_
#define _SDWAP_TABLE_GENERATOR_H_

#ifdef __cplusplus
extern "C"
{
#endif //__cplusplus

#ifndef _WIN

	#define SPC_INTERNAL  __attribute__((visibility("hidden")))
#else
	#define SPC_INTERNAL  
#endif


/*! SDWAP table generator return values */
typedef enum
{
	SDWAP_TBLGEN_RETURN_SUCCESS =					0x00000000,		/*!< success case */
	SDWAP_TBLGEN_RETURN_INVALID_PARAMETER =			0x80000011,		/*!< null parameter */
	SDWAP_TBLGEN_RETURN_INVALID_KEYLEN =				0x80000012,		/*!< invalid key length */
	SDWAP_TBLGEN_RETURN_INVALID_OTMZ_LEVEL = 		0x80000013,		/*!< invalid optimization level */
	SDWAP_TBLGEN_RETURN_MEM_ALLOC_FAILED =			0x80000014		/*!< memory allocation failed */
} SDWAP_TBLGEN_RETURN_VAL;

typedef enum
{
	SDWAP_TBL_TBOX		= 0x00,
	SDWAP_TBL_KEYLOOKUP = 0x01
}SDWAP_TBLGEN_TYPE;

typedef enum
{
	SDWAP_DECRYPTION	= 0x00,
	SDWAP_ENCRYPTION	= 0x01
}SDWAP_CRYPTO_MODE;

/**
 * @fn		unsigned int SDWAP_GenerateTable(unsigned char* Key, unsigned char KeyLen, unsigned int seed, unsigned char **Table, unsigned int *TableLen, int isEncryption, unsigned int OptimizLev)
 * @brief	derivate look-up table from given key
 *
 * @param	[in] Key			user key (cipher key)
 * @param	[in] KeyLen			byte-length of cipher key
 * @param	[in] seed			random seed
 * @param	[out] Table			look-up table for SDWAP
 * @param	[out] TableLen		byte-length of look-up table
 * @param	[in] isEncryption	flag ordering encryption or decryption
 * @return	SDWAP_TBLGEN_RETURN_VAL
 */
unsigned int SDWAP_GenerateTable(unsigned char* Key, unsigned char KeyLen, unsigned int seed, unsigned char **Table, unsigned int *TableLen, int isEncryption, int TableType);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //_SDWAP_TABLE_GENERATOR_H_

