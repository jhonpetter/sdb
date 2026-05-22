/**
 * @file	SDWAP.h
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


/**
 * @interface	SDWAP
 * @brief		encryption/decryption processing module of SDWAP(Samsung Dynamic Whitebox AES Project Version 2)
 *
 * @par Features :
 * # Functionality1 : encryption/decryption processing module of SDWAP
 * @date 2012-01-10
 * @version 1.0
 */

#ifndef _SAMSUNG_DYNIMIC_WHITE_BOX_AES_PROJECT_H_
#define _SAMSUNG_DYNIMIC_WHITE_BOX_AES_PROJECT_H_

#ifdef __cplusplus
extern "C"
{
#endif //__cplusplus

#ifndef _WIN

	#define SPC_INTERNAL  __attribute__((visibility("hidden")))
#else
	#define SPC_INTERNAL  
#endif

/*! SDWAP return values */
typedef enum
{
	SDWAP_RETURN_SUCCESS =					0x00000000,		/*!< success case */
	SDWAP_RETURN_INVALID_PARAMETER =			0x80000001,		/*!< null parameter */
	SDWAP_RETURN_INVALID_TBLSIZE =			0x80000002,		/*!< invalid table size */
	SDWAP_TBLGEN_INVALID_OTMZ_LEVEL = 		0x80000003		/*!< invalid optimization level */
} SDWAP_RETURN_VAL;

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
SPC_INTERNAL SDWAP_RETURN_VAL SDWAP_Process(unsigned char *Table, unsigned int TableLen, unsigned char* in, unsigned char* out, unsigned int isEncryption);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //_SAMSUNG_WHITE_BOX_AES_PROJECT_H_

