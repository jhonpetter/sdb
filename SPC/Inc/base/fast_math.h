/** 
 * @file	fast_math.h
 * @brief	Header file for fast_mathf.c
 *
 * [Optional] Detail description (major features, interface description, flow of control, and so on)
 * @see	[Optional] Related information

 * Copyright 2008 by Samsung Electronics, Inc.,
 * 
 * This software is the confidential and proprietary information
 * of Samsung Electronics, Inc. ("Confidential Information").  You
 * shall not disclose such Confidential Information and shall use
 * it only in accordance with the terms of the license agreement
 * you entered into with Samsung.
 * 
 * \internal
 * Author : Karen Ispiryan
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2008/08/28
*/

#ifndef FAST_MATH_H
#define FAST_MATH_H

#include "CC_Type.h"

#ifndef _OP64_NOTSUPPORTED
#	define ORD_32
#else
#	define ORD_16
#endif	//_OP64_NOTSUPPORTED

/* when we have only 16 bit processor available */
#ifdef ORD_16

typedef cc_u16 BasicWord;
typedef cc_u32 BasicDWord;

#define DIV_BY_ORD_BYTES_COUNT(x)		(BasicWord)((x) >> 1)
#define MUL_BY_ORD_BYTES_COUNT(x)		(BasicWord)((x) << 1)

#define BASICWORD_BITS_COUNT	16
#define BASICWORD_BYTES_COUNT	2
#define MAXDIGIT	(BasicWord)(0xFFFF)

#endif

/* when we have 32 bit processor available and also have 64 bit data type */
#ifdef ORD_32

typedef cc_u32 BasicWord;
typedef cc_u64 BasicDWord;

#define DIV_BY_ORD_BYTES_COUNT(x)		(BasicWord)((x) >> 2)
#define MUL_BY_ORD_BYTES_COUNT(x)		(BasicWord)((x) << 2)

#define BASICWORD_BITS_COUNT	32
#define BASICWORD_BYTES_COUNT	4
#define MAXDIGIT	(BasicWord)(0xFFFFFFFF)

#endif

#define LOW_WORD(a)		(BasicWord) (a)
#define HIGH_WORD(a)	(BasicWord)((a) >> BASICWORD_BITS_COUNT)

/* In our implementation we are using assumption that DWord data type available for using. */
/* If for some reasons it isn't so, then we just need to redefine rhe following two macros in appropriate way 
 * and functions will work properly.
 */
#define _add_add_(aw1,aw2,aw3,rwl,rwh) {													\
											BasicDWord dw = (BasicDWord)(aw1)+(aw2)+(aw3);	\
											rwl = LOW_WORD(dw);								\
											rwh = HIGH_WORD(dw);							\
										}

#define _mul_add_add(wm1,wm2,aw1,aw2,rwl,rwh) {																\
													BasicDWord dw = (BasicDWord)(wm1)*(wm2)+(aw1)+(aw2);	\
													rwl = LOW_WORD(dw);										\
													rwh = HIGH_WORD(dw);									\
												}

#define IN
#define OUT

/*===========================================================================================================*/

/**
  * @fn			SDRM_ll_Cmp
  * @brief		Compare two large unsigned integers
  * 
  * @param		pFirstOperand [in] the first operand
  * @param		pSecondOperand [in] the second operand
  *
  * @return		0 if they are equal
  *				1 if first bigger then second
  *				-1 if the seond one is bigger then first
  */
CRYPTOCORE_INTERNAL int SDRM_ll_Cmp(const BasicWord *pFirstOperand, const BasicWord *pSecondOperand, unsigned uOperandLength);

/**
  * @fn			SDRM_ll_Copy
  * @brief		Just copy two large unsigned integers from one into another
  */
CRYPTOCORE_INTERNAL void SDRM_ll_Copy(BasicWord *pFirstOperand, const BasicWord *pSecondOperand, unsigned uOperandLength);

/**
  * @fn			SDRM_ll_bit_RShift
  * @brief		Shift large unsigned integer to the right by uBits
  * 
  * @param		pOperand [inout] pointer to the operand to be shifted
  *
  * @return		Nothing
  * @warning	We have to be careful when using this function because it modifies uOperandLength+1 words 
  *				that is by 1 word bigger then operand original size.
  *				WWW....Operand...WWW|W <- it modifies the word immediately after the last one of passed operand.
  */
CRYPTOCORE_INTERNAL void SDRM_ll_bit_RShift(IN OUT BasicWord *pOperand, IN BasicWord uOperandLength, OUT BasicWord uBits);

/**
  * @fn			SDRM_ll_bit_LShift
  * @brief		Shift large unsigned integer to the left by uBits
  * 
  * @param		pOperand [inout] pointer to the operand to be shifted
  *
  * @return		Nothing
  * @warning	We have to be careful when using this function because it modifies uOperandLength+1 words 
  *				that is by 1 word bigger then operand original size.
  *				It modifies the word immediately prior to the first one of passed operand -> W|WWW....Operand...WWW
  */
CRYPTOCORE_INTERNAL void SDRM_ll_bit_LShift(IN OUT BasicWord *pOperand, IN BasicWord uOperandLength, OUT BasicWord uBits);

/**
  * @fn			SDRM_ll_getMSW
  * @brief		Return index of most significant word.
  * 
  * @param		pOperand [in] pointer to the large integer.
  *
  * @return		The index of most significant word.
  *				-1 if passed integer actually is equal to 0.
  */
CRYPTOCORE_INTERNAL int SDRM_ll_getMSW(IN const BasicWord *pOperand, IN BasicWord uOperandLength);

/**
  * @fn			SDRM_ll_Add
  * @brief		Add two large unsigned integers that have the same size.
  * 
  * @param		pFirstOperand  [in] pointer to first large integer
  * @param		pSecondOperand [in] pointer to second large integer
  * @param		uOperandsLength [in] length of the operands in words
  * @param		pResult [out] pointer to result of subtraction
  *
  * @return		carry if so.
  */
CRYPTOCORE_INTERNAL int SDRM_ll_Add(IN const BasicWord *pFirstOperand, 
				IN const BasicWord *pSecondOperand, 
				IN BasicWord uOperandsLength, 
				OUT BasicWord *pResult);

/**
  * @fn			SDRM_ll_AddCarry
  * @brief		Add carry to large unsigned integer
  * 
  * @param		oneWord  [in] value of carry
  * @param		pOperand [inout] pointer to large integer
  * @param		uOperandLength [in] length of the second operand in words
  *
  * @return		carry if so.
  */
CRYPTOCORE_INTERNAL int SDRM_ll_AddCarry(IN BasicWord oneWord, IN BasicWord *pOperand, IN BasicWord uOperandLength);

/**
  * @fn			SDRM_ll_Sub
  * @brief		Subtract two large unsigned integers that have the same size.
  * 
  * @param		pFirstOperand	[in] pointer to first large integer
  * @param		pSecondOperand	[in] pointer to second large integer
  * @param		uOperandsLength [in] length of the operands in words
  * @param		pResult			[out] pointer to result of subtraction
  *
  * @return		borrow if so.
  */
CRYPTOCORE_INTERNAL int SDRM_ll_Sub(IN const BasicWord *pFirstOperand, 
				IN const BasicWord *pSecondOperand, 
				IN BasicWord uOperandsLength, 
				OUT BasicWord *pResult);

/**
  * @fn			[Mandatory] Function name
  * @brief		[Mandatory] Description of major features and algorithms
  * 
  * @param		[Optional] description of parameters ([one among in, out, inout])
  *
  * @return		[Optional] description of return value
  * @warning	[Optional] constraints or notices
  * @see		[Optional] related information
  */
CRYPTOCORE_INTERNAL void SDRM_ll_MulAdd(IN BasicWord *pFirstOperand, IN BasicWord uFirstOperandsLength, 
					IN BasicWord *pSecondOperand, IN BasicWord uSecondOperandsLength, 
					OUT BasicWord *pResult);

/**
  * @fn			[Mandatory] Function name
  * @brief		[Mandatory] Description of major features and algorithms
  * 
  * @param		[Optional] description of parameters ([one among in, out, inout])
  *
  * @return		[Optional] description of return value
  * @warning	[Optional] constraints or notices
  * @see		[Optional] related information
  */
CRYPTOCORE_INTERNAL void SDRM_ll_Mul(IN BasicWord *pFirstOperand, IN BasicWord uFirstOperandsLength, 
				 IN BasicWord *pSecondOperand, IN BasicWord uSecondOperandsLength, 
				 OUT BasicWord *pResult);

/**
  * @fn			[Mandatory] Function name
  * @brief		[Mandatory] Description of major features and algorithms
  * 
  * @param		[Optional] description of parameters ([one among in, out, inout])
  *
  * @return		[Optional] description of return value
  * @warning	[Optional] constraints or notices
  * @see		[Optional] related information
  */
CRYPTOCORE_INTERNAL void SDRM_ll_Square(IN BasicWord *pOperand, IN BasicWord uOperandLength, OUT BasicWord *pResult);

/**
  * @fn			[Mandatory] Function name
  * @brief		[Mandatory] Description of major features and algorithms
  * 
  * @param		[Optional] description of parameters ([one among in, out, inout])
  *
  * @return		[Optional] description of return value
  * @warning	[Optional] constraints or notices
  * @see		[Optional] related information
  */
CRYPTOCORE_INTERNAL void SDRM_ll_mont_Rem(IN OUT BasicWord *pFirstOperand, 
					  IN BasicWord *pModule, 
					  IN BasicWord uModuleLength, 
					  IN BasicWord inv);

/**
  * @fn			[Mandatory] Function name
  * @brief		[Mandatory] Description of major features and algorithms
  * 
  * @param		[Optional] description of parameters ([one among in, out, inout])
  *
  * @return		[Optional] description of return value
  * @warning	[Optional] constraints or notices
  * @see		[Optional] related information
  */
CRYPTOCORE_INTERNAL int SDRM_ll_mont_Square(IN BasicWord *pFirstOperand, 
						IN BasicWord *pModule, 
						IN BasicWord uModuleLength, 
						IN BasicWord Inv, 
						OUT BasicWord *pResult);

/**
  * @fn			[Mandatory] Function name
  * @brief		[Mandatory] Description of major features and algorithms
  * 
  * @param		[Optional] description of parameters ([one among in, out, inout])
  *
  * @return		[Optional] description of return value
  * @warning	[Optional] constraints or notices
  * @see		[Optional] related information
  */
CRYPTOCORE_INTERNAL int SDRM_ll_mont_Mul(IN BasicWord *pFirstOperand, 
					 IN BasicWord *pSecondOperand, 
					 IN BasicWord *pModule, 
					 IN BasicWord uModuleLengthInBytes, 
					 IN BasicWord Inv, 
					 OUT BasicWord *pResult);

/**
  * @fn			[Mandatory] Function name
  * @brief		[Mandatory] Description of major features and algorithms
  * 
  * @param		[Optional] description of parameters ([one among in, out, inout])
  *
  * @return		[Optional] description of return value
  * @warning	[Optional] constraints or notices
  * @see		[Optional] related information
  */
CRYPTOCORE_INTERNAL int SDRM_ll_ExpMod( IN BasicWord *pBase, IN BasicWord uBaseLengthInBytes, 
					IN BasicWord *pExponent, IN BasicWord uExponentLengthInBytes,
					IN BasicWord *pModule, IN BasicWord uModuleLengthInBytes, 
					OUT BasicWord *pResult);

#endif /*FAST_MATH_H*/
