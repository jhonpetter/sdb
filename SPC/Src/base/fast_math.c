/** 
 * @file	fast_mathf.c
 * @brief	This file contains optimized implementations for severall basic arithmetical functions.
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

#include <stdlib.h>
#include <string.h>

#include "CryptoCore.h"
#include "CC_Constants.h"
#include "bignum.h"

#include "fast_math.h"

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
CRYPTOCORE_INTERNAL int SDRM_ll_Cmp(const BasicWord *pFirstOperand, const BasicWord *pSecondOperand, unsigned uOperandLength)
{
	pFirstOperand += uOperandLength;
	pSecondOperand += uOperandLength;

	while (uOperandLength--) {
		if (*--pFirstOperand != *--pSecondOperand)
		{
			if (*pFirstOperand < *pSecondOperand)
			{
				return -1;
			}
			else
			{
				return 1;
			}
		}
	}
	return 0;
}

/**
  * @fn			SDRM_ll_Copy
  * @brief		Just copy two large unsigned integers from one into another
  */
CRYPTOCORE_INTERNAL void SDRM_ll_Copy(BasicWord *pFirstOperand, const BasicWord *pSecondOperand, unsigned uOperandLength)
{
	while (uOperandLength--)
	{
		*pFirstOperand++ = *pSecondOperand++;
	}
}

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
CRYPTOCORE_INTERNAL void SDRM_ll_bit_RShift(IN OUT BasicWord *pOperand, IN BasicWord uOperandLength, OUT BasicWord uBits)
{
	BasicWord uLastIndex = (BasicWord)(uOperandLength - 1);
	register BasicWord t;

	while (uLastIndex--)
	{
		t = *pOperand >> uBits;
		*pOperand = t | (*(pOperand + 1) << (BASICWORD_BITS_COUNT - uBits));
		pOperand++;
	}
	*pOperand >>= uBits;
}

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
CRYPTOCORE_INTERNAL void SDRM_ll_bit_LShift(IN OUT BasicWord *pOperand, IN BasicWord uOperandLength, OUT BasicWord uBits)
{
	BasicWord uLastIndex = (BasicWord)(uOperandLength - 1);
	BasicWord t;

	pOperand += uOperandLength-1;
	while (uLastIndex--)
	{
		t = *pOperand << uBits;
		*pOperand = t | (*(pOperand - 1) >> (BASICWORD_BITS_COUNT - uBits));
		pOperand--;		
	}
	*pOperand <<= uBits;
}

/**
  * @fn			SDRM_ll_getMSW
  * @brief		Return index of most significant word.
  * 
  * @param		pOperand [in] pointer to the large integer.
  *
  * @return		The index of most significant word.
  *				-1 if passed integer actually is equal to 0.
  */
CRYPTOCORE_INTERNAL int SDRM_ll_getMSW(IN const BasicWord *pOperand, IN BasicWord uOperandLength)
{
	int nEl;
	for(nEl = uOperandLength - 1; nEl >= 0; nEl--)
	{
		if (0 != pOperand[nEl])
		{
			break;
		}
	}
	return nEl;
}

/**
  * @fn			SDRM_ll_getMSB
  * @brief		Find the leftmost non-zero bit in passed unsigned integer.
  * 
  * @param		oneWord [in] value of unsigned integer
  *
  * @return		Position of leftmost non-zero bit.
  * @warning	Actually this function returns the position of leftmost non-zero bit started from the end of the integer.
  *				For example if we considering the unsigned integer with value 0x80000000 then SDRM_ll_getMSB will return 0 as a result.
  *				Or in the case if integer has value equal t 1, then SDRM_ll_getMSB will return BASICWORD_BITS_COUNT as a result.
  */
CRYPTOCORE_INTERNAL int SDRM_ll_getMSB(IN BasicWord oneWord)
{
	register BasicWord mask = (1 << (BASICWORD_BITS_COUNT-1));
	int nPos = 0;

	if ( !oneWord )
		return BASICWORD_BITS_COUNT;

	while (!(oneWord & mask))
	{
		nPos++;
		mask >>= 1;
	}

	return nPos;
}

/**
  * @fn			SDRM_ll_bit_getBitValue
  * @brief		Return one bit value in the large integer number.
  * 
  * @param		pOperand [in] pointer to large integer
  * @param		nBit     [in] bit position in the large integer.
  *
  * @return		0 or 1 depends on actual bit value.
  */
CRYPTOCORE_INTERNAL int SDRM_ll_bit_getBitValue(IN BasicWord *pOperand, IN BasicWord nBit)
{
	BasicWord uOrdNum = nBit / BASICWORD_BITS_COUNT;
	BasicWord uBitNum = nBit % BASICWORD_BITS_COUNT;

	return (pOperand[uOrdNum] >> uBitNum) & 0x1;
}

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
CRYPTOCORE_INTERNAL int SDRM_ll_bit_getBitsValue(IN const BasicWord *pOperand, IN BasicWord uStartBit, IN BasicWord uBitsCount)
{
	int nValueLen, i;
	BasicWord uValue = 0;
	BasicWord uStartOrdNum = uStartBit / BASICWORD_BITS_COUNT;	/* number of ords */
	BasicWord uStartBitNum = uStartBit % BASICWORD_BITS_COUNT;	/* number of bits in remainder BasicWord */

	if((nValueLen = (int)(uStartBitNum + 1 - uBitsCount)) >= 0)
	{
		for(i = uStartBitNum; i >= nValueLen; i--)
		{
			uValue = (BasicWord)(((pOperand[uStartOrdNum] >> i) & 1) | (uValue << 1));
		}
	}
	else
	{
		nValueLen = uBitsCount - uStartBitNum - 1;
		for(i = uStartBitNum; i >= 0; i--)
		{
			uValue = (BasicWord)(((pOperand[uStartOrdNum] >> i) & 1) | (uValue << 1));
		}

		uStartOrdNum--;
		nValueLen = BASICWORD_BITS_COUNT - nValueLen;
		for(i = BASICWORD_BITS_COUNT - 1; i >= nValueLen; i--)
		{
			uValue = (BasicWord)(((pOperand[uStartOrdNum] >> i) & 1) | (uValue << 1));
		}
	}

	do
	{
		if(0 != (uValue & 1))
		{
			break;
		}
		uValue >>= 1;
	} while(1);

	uValue = uValue >> 1;	/* get rid of least significant bit */

	return uValue;
}

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
				OUT BasicWord *pResult)
{
	unsigned i = 1;
	register BasicWord rh;
	register BasicWord fo, so, rl;

	fo = *pFirstOperand++;
	so = *pSecondOperand++;
	_add_add_(fo,so,0,rl,rh)
	*pResult++ = rl;
	for (; i < uOperandsLength; i++)
	{
		fo = *pFirstOperand++;
		so = *pSecondOperand++;
		_add_add_(fo,so,rh,rl,rh)
		*pResult++ = rl;
	}

	return rh;
}

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
CRYPTOCORE_INTERNAL int SDRM_ll_AddCarry(IN BasicWord oneWord, IN BasicWord *pOperand, IN BasicWord uOperandLength)
{
	BasicWord	i = 1;
	register BasicWord ow = oneWord;

	if ((pOperand[0] += ow) >= ow)
	{
		return 0;
	}

	while(i < uOperandLength)
	{
		if(++pOperand[i++] != 0)
		{
			return 0;
		}
	}

	return 1;
}

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
				OUT BasicWord *pResult)
{
	register BasicWord temp, borrow = 0;

	while (uOperandsLength--)
	{
		temp = *pFirstOperand - *pSecondOperand - borrow;
		borrow = (borrow && (*pFirstOperand == *pSecondOperand)) || (*pFirstOperand < *pSecondOperand);
		*pResult++ = temp;
		pFirstOperand++;
		pSecondOperand++;
	}
	return (borrow);
}

/**
  * @fn			SDRM_ll_Mul1
  * @brief		Multiply large integer by one word.
  *				Result = oneWord*SecondOperand.
  * 
  * @param		oneWord					[in] value of first multiplayer.
  * @param		pSecondOperand			[in] pointer to large integer
  * @param		uSecondOperandsLength	[in] length of the second operand in words
  * @param		pResult					[out] pointer to result of multiplication
  *
  * @warning	Routine doesn't store the last word of multiplication result, 
  *				so we have to be carefull and take care about it after calling this function.
  */
CRYPTOCORE_INTERNAL BasicWord SDRM_ll_Mul1(IN BasicWord oneWord, 
					   IN BasicWord *pSecondOperand, BasicWord uSecondOperandsLength, 
					   IN OUT BasicWord *pResult)
{
	register BasicWord ow = oneWord;
	register BasicWord rh, op2, r;

	op2 = *pSecondOperand++;
	r = *pResult;
	_mul_add_add(op2, ow, 0, 0, r, rh)
	*pResult++ = r;
	while ( --uSecondOperandsLength )
	{
		op2 = *pSecondOperand++;
		r = *pResult;
		_mul_add_add(op2, ow, 0, rh, r, rh)
		*pResult++ = r;
	}

	return rh;
}

/**
  * @fn			SDRM_ll_Mul1
  * @brief		Multiply large integer by one word and add result to the another large integer.
  *				Result += oneWord*SecondOperand.
  * 
  * @param		oneWord  [in] value of first multiplayer.
  * @param		pSecondOperand [in] pointer to large integer
  * @param		uSecondOperandsLength [in] length of the second operand in words
  * @param		pResult [inout] pointer to result of multiplication
  *
  * @warning	Routine doesn't store the last word of multiplication result, 
  *				so we have to be carefull and take care about it after calling this function.
  */
CRYPTOCORE_INTERNAL BasicWord SDRM_ll_MulAdd1(IN BasicWord oneWord, 
						  IN BasicWord *pSecondOperand, BasicWord uSecondOperandsLength, 
						  IN OUT BasicWord *pResult)
{
	register BasicWord ow = oneWord;
	register BasicWord rh, op2, r;

	op2 = *pSecondOperand++;
	r = *pResult;
	_mul_add_add(op2, ow, r, 0, r, rh)
	*pResult++ = r;
	while (--uSecondOperandsLength)
	{
		op2 = *pSecondOperand++;
		r = *pResult;
		_mul_add_add(op2, ow, r, rh, r, rh)
		*pResult++ = r;
	}

	return rh;
}

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
					OUT BasicWord *pResult)
{
	while (uFirstOperandsLength--)
	{
		*(pResult+uSecondOperandsLength) = SDRM_ll_MulAdd1(*pFirstOperand++, pSecondOperand, uSecondOperandsLength, pResult);
		pResult++;
	}
}

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
				 OUT BasicWord *pResult)
{
	*(pResult+uSecondOperandsLength) = SDRM_ll_Mul1(*pFirstOperand++, pSecondOperand, uSecondOperandsLength, pResult);
	while (--uFirstOperandsLength)
	{
		*(pResult+uSecondOperandsLength) = SDRM_ll_MulAdd1(*pFirstOperand++, pSecondOperand, uSecondOperandsLength, pResult);
		pResult++;
	}
}

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
CRYPTOCORE_INTERNAL void SDRM_ll_Square(IN BasicWord *pOperand, IN BasicWord uOperandLength, OUT BasicWord *pResult)
{
	BasicWord i;
	BasicWord j;
	BasicWord t;
	BasicWord len;

	/* Compute the product of diagonal elements */
	for(i = 0; i < uOperandLength; i++)
	{
		BasicWord rl, rh, op;
		op = pOperand[i];
		_mul_add_add(op,op,0,0,rl,rh)
		pResult[i * 2] = rl;
		pResult[i * 2 + 1] = rh;
	}

	/* Divide the result by 2 */
	SDRM_ll_bit_RShift(pResult, (BasicWord)(uOperandLength << 1), 1);

	/* Add the half of the rest part of squaring to the half of diagonal */
	i = 0;
	j = 0;
	len = uOperandLength;
	while (--len)
	{
		t = SDRM_ll_MulAdd1(pOperand[i], pOperand+i+1, (BasicWord)len, pResult + j + 1);
		SDRM_ll_AddCarry(t, pResult+len+j+1, len+1);
		j+=2;
		i++;
	}

	/* Multiply the result by 2 */
	SDRM_ll_bit_LShift(pResult, (BasicWord)(uOperandLength << 1), 1);

	/* Restore the least significant bit */
	if((pOperand[0] & 0x1L) != 0)
	{
		pResult[0] |= 0x1L;
	}
}

/**
  * @fn			SDRM_ll_Rem
  * @brief		Compute reminder of division.
  * 
  * @warning	This is a temporary solution. It has been created mostly for testing purposes. 
  */
CRYPTOCORE_INTERNAL int SDRM_ll_Rem(IN BasicWord *pOperand, IN BasicWord uOperandLengthInBytes, 
				IN BasicWord *pModule, IN BasicWord uModuleLengthInBytes, 
				OUT BasicWord *pResult)
{
	BasicWord nWordX = DIV_BY_ORD_BYTES_COUNT(uOperandLengthInBytes);
	BasicWord nWordP;
	BasicWord *pTempResult;

	nWordX = SDRM_ll_getMSW(pOperand, nWordX) + 1;
	nWordP = SDRM_ll_getMSW(pModule, nWordX) + 1;
	
	pTempResult = calloc(nWordX+1,BASICWORD_BYTES_COUNT);
	if (!pTempResult)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	SDRM_ll_Copy(pTempResult, pOperand, nWordX);

	SDRM_DWD_Classical_REDC(pTempResult, nWordX, pModule, nWordP);
	
	SDRM_ll_Copy(pResult, pTempResult, nWordP);

	free(pTempResult);

	return 0;
}

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
CRYPTOCORE_INTERNAL int SDRM_ll_mont_Inverse(OUT BasicWord *out, IN BasicWord oneWord)
{
	/*
		t = m^(-1) mod b
		m^(-1) = t*(2-m*t) mod (b^2)

		So we are just using some simple iteration t <- t*(2-m*t) and check the condition that t*m == 1 mod b.
	*/
	BasicWord t = oneWord;
	BasicWord r = t*t;

	while (r != 1)
	{
		t = t*(2 - r);
		r = oneWord*t;

		if (!(r) && !(t))
		{
			return -1;
		}
	}

	*out = (BasicWord)(-t);

	return 0;
}

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
					  IN BasicWord inv)
{
	BasicWord lp;              /* leftmost non-zero element */
	BasicWord temp, temp_longs;
	BasicWord carry = 0;

	temp_longs = uModuleLength;
	lp = SDRM_ll_getMSW(pModule, uModuleLength) + 1;
	do
	{
		temp = inv * pFirstOperand[0];
		temp = SDRM_ll_MulAdd1(temp, pModule, lp, pFirstOperand);
		carry += SDRM_ll_AddCarry(temp, pFirstOperand+uModuleLength, temp_longs);
		pFirstOperand++;
	} while(--temp_longs);

	while(carry)
	{
		if(SDRM_ll_Sub(pFirstOperand, pModule, uModuleLength, pFirstOperand))
			carry--;
	}

	while(SDRM_ll_Cmp(pFirstOperand, pModule, uModuleLength) >= 0)
	{
		SDRM_ll_Sub(pFirstOperand, pModule, uModuleLength, pFirstOperand);
	}
}

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
						OUT BasicWord *pResult)
{
	pResult[uModuleLength * 2] = 0;

	/* Compute square */
	SDRM_ll_Square(pFirstOperand, uModuleLength, pResult);
	/* Compute the modulo by the Montgomery */
	SDRM_ll_mont_Rem(pResult, pModule, uModuleLength, Inv);

	/* Note: The next step for making toolkit faster is to redesign Montgomery functions and remove all memory allocation 
	   and copying from there. That means that exponentiation routine should be redesigne as well. */
	memcpy(pFirstOperand, pResult + uModuleLength, MUL_BY_ORD_BYTES_COUNT(uModuleLength));
	return CRYPTO_SUCCESS;
}

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
					 OUT BasicWord *pResult)
{
	BasicWord P_longs;             /* number of longs in P, X and Y */
	BasicWord lx, ly;              /* leftmost non-zero elements */
	BasicWord *XY;                 /* pointer to product result */

	P_longs = DIV_BY_ORD_BYTES_COUNT(uModuleLengthInBytes);
	XY = (BasicWord*)calloc(2 * P_longs + 1, BASICWORD_BYTES_COUNT);
	if(!XY)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	/* Find leftmost non-zero elements */
	lx = SDRM_ll_getMSW(pFirstOperand, P_longs) + 1;
	ly = SDRM_ll_getMSW(pSecondOperand, P_longs) + 1;
	/* Compute the product of FirstOperand and SecondOperand */
	SDRM_ll_MulAdd(pFirstOperand, lx, pSecondOperand, ly, XY);
	/* Compute the modulo by the Montgomery */
	SDRM_ll_mont_Rem(XY, pModule, P_longs, Inv);

	/* Note: The next step for making toolkit faster is to redesign Montgomery functions and remove all memory allocation 
	   and copying from there. That means that exponentiation routine should be redesigne as well. */
	memcpy(pResult, XY + P_longs, uModuleLengthInBytes);
	free(XY);
	return CRYPTO_SUCCESS;
}

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

#define _win_pval(i) (BasicWord*)(temp_1 + (i) * uOrdsP)
CRYPTOCORE_INTERNAL int SDRM_ll_ExpMod( IN BasicWord *pBase, IN BasicWord uBaseLengthInBytes, 
					IN BasicWord *pExponent, IN BasicWord uExponentLengthInBytes,
					IN BasicWord *pModule, IN BasicWord uModuleLengthInBytes, 
					OUT BasicWord *pResult)
{
	int nStatus = CRYPTO_SUCCESS;
	BasicWord *temp_1, inv;
	BasicWord *m_temp, *m_sq;
	int n_mem, win_len;
	BasicWord uOrdsY, uOrdsP;
	int i, j, k, eb = 0;
	BasicWord nIndex;
	int ly;
	/* The values of num_squar array given below represents the lengths of particular window values in bits */
	/* We have to take into account that we store only odd values. */
	/* window values  -> 1, 3, 5, 7, 9, 11, 13, 15, 17, 19, etc... */
	/* num_squar	  -> 1, 2, 3, 3, 4,  4,  4,  4,  5,  5, etc... */
	int num_squar[32] = {1, 2, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5,
						 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,};

	uOrdsY = DIV_BY_ORD_BYTES_COUNT(uExponentLengthInBytes);
	uOrdsP = DIV_BY_ORD_BYTES_COUNT(uModuleLengthInBytes);
	/* Find the leftmost non-zero element of modulo */
	if(-1 == SDRM_ll_getMSW(pModule, uOrdsP))
		return CRYPTO_INVALID_ARGUMENT;
	/* Find the leftmost non-zero element of exponent */
	ly = SDRM_ll_getMSW(pExponent, uOrdsY);

	/* if exponent equal to 0 result is 1 */
	if(-1 == ly)
	{
		memset(pResult, 0, uModuleLengthInBytes);
		pResult[0] = 1;
		return CRYPTO_SUCCESS;
	}

	/* Find the leftmost non-zero bit in this element */
	eb = SDRM_ll_getMSB(pExponent[ly]);

	/* Choose window length */
	k = BASICWORD_BITS_COUNT * (ly + 1) - eb - 1;
	if(k < 512)
	{
		win_len = 4;
	}
	else if((k >= 512) && (k < 1024))
	{
		win_len = 5;
	}
	else
	{ /* for any k >= 1024 */
		win_len = 6;
	}

	/* Obtain number of precomputed elements */
	n_mem = (1 << (win_len - 1)) + 1;
	/* Allocate storage for precomputetd values */
	temp_1 = (BasicWord*)calloc((n_mem + 1) * uOrdsP, BASICWORD_BYTES_COUNT);
	if (!temp_1)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	/* Allocate temporary storages */
	m_temp = (BasicWord*)calloc(2 * uOrdsP + 1, BASICWORD_BYTES_COUNT);
	if (!m_temp)
	{
		free(temp_1);
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}
	m_sq = (BasicWord*)malloc(2 * uModuleLengthInBytes + BASICWORD_BYTES_COUNT);
	if (!m_sq)
	{
		free(temp_1);
		free(m_temp);
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	do
	{
		/* Convert Base to Montgomery form */
		inv = *pModule;
		if (SDRM_ll_mont_Inverse(&inv, inv) != 0)
		{
			nStatus = CRYPTO_INVERSE_NOT_EXIST;
			break;
		}
		/* Move n up "mlen" words into a */
		/* Actually we obtain X*R where R is Montgomery reduction coefficient */
		memcpy(m_temp + uOrdsP, pBase, uBaseLengthInBytes);

		/* Do the division - dump the quotient in the high-order words */
		if((nStatus = SDRM_ll_Rem(m_temp, (BasicWord)(uBaseLengthInBytes + uModuleLengthInBytes), pModule, uModuleLengthInBytes, temp_1)) != CRYPTO_SUCCESS)
		{
			break;
		}

		/* After this operation we will obtain X*R mod P */
		memcpy(m_temp, temp_1, uModuleLengthInBytes);

		/* Initialization */
		/* Compute X^2*R mod P */
		SDRM_ll_mont_Square(m_temp, pModule, uOrdsP, inv, m_sq);
		memcpy(_win_pval(n_mem), m_temp, uModuleLengthInBytes);

		/* We have to calculate X^3, X^5 and so on ... */
		/* For making that we just use previously calculated value of X^2 and use it as multiplayer consecutively. */
		/* element (0) <- X*R mod P */
		/* element (1) <- X^3*R = element (0) * X^2*R mod P */
		/* element (2) <- X^5*R = element (1) * X^2*R mod P */
		/* element (3) <- X^7*R = element (2) * X^2*R mod P */
		/* element (4) <- ... */
		for(i = 1; i < n_mem; i++)
		{
			SDRM_ll_mont_Mul(_win_pval(i - 1), _win_pval(n_mem), pModule, uModuleLengthInBytes, inv, _win_pval(i));
		}
		
		/* OK, now let compute R mod P */
		memset(m_temp, 0, 2 * uModuleLengthInBytes + 1);
		m_temp[uOrdsP] = 1;
		if((nStatus = SDRM_ll_Rem(m_temp, (BasicWord)(uModuleLengthInBytes + BASICWORD_BYTES_COUNT), pModule, uModuleLengthInBytes, m_temp)) != CRYPTO_SUCCESS)
			break;

		/* Compute the exponent */
		for(i = k; i >= win_len-1; )
		{
			/* Note: I don't like this solution, but it was easy and from that point of view was suitable for short development cycle. 
			   During further refactoring exponent bits processing should be changed in a way that makes possible to perform
			   all computations inside of the one cycle. See some additional related comments right after the body of this cycle.*/

			/* Find next suitable bits for computations */
			nIndex = (BasicWord)SDRM_ll_bit_getBitsValue(pExponent, (BasicWord)i, (BasicWord)win_len);

			/* Square the intermediate result */
			for(j = 0; j < num_squar[nIndex]; j++)
			{
				SDRM_ll_mont_Square(m_temp, pModule, uOrdsP, inv, m_sq);
			}

			/* Multiply with the precomputed data */
			SDRM_ll_mont_Mul(m_temp, _win_pval(nIndex), pModule, uModuleLengthInBytes, inv, m_temp);

			/* Square (win_len - num_squar) times */
			for(j = 0 ; j < win_len - num_squar[nIndex]; j++)
			{
				SDRM_ll_mont_Square(m_temp, pModule, uOrdsP, inv, m_sq);
			}

			i -= win_len;

			/* perform squering till first nonzero bit */
			while((i >= win_len - 1) && !SDRM_ll_bit_getBitValue(pExponent, (BasicWord)i))
			{
				SDRM_ll_mont_Square(m_temp, pModule, uOrdsP, inv, m_sq);
				i--;
			}
		}

		/* Note: Actually it would be batter to perform remeined last bits processing inside of the exponent computation main cycle.
		   So the next refactoring step is to modify this routine and make things in that way. */

		/* if we still have some bit(s) ... */
		/* perform squering till first nonzero bit */
		while((i >= 0) && !SDRM_ll_bit_getBitValue(pExponent, (BasicWord)i))
		{
			SDRM_ll_mont_Square(m_temp, pModule, uOrdsP, inv, m_sq);
			i--;
		}

		/* if we still have some nonzero bit(s) ... */
		if(i >= 0)
		{
			nIndex = (BasicWord)SDRM_ll_bit_getBitsValue(pExponent, (BasicWord)i, (BasicWord)(i + 1));
			for(j = 0; j < num_squar[nIndex]; j++)
			{
				SDRM_ll_mont_Square(m_temp, pModule, uOrdsP, inv, m_sq);
			}

			/* Multiply with precomputed data*/
			SDRM_ll_mont_Mul(m_temp, _win_pval(nIndex), pModule, uModuleLengthInBytes, inv, m_temp);

			/* Square (win_len - num_squar) times */
			for(j = 0 ; j <= i - num_squar[nIndex]; j++)
			{
				SDRM_ll_mont_Square(m_temp, pModule, uOrdsP, inv, m_sq);
			}
		}

		/* Convert the result out of Montgomery form */
		SDRM_ll_mont_Rem(m_temp,  pModule, uOrdsP, inv);
		memcpy(pResult, m_temp + uOrdsP, uModuleLengthInBytes);
		/* This is the tricky place :) Actually we have (X*R+R) mod P. */
		/* So we just need to remove that additional R */
		pResult[0]--;

		break;	/* always break this loop */
	} while(0);

	free(temp_1);
	free(m_temp);
	free(m_sq);

	return nStatus;
}
