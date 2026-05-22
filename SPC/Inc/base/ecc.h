/**
 * \file	ecc.h
 * @brief	ecc library based on big number
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jiyoung Moon
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/05/03
 * Note : optimized by Jiyoung Moon & Jisoon Park, August,2006.
 */

#ifndef _ECC_H
#define _ECC_H

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include "CryptoCore.h"
#include "bignum.h"
#include "sha1.h"

////////////////////////////////////////////////////////////////////////////
// Constants
////////////////////////////////////////////////////////////////////////////
#define	SDRM_MAX_DIMENSION_ECC	256
#define SDRM_SIZE_OF_ECC_KEY	(SDRM_SIZE_OF_DWORD * SDRM_ECC_BN_BUFSIZE)

////////////////////////////////////////////////////////////////////////////
// Macros for ECC
////////////////////////////////////////////////////////////////////////////
#define SDRM_EC_FREE(X)			if (X) {free(X);}

#define SDRM_EC_SET_ZERO(A)		do {																						\
									memset((A), 0, sizeof(SDRM_EC_POINT));						\
									(A)->IsInfinity = 0;																	\
									A->x  = SDRM_BN_Alloc((cc_u8*)A     + sizeof(SDRM_EC_POINT), SDRM_ECC_BN_BUFSIZE);		\
									A->y  = SDRM_BN_Alloc((cc_u8*)A->x  + SDRM_ECC_ALLOC_SIZE,   SDRM_ECC_BN_BUFSIZE);		\
									A->z  = SDRM_BN_Alloc((cc_u8*)A->y  + SDRM_ECC_ALLOC_SIZE,   SDRM_ECC_BN_BUFSIZE);		\
									A->z2 = SDRM_BN_Alloc((cc_u8*)A->z  + SDRM_ECC_ALLOC_SIZE,   SDRM_ECC_BN_BUFSIZE);		\
									A->z3 = SDRM_BN_Alloc((cc_u8*)A->z2 + SDRM_ECC_ALLOC_SIZE,   SDRM_ECC_BN_BUFSIZE);		\
								} while(0)

#define SDRM_EC_CLR(A)			SDRM_EC_SET_ZERO(A)

#define SDRM_ECC_Clr(A)		do {													\
									SDRM_BN_Clr((A)->ECC_p);						\
									SDRM_BN_Clr((A)->ECC_A);						\
									SDRM_BN_Clr((A)->ECC_b);						\
									SDRM_BN_Clr((A)->ECC_n);						\
									SDRM_BN_Clr((A)->PRIV_KEY);						\
									EC_Clr((A)->ECC_G);								\
									EC_Clr((A)->PUBLIC_KEY);						\
								} while(0)

#define SDRM_ECC_FREE(X)		do {																\
									if ((X)) {														\
										SDRM_BN_FREE(X->ECC_a);										\
										SDRM_EC_FREE(X->ECC_G);										\
										SDRM_EC_FREE(X->PUBLIC_KEY);								\
										SDRM_EC_FREE(X);											\
									}																\
								} while(0)

#define SDRM_EC_COPY(A, B)		do {																\
									(A)->IsInfinity = (B)->IsInfinity;								\
									SDRM_BN_Copy((A)->x, (B)->x);									\
									SDRM_BN_Copy((A)->y, (B)->y);									\
									SDRM_BN_Copy((A)->z, (B)->z);									\
									SDRM_BN_Copy((A)->z2, (B)->z2);									\
									SDRM_BN_Copy((A)->z3, (B)->z3);									\
								} while(0)


////////////////////////////////////////////////////////////////////////////
// Function Prototypes
////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

///// ECC 보조함수
/*
 * @fn		SDRM_ECC_Init	
 * @brief	return SDRM_EC_POINT structure
 *
 * @return	address of allocate structure
 * \n		NULL	if memory allocation is failed
 */
CRYPTOCORE_INTERNAL SDRM_EC_POINT *SDRM_ECC_Init(void);

/*
 * @fn		SDRM_CURVE_Init
 * @brief	return SDRM_ECC_CTX structure
 *
 * @return	address of allocate structure
 * \n		NULL	if memory allocation is failed
 */
CRYPTOCORE_INTERNAL SDRM_ECC_CTX *SDRM_CURVE_Init(void);

///// ECC Point 연산함수
/*
 * @fn		SDRM_CTX_EC_Chain
 * @brief	Chain 함수
 *
 * signed window method	:	size of window = 4
 * chain for addition/subtraction of k Using sliding window method
 * @param	chain						[out]destination
 * @param	L_Src						[in]byte-length of chain
 * @param	Len_Src						[in]number of doubling in chain
 * @param	k							[in]source
 * @param	window_size					[in]size of window
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_INVALID_ARGUMENT		if given value is incorrect
 */
CRYPTOCORE_INTERNAL int SDRM_CTX_EC_Chain(signed char *chain, cc_u32 *L_Src, cc_u32 *Len_Src, SDRM_BIG_NUM *k, int window_size);

/*
 * @fn		SDRM_CTX_EC_kP
 * @brief	get EC_Dst = kP by Montgomery Method
 *
 * @param	ctx							[in]ecc context
 * @param	EC_Dst						[out]destination
 * @param	EC_Src						[in]first element(P)
 * @param	k							[in]second element(k)
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_INVALID_ARGUMENT		if the arguemnt represents a minus value
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 * \n		CRYPTO_INFINITY_INPUT		if the argument is a infinity value
 */
CRYPTOCORE_INTERNAL int SDRM_CTX_EC_kP(SDRM_ECC_CTX *ctx, SDRM_EC_POINT* EC_Dst, SDRM_EC_POINT *EC_Src, SDRM_BIG_NUM *k);

/*	
 * @fn		SDRM_CTX_EC_2kP
 * @brief	get EC_Dst = k1*C1 + k2*C2
 *
 * @param	ctx							[in]ecc context
 * @param	EC_Dst						[out]destination
 * @param	k1							[in]first element(k1)
 * @param	EC_Src1						[in]second element(C1)
 * @param	k2							[in]third element(k2)
 * @param	EC_Src2						[in]fourth element(C2)
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_INVALID_ARGUMENT		if the arguemnt represents a minus value
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 * \n		CRYPTO_INFINITY_INPUT		if the argument is a infinity value
 */
CRYPTOCORE_INTERNAL int SDRM_CTX_EC_2kP(SDRM_ECC_CTX *ctx, SDRM_EC_POINT *EC_Dst, SDRM_BIG_NUM *k1, SDRM_EC_POINT *EC_Src1, SDRM_BIG_NUM *k2, SDRM_EC_POINT *EC_Src2);

///// Functions of Converting Coordingate
/*
 * @fn		SDRM_Mont_Jm2Jc
 * @brief	좌표변환 1
 *			Modified Jacobian  =>  Chundnovsky Jacobian 
 *			(A->y)  <= (A->y)/2
 *			(A->z2) <= (A->z)^2
 *			(A->z3) <= (A->z)^3
 *
 * @param	EC_Dst			[out]destination
 * @param	new_a			[in]first element
 * @param	new_b			[in]second element
 * @param	Mont			[in]montgomery context
 *
 * @return	CRYPTO_SUCCESS	if no error is occured
 * \n		CRYPTO_ERROR	if evaluation is failed
 */
CRYPTOCORE_INTERNAL int SDRM_Mont_Jm2Jc(SDRM_EC_POINT *EC_Dst, SDRM_BIG_NUM *new_a, SDRM_BIG_NUM *new_b, SDRM_BIG_MONT *Mont);

/*
 * @fn		SDRM_Mont_Jc2Jm
 * @brief	좌표변환 2
 *			Chundnovsky Jacobian  =>  Modified Jacobian
 *			(A->y)  <= 2*(A->y)
 *			(A->z2) <= new_a*(A->z)^4
 * @param	A				[out]destination
 * @param	new_a			[in]first element
 * @param	new_b			[in]second element
 * @param	Mont			[in]montgomery context
 *
 * @return	CRYPTO_SUCCESS	if no error is occured
 * \n		CRYPTO_ERROR	if evaluation is failed
 */
CRYPTOCORE_INTERNAL int SDRM_Mont_Jc2Jm(SDRM_EC_POINT *A, SDRM_BIG_NUM *new_a, SDRM_BIG_NUM *new_b, SDRM_BIG_MONT *Mont);

/*
 * @fn		SDRM_CTX_EC_Add_Jc
 * @brief	Chundnovsky Jacobian coordinate
 *			using montgomery (A = B + C)
 *
 * @param	EC_Dst						[out]destination(A)
 * @param	EC_Src1						[in]first element(B)
 * @param	EC_Src2						[in]second element(C)
 * @param	new_a						[in]ECC_A's montgomery value
 * @param	new_b						[in]ECC_B's montgomery value
 * @param	Mont						[in]montgomery context
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_ERROR				if evaluation is failed
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 */
CRYPTOCORE_INTERNAL int SDRM_CTX_EC_Add_Jc(SDRM_EC_POINT* EC_Dst, SDRM_EC_POINT *EC_Src1, SDRM_EC_POINT *EC_Src2, SDRM_BIG_NUM *new_a, SDRM_BIG_NUM *new_b, SDRM_BIG_MONT *Mont);

/*
 * @fn		SDRM_CTX_EC_Double_Jc	
 * @brief	Chundnovsky Jacobian coordinate
 *			montgomery (A = 2B)
 *
 * @param	EC_Dst						[out]destination(A)
 * @param	EC_Src1						[in]first element(B)
 * @param	new_a						[in]ECC_A's montgomery value
 * @param	new_b						[in]ECC_B's montgomery value
 * @param	Mont						[in]montgomery context
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_ERROR				if evaluation is failed
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 */
CRYPTOCORE_INTERNAL int SDRM_CTX_EC_Double_Jc(SDRM_EC_POINT *EC_Dst, SDRM_EC_POINT *EC_Src1, SDRM_BIG_NUM *new_a, SDRM_BIG_NUM *new_b, SDRM_BIG_MONT *Mont);

/*
 * @fn		SDRM_CTX_EC_Double_Jm
 * @brief	Modified Jacobian coordinate
 *			montgomery (A = 2B)
 *
 * @param	EC_Dst						[out]destination(A)
 * @param	EC_Src1						[in]first element(B)
 * @param	new_a						[in]ECC_A's montgomery value
 * @param	new_b						[in]ECC_B's montgomery value
 * @param	Mont						[in]montgomery context
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_ERROR				if evaluation is failed
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 */
CRYPTOCORE_INTERNAL int SDRM_CTX_EC_Double_Jm(SDRM_EC_POINT *EC_Dst, SDRM_EC_POINT *EC_Src1, SDRM_BIG_NUM *new_a, SDRM_BIG_NUM *new_b, SDRM_BIG_MONT *Mont);

#ifdef __cplusplus
}
#endif

#endif // _ECC_H

/***************************** End of File *****************************/
