/**
 * \file	ecc.c
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

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include "ecc.h"

////////////////////////////////////////////////////////////////////////////
// Functions
////////////////////////////////////////////////////////////////////////////
/*
 * @fn		SDRM_ECC_Init
 * @brief	return SDRM_EC_POINT structure
 *
 * @return	address of allocate structure
 * \n		NULL	if memory allocation is failed
 */
CRYPTOCORE_INTERNAL SDRM_EC_POINT *SDRM_ECC_Init()
{
	SDRM_EC_POINT	*temp;

	temp = (SDRM_EC_POINT *)malloc(sizeof(SDRM_EC_POINT) + SDRM_ECC_ALLOC_SIZE * 5);
	if (!temp)
	{
		return NULL;
	}

	temp->IsInfinity = 0;
	temp->x  = SDRM_BN_Alloc((cc_u8*)temp     + sizeof(SDRM_EC_POINT), SDRM_ECC_BN_BUFSIZE);
	temp->y  = SDRM_BN_Alloc((cc_u8*)temp->x  + SDRM_ECC_ALLOC_SIZE,   SDRM_ECC_BN_BUFSIZE);
	temp->z  = SDRM_BN_Alloc((cc_u8*)temp->y  + SDRM_ECC_ALLOC_SIZE,   SDRM_ECC_BN_BUFSIZE);
	temp->z2 = SDRM_BN_Alloc((cc_u8*)temp->z  + SDRM_ECC_ALLOC_SIZE,   SDRM_ECC_BN_BUFSIZE);
	temp->z3 = SDRM_BN_Alloc((cc_u8*)temp->z2 + SDRM_ECC_ALLOC_SIZE,   SDRM_ECC_BN_BUFSIZE);

	return temp;
}

/*
 * @fn		SDRM_CURVE_Init
 * @brief	return SDRM_ECC_CTX structure
 *
 * @return	address of allocate structure
 * \n		NULL	if memory allocation is failed
 */
CRYPTOCORE_INTERNAL SDRM_ECC_CTX *SDRM_CURVE_Init()
{
	SDRM_ECC_CTX	*temp;
	SDRM_EC_POINT	*ptr;
	cc_u8			*pbBlk;

	temp = (SDRM_ECC_CTX *)malloc(sizeof(SDRM_ECC_CTX) + SDRM_ECC_ALLOC_SIZE * 15 + 2 * sizeof(SDRM_EC_POINT));
	if (!temp) return NULL;

	pbBlk = (cc_u8*)temp + sizeof(SDRM_ECC_CTX);

	temp->ECC_a		= SDRM_BN_Alloc(pbBlk,									  SDRM_ECC_BN_BUFSIZE);
	temp->ECC_b		= SDRM_BN_Alloc((cc_u8*)temp->ECC_a + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	temp->ECC_p		= SDRM_BN_Alloc((cc_u8*)temp->ECC_b + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	temp->ECC_n		= SDRM_BN_Alloc((cc_u8*)temp->ECC_p + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	temp->PRIV_KEY	= SDRM_BN_Alloc((cc_u8*)temp->ECC_n + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);

	temp->uDimension = 0;

	ptr = (SDRM_EC_POINT*)(void*)((cc_u8*)temp + sizeof(SDRM_ECC_CTX) + SDRM_ECC_ALLOC_SIZE * 5);
	ptr->IsInfinity = 0;
	ptr->x  = SDRM_BN_Alloc((cc_u8*)ptr     + sizeof(SDRM_EC_POINT), SDRM_ECC_BN_BUFSIZE);
	ptr->y  = SDRM_BN_Alloc((cc_u8*)ptr->x  + SDRM_ECC_ALLOC_SIZE,   SDRM_ECC_BN_BUFSIZE);
	ptr->z  = SDRM_BN_Alloc((cc_u8*)ptr->y  + SDRM_ECC_ALLOC_SIZE,   SDRM_ECC_BN_BUFSIZE);
	ptr->z2 = SDRM_BN_Alloc((cc_u8*)ptr->z  + SDRM_ECC_ALLOC_SIZE,   SDRM_ECC_BN_BUFSIZE);
	ptr->z3 = SDRM_BN_Alloc((cc_u8*)ptr->z2 + SDRM_ECC_ALLOC_SIZE,   SDRM_ECC_BN_BUFSIZE);

	temp->ECC_G = ptr;

	ptr = (SDRM_EC_POINT*)(void*)((cc_u8*)ptr + sizeof(SDRM_EC_POINT) + SDRM_ECC_ALLOC_SIZE * 5);
	ptr->IsInfinity = 0;
	ptr->x  = SDRM_BN_Alloc((cc_u8*)ptr     + sizeof(SDRM_EC_POINT), SDRM_ECC_BN_BUFSIZE);
	ptr->y  = SDRM_BN_Alloc((cc_u8*)ptr->x  + SDRM_ECC_ALLOC_SIZE,   SDRM_ECC_BN_BUFSIZE);
	ptr->z  = SDRM_BN_Alloc((cc_u8*)ptr->y  + SDRM_ECC_ALLOC_SIZE,   SDRM_ECC_BN_BUFSIZE);
	ptr->z2 = SDRM_BN_Alloc((cc_u8*)ptr->z  + SDRM_ECC_ALLOC_SIZE,   SDRM_ECC_BN_BUFSIZE);
	ptr->z3 = SDRM_BN_Alloc((cc_u8*)ptr->z2 + SDRM_ECC_ALLOC_SIZE,   SDRM_ECC_BN_BUFSIZE);

	temp->PUBLIC_KEY = ptr;

	return temp;
}

////////////////////////////////////////////////////////////////////////////
// ECC 보조 연산 함수
////////////////////////////////////////////////////////////////////////////
/*
 * @fn		SDRM_CHECK_EC_POINT_ZERO
 * @brief	check if the point points zero
 *
 * @param	r			[in]point
 *
 * @return	1			if the point is pointing zero
 * \n		0			otherwise
 */
CRYPTOCORE_INTERNAL int SDRM_CHECK_EC_POINT_ZERO(SDRM_EC_POINT* r)
{
	if ((r->x->Length == 0) | (r->y->Length == 0))
	{
		//	return = 1		if input is zero
		return 1; 
	}
	else
	{
		return 0; 
	}
}

/*
 * @fn		SDRM_Mont_Jm2Jc
 * @brief	좌표변환 1 : Modified Jacobian  =>  Chundnovsky Jacobian 
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
CRYPTOCORE_INTERNAL int SDRM_Mont_Jm2Jc(SDRM_EC_POINT *EC_Dst, SDRM_BIG_NUM *new_a, SDRM_BIG_NUM *new_b, SDRM_BIG_MONT *Mont)
{
	if (SDRM_BN_IS_ODD(EC_Dst->y))
	{
		if (SDRM_BN_Add(EC_Dst->y, EC_Dst->y, Mont->Mod) != CRYPTO_SUCCESS)
		{
			return CRYPTO_ERROR;
		}
	}
	
	if (SDRM_BN_SHR(EC_Dst->y, EC_Dst->y, 1) != CRYPTO_SUCCESS)
	{
		return CRYPTO_ERROR;
	}
	
	SDRM_MONT_Mul(EC_Dst->z2, EC_Dst->z, EC_Dst->z, Mont);
	SDRM_MONT_Mul(EC_Dst->z3, EC_Dst->z, EC_Dst->z2, Mont);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_Mont_Jc2Jm
 * @brief	좌표변환 2 : Chundnovsky Jacobian  =>  Modified Jacobian
 *			(A->y)  <= 2*(A->y)
 *			(A->z2) <= new_a*(A->z)^4
 *
 * @param	A				[out]destination
 * @param	new_a			[in]first element
 * @param	new_b			[in]second element
 * @param	Mont			[in]montgomery context
 *
 * @return	CRYPTO_SUCCESS	if no error is occured
 * \n		CRYPTO_ERROR	if evaluation is failed
 */
CRYPTOCORE_INTERNAL int SDRM_Mont_Jc2Jm(SDRM_EC_POINT *A, SDRM_BIG_NUM *new_a, SDRM_BIG_NUM *new_b, SDRM_BIG_MONT *Mont)
{
	if (SDRM_BN_SHL(A->y, A->y, 1) != CRYPTO_SUCCESS)
	{
		return CRYPTO_ERROR;
	}
	
	if (SDRM_BN_Cmp(A->y, Mont->Mod)>=0)
	{
		SDRM_BN_Sub(A->y, A->y, Mont->Mod);
	}
	
	SDRM_MONT_Mul(A->z2, A->z, A->z, Mont);
	SDRM_MONT_Mul(A->z2, A->z2, A->z2, Mont);
	SDRM_MONT_Mul(A->z2, new_a, A->z2, Mont);

	return CRYPTO_SUCCESS;
}


/*
 * @fn		SDRM_CTX_EC_Add
 * @brief	Affine Coordinate (A = B + C)
 *
 * @param	ctx							[in]ECC context
 * @param	EC_Dst						[out]destination(A)
 * @param	EC_Src1						[in]first element(B)
 * @param	EC_Src2						[in]second element(C)
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_ERROR				if evaluation is failed
 * \n		CRYPTO_MEMORY_ALLOC_FAIL	if memory allocation is failed
 */
CRYPTOCORE_INTERNAL int SDRM_CTX_EC_Add(SDRM_ECC_CTX *ctx, SDRM_EC_POINT* EC_Dst, SDRM_EC_POINT *EC_Src1, SDRM_EC_POINT *EC_Src2)
{
	SDRM_BIG_NUM	*t1, *t2, *t3, *lambda, *lambda_sqr; 
	SDRM_BIG_NUM	*x3, *y3;
	cc_u8			*pbBuf = (cc_u8*)malloc(SDRM_ECC_ALLOC_SIZE * 7);
	
	if (!pbBuf)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	if (SDRM_CHECK_EC_POINT_ZERO(EC_Src1))
	{
		SDRM_EC_COPY(EC_Dst, EC_Src2); 
		free(pbBuf);
		return CRYPTO_SUCCESS; 
	}
	else if (SDRM_CHECK_EC_POINT_ZERO(EC_Src2))
	{
		SDRM_EC_COPY(EC_Dst, EC_Src1); 
		free(pbBuf);
		return CRYPTO_SUCCESS; 
	}

	t1         = SDRM_BN_Alloc(pbBuf,									SDRM_ECC_BN_BUFSIZE);
	t2         = SDRM_BN_Alloc((cc_u8*)t1		 + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	t3         = SDRM_BN_Alloc((cc_u8*)t2		 + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	lambda	   = SDRM_BN_Alloc((cc_u8*)t3		 + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	lambda_sqr = SDRM_BN_Alloc((cc_u8*)lambda	 + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	x3         = SDRM_BN_Alloc((cc_u8*)lambda_sqr + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	y3         = SDRM_BN_Alloc((cc_u8*)x3		 + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);

	if (SDRM_BN_Cmp(EC_Src1->x, EC_Src2->x) == 0)					/* x좌표가 같다면 */
	{
		if (SDRM_BN_Cmp(EC_Src1->y, EC_Src2->y) != 0)				/* y 좌표만 다르다면 */
		{	// (B = -C)
			SDRM_EC_SET_ZERO(EC_Dst);
			free(pbBuf);

			return CRYPTO_SUCCESS;
		}
		else														/* y 좌표도 같다면 */
		{	// (B = C)
			SDRM_BN_ModAdd(t1, EC_Src1->y, EC_Src1->y, ctx->ECC_p);	/* t1 = 2 * y1 */
			SDRM_BN_ModInv(t1, t1, ctx->ECC_p);						/* t1 = 1/(2 * y1) */

			SDRM_BN_ModMul(t2, EC_Src1->x, EC_Src1->x, ctx->ECC_p); 	/* t2 = x1^2 */
			SDRM_BN_ModAdd(t3, t2, t2, ctx->ECC_p);					/* t3 = t2 + t2 */			
			SDRM_BN_ModAdd(t3, t3, t2, ctx->ECC_p);					/* t2 = t3 + t2 = 3 * x1^2*/			
			SDRM_BN_ModAdd(t3, t3, ctx->ECC_a, ctx->ECC_p);			/* t3 = 3 * x1^2 + a */

			SDRM_BN_ModMul(lambda, t3, t1, ctx->ECC_p);				/* lambda = (3 * x1^2 + a) / (2 * y1) */
		}
	}
	else /* x 좌표가 다르다면 */
	{
		SDRM_BN_ModSub(t1, EC_Src2->x, EC_Src1->x, ctx->ECC_p);		/* t1 = x2 - x1 */
		SDRM_BN_ModSub(t2, EC_Src2->y, EC_Src1->y, ctx->ECC_p);		/* t2 = y2 - y1 */

		SDRM_BN_ModInv(t1, t1, ctx->ECC_p);							/* t1 = t1^(-1) = 1/(x2-x1) */
		SDRM_BN_ModMul(lambda, t1, t2, ctx->ECC_p);					/* lambda = (y2-y1)/(x2-x1) */
	}

	SDRM_BN_ModMul(lambda_sqr, lambda, lambda, ctx->ECC_p);			/* lambda^2 */
	SDRM_BN_ModSub(t1, lambda_sqr, EC_Src1->x, ctx->ECC_p);			/* x3 = lambda^2 - x1 */
	SDRM_BN_ModSub(x3, t1, EC_Src2->x, ctx->ECC_p);					/* x3 = lambda^2 - x1 - x2 */

	SDRM_BN_ModSub(t1, EC_Src1->x, x3, ctx->ECC_p); 				/* t1 = x1 - x3 */
	SDRM_BN_ModMul(t2, t1, lambda, ctx->ECC_p);						/* t2 = (x1 - x3) * lambda */
	SDRM_BN_ModSub(y3, t2, EC_Src1->y, ctx->ECC_p);					/* y3 = (x1 - x3) * lambda - y1 */

	SDRM_BN_Copy(EC_Dst->x, x3); 
	SDRM_BN_Copy(EC_Dst->y, y3); 

	free(pbBuf);

	return CRYPTO_SUCCESS; 
}

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
CRYPTOCORE_INTERNAL int SDRM_CTX_EC_Add_Jc(SDRM_EC_POINT *EC_Dst, SDRM_EC_POINT *EC_Src1, SDRM_EC_POINT *EC_Src2, SDRM_BIG_NUM *new_a, SDRM_BIG_NUM *new_b, SDRM_BIG_MONT *Mont)
{
	SDRM_BIG_NUM	*u1, *u2, *s1, *s2, *h, *r, *tmp1, *tmp2;
	cc_u8			*pbBuf = (cc_u8*)malloc(SDRM_ECC_ALLOC_SIZE * 8);
	
	if (!pbBuf)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}
	
	if (EC_Src1->IsInfinity || SDRM_CHECK_EC_POINT_ZERO(EC_Src1))
	{
		SDRM_EC_COPY(EC_Dst, EC_Src2); 
		free(pbBuf);

		return CRYPTO_SUCCESS; 
	}
	else if (EC_Src2->IsInfinity || SDRM_CHECK_EC_POINT_ZERO(EC_Src2))
	{
		SDRM_EC_COPY(EC_Dst, EC_Src1); 
		free(pbBuf);

		return CRYPTO_SUCCESS; 
	}

	u1   = SDRM_BN_Alloc(pbBuf							  , SDRM_ECC_BN_BUFSIZE);
	u2   = SDRM_BN_Alloc((cc_u8*)u1 + SDRM_ECC_ALLOC_SIZE,   SDRM_ECC_BN_BUFSIZE);
	s1   = SDRM_BN_Alloc((cc_u8*)u2 + SDRM_ECC_ALLOC_SIZE,   SDRM_ECC_BN_BUFSIZE);
	s2   = SDRM_BN_Alloc((cc_u8*)s1 + SDRM_ECC_ALLOC_SIZE,   SDRM_ECC_BN_BUFSIZE);
	h    = SDRM_BN_Alloc((cc_u8*)s2  + SDRM_ECC_ALLOC_SIZE,  SDRM_ECC_BN_BUFSIZE);
	r    = SDRM_BN_Alloc((cc_u8*)h + SDRM_ECC_ALLOC_SIZE,    SDRM_ECC_BN_BUFSIZE);
	tmp1 = SDRM_BN_Alloc((cc_u8*)r + SDRM_ECC_ALLOC_SIZE,    SDRM_ECC_BN_BUFSIZE);
	tmp2 = SDRM_BN_Alloc((cc_u8*)tmp1 + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);

	// u1
	SDRM_MONT_Mul(u1, EC_Src1->x, EC_Src2->z2, Mont);
	// u2
	SDRM_MONT_Mul(u2, EC_Src2->x, EC_Src1->z2, Mont);
	// s1
	SDRM_MONT_Mul(s1, EC_Src1->y, EC_Src2->z3, Mont);
	// s2
	SDRM_MONT_Mul(s2, EC_Src2->y, EC_Src1->z3, Mont);

	SDRM_BN_Sub(h, u2, u1);
	if (h->sign)
	{
		SDRM_BN_Add(h, h, Mont->Mod);
	}

	// r
	SDRM_BN_Sub(r, s2, s1);
	if (r->sign)
	{
		SDRM_BN_Add(r, r, Mont->Mod);
	}

	// exception cases check
	if (h->Length == 0)
	{
		if (r->Length == 0)
		{
			// If (h == 0) & (r == 0), CTX_EC_Double_Jc로 계산
			// because B, C are same point.
			free(pbBuf);

			return SDRM_CTX_EC_Double_Jc(EC_Dst, EC_Src1, new_a, new_b, Mont);
		}
		else
		{
			// If (h == 0) & (r != 0), A = Infinity point
			EC_Dst->IsInfinity = 1;
			free(pbBuf);

			return CRYPTO_INFINITY_INPUT;
		}
	}

	// EC_Dst->x
	SDRM_MONT_Mul(EC_Dst->x, r, r, Mont);
	SDRM_MONT_Mul(EC_Dst->y, h, h, Mont);				// A->y : h^2, temp
	SDRM_MONT_Mul(tmp1, EC_Dst->y, h, Mont);			// tmp1 : h^3, temp
	SDRM_MONT_Mul(EC_Dst->y, u1, EC_Dst->y, Mont);		// A->y : u1*h^2

	SDRM_BN_SHL(tmp2, EC_Dst->y, 1);
	if (SDRM_BN_Cmp(tmp2, Mont->Mod) >= 0)
	{
		SDRM_BN_Sub(tmp2, tmp2, Mont->Mod);
	}

	SDRM_BN_ModSub(EC_Dst->x, EC_Dst->x, tmp2, Mont->Mod);
	SDRM_BN_ModSub(EC_Dst->x, EC_Dst->x, tmp1, Mont->Mod);

	// EC_Dst->y
	SDRM_BN_ModSub(EC_Dst->y, EC_Dst->y, EC_Dst->x, Mont->Mod);
	SDRM_MONT_Mul(EC_Dst->y, r, EC_Dst->y, Mont);
	SDRM_MONT_Mul(tmp1, s1, tmp1, Mont);
	SDRM_BN_ModSub(EC_Dst->y, EC_Dst->y, tmp1, Mont->Mod);

	// EC_Dst->z
	SDRM_MONT_Mul(EC_Dst->z, EC_Src1->z, EC_Src2->z, Mont);
	SDRM_MONT_Mul(EC_Dst->z, EC_Dst->z, h, Mont);

	// 효율성을 고려해 아래는 생략-> 필요한 경우 외부에서 계산
#if 0
	// EC_Dst->z2
	SDRM_MONT_Mul(EC_Dst->z2, EC_Dst->z, EC_Dst->z, Mont);
	// EC_Dst->z3
	SDRM_MONT_Mul(EC_Dst->z3, EC_Dst->z, EC_Dst->z2, Mont);
#endif

	free(pbBuf);

	return CRYPTO_SUCCESS;
}

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
CRYPTOCORE_INTERNAL int SDRM_CTX_EC_Double_Jc(SDRM_EC_POINT *EC_Dst, SDRM_EC_POINT *EC_Src1, SDRM_BIG_NUM *new_a, SDRM_BIG_NUM *new_b, SDRM_BIG_MONT *Mont)
{
	SDRM_BIG_NUM	*s, *k, *tmp1, *tmp2;
	cc_u8			*pbBuf = (cc_u8*)malloc(SDRM_ECC_ALLOC_SIZE * 4);
	
	if (!pbBuf)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	// If B = infinite point || (B->y) = 0, A = infinite point.
	if (EC_Src1->IsInfinity || SDRM_CHECK_EC_POINT_ZERO(EC_Src1))
	{
		EC_Dst->IsInfinity = 1; 
		free(pbBuf);
		return CRYPTO_SUCCESS; 
	}

	s    = SDRM_BN_Alloc(pbBuf							  , SDRM_ECC_BN_BUFSIZE);
	k    = SDRM_BN_Alloc((cc_u8*)s + SDRM_ECC_ALLOC_SIZE,    SDRM_ECC_BN_BUFSIZE);
	tmp1 = SDRM_BN_Alloc((cc_u8*)k + SDRM_ECC_ALLOC_SIZE,    SDRM_ECC_BN_BUFSIZE);
	tmp2 = SDRM_BN_Alloc((cc_u8*)tmp1 + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	
	// s
	SDRM_MONT_Mul(s, EC_Src1->y, EC_Src1->y, Mont);			// s = (B->y)^2
	SDRM_MONT_Mul(tmp1, s, s, Mont);							// tmp1 = (B->y)^4
	SDRM_MONT_Mul(s, EC_Src1->x, s, Mont);
	SDRM_BN_SHL(s, s, 2);
	SDRM_BN_ModRed(s, s, Mont->Mod);

	// k
	SDRM_MONT_Mul(k, EC_Src1->x, EC_Src1->x, Mont);
	SDRM_BN_SHL(tmp2, k, 1);
	SDRM_BN_ModAdd(tmp2, tmp2, k, Mont->Mod);
	SDRM_MONT_Mul(k, EC_Src1->z, EC_Src1->z3, Mont);
	SDRM_MONT_Mul(k, new_a, k, Mont);
	SDRM_BN_ModAdd(k, tmp2, k, Mont->Mod);

	// t & EC_Dst->x
	SDRM_BN_SHL(tmp2, s, 1);

	if (SDRM_BN_Cmp(tmp2, Mont->Mod)>=0)
	{
		SDRM_BN_Sub(tmp2, tmp2, Mont->Mod);
	}

	SDRM_MONT_Mul(EC_Dst->x, k, k, Mont);
	SDRM_BN_ModSub(EC_Dst->x, EC_Dst->x, tmp2, Mont->Mod);

	// EC_Dst->z
	SDRM_MONT_Mul(EC_Dst->z, EC_Src1->y, EC_Src1->z, Mont);
	SDRM_BN_SHL(EC_Dst->z, EC_Dst->z, 1);

	if (SDRM_BN_Cmp(EC_Dst->z, Mont->Mod)>=0)
	{
		SDRM_BN_Sub(EC_Dst->z, EC_Dst->z, Mont->Mod);
	}

	// EC_Dst->y
	SDRM_BN_SHL(EC_Dst->y, tmp1, 3);
	while(SDRM_BN_Cmp(EC_Dst->y, Mont->Mod) >= 0)
	{
		SDRM_BN_Sub(EC_Dst->y, EC_Dst->y, Mont->Mod);
	}

	SDRM_BN_ModSub(tmp1, s, EC_Dst->x, Mont->Mod);			// tmp1 = s-t (s값 바뀜)
	SDRM_MONT_Mul(tmp1, k, tmp1, Mont);						// k(s-t)
	SDRM_BN_ModSub(EC_Dst->y, tmp1, EC_Dst->y, Mont->Mod);
	if (EC_Dst->y->sign)
	{
		SDRM_BN_Add(EC_Dst->y, EC_Dst->y, Mont->Mod);
	}

	// EC_Dst->z2
	SDRM_MONT_Mul(EC_Dst->z2, EC_Dst->z, EC_Dst->z, Mont);
	
	// EC_Dst->z3
	SDRM_MONT_Mul(EC_Dst->z3, EC_Dst->z, EC_Dst->z2, Mont);

	// Memory Free
	free(pbBuf);

	return CRYPTO_SUCCESS;
}


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
CRYPTOCORE_INTERNAL int SDRM_CTX_EC_Double_Jm(SDRM_EC_POINT *EC_Dst, SDRM_EC_POINT *EC_Src1, SDRM_BIG_NUM *new_a, SDRM_BIG_NUM *new_b, SDRM_BIG_MONT *Mont)
{
	SDRM_BIG_NUM	*a, *b, *c, *tmp1;
	cc_u8			*pbBuf = (cc_u8*)malloc(SDRM_ECC_ALLOC_SIZE * 4);
	
	if (!pbBuf)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	// If B is the infinite point or (B->y) is zero, A is the infinite point.
	if (EC_Src1->IsInfinity || SDRM_CHECK_EC_POINT_ZERO(EC_Src1))
	{
		EC_Dst->IsInfinity = 1; 
		free(pbBuf);

		return CRYPTO_SUCCESS; 
	}

	a    = SDRM_BN_Alloc(pbBuf, SDRM_ECC_BN_BUFSIZE);
	b    = SDRM_BN_Alloc((cc_u8*)a + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	c    = SDRM_BN_Alloc((cc_u8*)b + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	tmp1 = SDRM_BN_Alloc((cc_u8*)c + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);

	// a
	SDRM_MONT_Mul(a, EC_Src1->x, EC_Src1->x, Mont);
	SDRM_BN_SHL(tmp1, a, 1);
	SDRM_BN_Add(a, tmp1, a);
	SDRM_BN_Add(a, a, EC_Src1->z2);
	while(SDRM_BN_Cmp(a, Mont->Mod) >= 0)
	{
		SDRM_BN_Sub(a, a, Mont->Mod);
	}

	// b & c
	SDRM_MONT_Mul(b, EC_Src1->y, EC_Src1->y, Mont);		// b = (y1)^2
	SDRM_MONT_Mul(c, b, b, Mont);							// c = (y1)^4
	SDRM_MONT_Mul(b, EC_Src1->x, b, Mont);
	SDRM_BN_SHL(b, b, 1);
	if (SDRM_BN_Cmp(b, Mont->Mod)>=0)
	{
		SDRM_BN_Sub(b, b, Mont->Mod);
	}

	// EC_Dst->x
	SDRM_MONT_Mul(EC_Dst->x, a, a, Mont);
	SDRM_BN_ModSub(EC_Dst->x, EC_Dst->x, b, Mont->Mod);

	// EC_Dst->z
	SDRM_MONT_Mul(EC_Dst->z, EC_Src1->y, EC_Src1->z, Mont);

	// EC_Dst->y
	SDRM_BN_SHL(EC_Dst->y, EC_Dst->x, 1);

	if (SDRM_BN_Cmp(EC_Dst->y, Mont->Mod)>=0)
	{
		SDRM_BN_Sub(EC_Dst->y, EC_Dst->y, Mont->Mod);
	}

	SDRM_BN_Sub(EC_Dst->y, b, EC_Dst->y);
	
	if (EC_Dst->y->sign)
	{
		SDRM_BN_Add(EC_Dst->y, EC_Dst->y, Mont->Mod);
	}

	SDRM_MONT_Mul(EC_Dst->y, a, EC_Dst->y, Mont);
	SDRM_BN_ModSub(EC_Dst->y, EC_Dst->y, c, Mont->Mod);

	// EC_Dst->z2
	SDRM_MONT_Mul(EC_Dst->z2, c, EC_Dst->z2, Mont);

	free(pbBuf);

	return CRYPTO_SUCCESS;
}

/*
 * @fn		SDRM_CTX_EC_Chain
 * @brief	Chain 함수
 *			signed wondow method	:	size of window = 4
 *			chain for addition/subtraction of k Using sliding window method
 *
 * @param	chain						[out]destination
 * @param	L_Src						[in]byte-length of chain
 * @param	Len_Src						[in]number of doubling in chain
 * @param	k							[in]source
 * @param	window_size					[in]size of window
 *
 * @return	CRYPTO_SUCCESS				if no error is occured
 * \n		CRYPTO_INVALID_ARGUMENT		if given value is incorrect
 */
CRYPTOCORE_INTERNAL int SDRM_CTX_EC_Chain(signed char *chain, cc_u32 *L_Src, cc_u32 *Len_Src, SDRM_BIG_NUM *k, int window_size)
{
	int		i, j = 0, AddorSub, last = 0, doublings = 0;
	int		bits_k = 0, subtract=0, pos = 0, temp_1 = 0;	
	cc_u32	temp = 0;
	cc_u32	numDoubling = 0;					// number of doubling(= lshift)

	// k의 유효성 check
	if (k->sign)
	{
		return CRYPTO_INVALID_ARGUMENT;
	}

	bits_k=(SDRM_BN_num_bits(k)-1);

	// sliding window method ('06)
	while(bits_k>=0)
	{
		if ((bits_k + 1) < window_size)
			window_size = bits_k + 1;

		if ((subtract == 0) || (subtract == 10))
		{
			AddorSub = 0;
		}
		else
		{
			AddorSub = 1;
		}

		for(i = bits_k; i >= bits_k - window_size + 1; i--)
		{
			temp <<= 1;
			temp += AddorSub ^ SDRM_CheckBitUINT32(k->pData, i);
		}

		bits_k -= window_size;
		
		if ((SDRM_CheckBitUINT32(k->pData, bits_k) == (cc_u32)1 - AddorSub) && (bits_k >= 0))
		{
			temp++;
			AddorSub = 1 - AddorSub;
		}

		if ((bits_k == -1) && (AddorSub == 1))
			temp++;
		
		if (bits_k>=0)
		{
			if (SDRM_CheckBitUINT32(k->pData, bits_k)==1)
			{
				if ((subtract == 0) || (subtract == 10))
				{
					subtract = 1;
				}
				else
				{
					subtract = 11;
				}

				for(temp_1 = 0 ; SDRM_CheckBitUINT32(k->pData, bits_k)==1; bits_k--)
				{
					if (bits_k >=0)
					{
						temp_1++;
					}
				}
			}
			else
			{
				if ((subtract == 0) || (subtract == 10))
				{
					subtract = 0;
				}
				else
				{
					subtract = 10;
				}

				for(temp_1 = 0 ; SDRM_CheckBitUINT32(k->pData, bits_k)==0; bits_k--)
				{
					if (bits_k >=0)
					{
						temp_1++;
					}
				}
			}

			if (bits_k < 0)
			{
				last = 1;
			}
		}
		else
		{
			if ((subtract == 0) || (subtract == 10))
			{
				subtract = 0;
			}
			else
			{
				subtract = 10;
			}
		}
		
		j = temp >> window_size;

		if (temp != 0)
		{
			for(doublings = 0; !(temp&0x1); doublings++)
			{
				temp >>= 1;
			}
			doublings += temp_1;
		}
		else
		{
			doublings = temp_1;
		}

		if (pos > 0)
		{
			for(i = temp ; i > j ; i>>=1)
			{
				chain[++pos] = 0;				
				numDoubling++;			
			}
		}

		if ((subtract==10) || (subtract == 11))
		{
			chain[++pos] = (char)((~temp + 1) & 0xff);
		}
		else
		{
			chain[++pos] = (char)((temp) & 0xff);
		}

		for( ; doublings > 0; doublings--)
		{
			chain[++pos] = 0;				
			numDoubling++;
		}

		if (last == 1)
		{
			if (AddorSub == 1) 
			{
				chain[++pos] = -1;
			}
		}
				
		temp = 0;
		temp_1 = 0;
	}

	*L_Src = pos;
	*Len_Src = numDoubling;

	return CRYPTO_SUCCESS;
}

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
CRYPTOCORE_INTERNAL int SDRM_CTX_EC_kP(SDRM_ECC_CTX *ctx, SDRM_EC_POINT* EC_Dst, SDRM_EC_POINT *EC_Src, SDRM_BIG_NUM *k)
{
	int				res, i;
	int				window_size = 4;					// window size
	int				w_p = (1 << (window_size-1)) + 1;	// pre-computation number
//	int				add = 0, subtract = 0;				// add : num_(addition + subtract)
														// subtract :  0 - before = 0 & after = 0
														//			  10 - before = 1 & after = 0 	
														//			   1 - before = 0 & after = 1 	
														//			  11 - before = 1 & after = 1 	
														//      => 0 : no subtract / 1 : subtract
	SDRM_EC_POINT	*Pw[9] = {0};						// number of precomputation data : 9 = w_p = 2^(window_size-1) + 1
	SDRM_BIG_MONT	*Mont;
	SDRM_BIG_NUM	*new_a, *new_b;
	SDRM_BIG_NUM	*t1, *t2;		
	signed char		chain[2 * SDRM_MAX_DIMENSION_ECC];		// DIMENSION_ECC :  ecdsa.h에서 define
	cc_u32			length;								// addition & subtrction chain length of k1 & k2
	cc_u32			lenD;								// number of doubling of addition & subtrction chain of k1 & k2	

	cc_u8			*pbBuf = (cc_u8*)malloc(SDRM_ECC_ALLOC_SIZE * 4);
	if (!pbBuf)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}
	
	// k와 P의 유효성 check
	if (k->sign)
	{
		free(pbBuf);
		return CRYPTO_INVALID_ARGUMENT;
	}

	if (EC_Src->x->sign|EC_Src->y->sign)
	{
		free(pbBuf);	
		return CRYPTO_INVALID_ARGUMENT;
	}

	Mont = SDRM_MONT_Init(ctx->ECC_p->Size);
	if (Mont == NULL) 
	{
		free(pbBuf);
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	SDRM_MONT_Set(Mont, ctx->ECC_p);

	new_a = SDRM_BN_Alloc(pbBuf,							  SDRM_ECC_BN_BUFSIZE);
	new_b = SDRM_BN_Alloc((cc_u8*)new_a + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	t1    = SDRM_BN_Alloc((cc_u8*)new_b + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	t2    = SDRM_BN_Alloc((cc_u8*)t1	   + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);

	if (SDRM_MONT_Zn2rzn(new_a, ctx->ECC_a, Mont) != CRYPTO_SUCCESS)
	{
		free(pbBuf);
		SDRM_MONT_Free(Mont);
		return CRYPTO_ERROR;
	}

	if (SDRM_MONT_Zn2rzn(new_b, ctx->ECC_b, Mont) != CRYPTO_SUCCESS)
	{
		free(pbBuf);
		SDRM_MONT_Free(Mont);
		return CRYPTO_ERROR;
	}


	//chain 계산
	res = SDRM_CTX_EC_Chain(chain, &length, &lenD, k, window_size);
	if (res != CRYPTO_SUCCESS)
	{
		free(pbBuf);
		SDRM_MONT_Free(Mont);

		return CRYPTO_ERROR;
	}
	
	// pre-computation Data 계산	:		Chunvosky algorithm
		// Pw[1] = EC_Src
		// Pw[2] = 3 * EC_Src
		// Pw[3] = 5 * EC_Src
		// Pw[4] = 7 * EC_Src
		// ..................
	for(i = 0; i < 9; i++)
	{
		Pw[i] = SDRM_ECC_Init();
		if (Pw[i] == NULL)
		{
			free(pbBuf);
			SDRM_MONT_Free(Mont);
			while (i > 0)
			{
				free(Pw[--i]);
			}
			return CRYPTO_MEMORY_ALLOC_FAIL;
		}
	}

	SDRM_EC_COPY(Pw[1], EC_Src);

	SDRM_MONT_Zn2rzn(Pw[1]->x, Pw[1]->x, Mont);
	SDRM_MONT_Zn2rzn(Pw[1]->y, Pw[1]->y, Mont);
	SDRM_MONT_Zn2rzn(Pw[1]->z, BN_One, Mont);

	SDRM_BN_Copy(Pw[1]->z2, Pw[1]->z);
	SDRM_BN_Copy(Pw[1]->z3, Pw[1]->z);

	SDRM_EC_SET_ZERO(Pw[0]);
	SDRM_CTX_EC_Double_Jc(Pw[0], Pw[1], new_a, new_b, Mont);

	for (i = 2; i < w_p; i++)
	{
		SDRM_EC_SET_ZERO(Pw[i]);
		SDRM_CTX_EC_Add_Jc(Pw[i], Pw[i-1], Pw[0], new_a, new_b, Mont);

		SDRM_MONT_Mul(Pw[i]->z2, Pw[i]->z, Pw[i]->z, Mont);
		SDRM_MONT_Mul(Pw[i]->z3, Pw[i]->z2, Pw[i]->z, Mont);
	}

	EC_Dst->IsInfinity = 1;

	for(i = 0; i != (int)length; i++)
	{
		if (chain[i + 1]==0)
		{
			// EC_Dst = 2 * EC_Dst
			SDRM_CTX_EC_Double_Jm(EC_Dst, EC_Dst, new_a, new_b, Mont);
			lenD--;
		}
		else
		{
			SDRM_Mont_Jm2Jc(EC_Dst, new_a, new_b, Mont);
			if (chain[i + 1]>0)
			{
				// EC_Dst = EC_Dst + Pw[(chain[i + 1]+1)/2]
				SDRM_CTX_EC_Add_Jc(EC_Dst, EC_Dst, Pw[(chain[i + 1]+1)/2], new_a, new_b, Mont);
			}
			else
			{
				// EC_Dst = EC_Dst - Pw[(chain[i + 1]]+1)/2]
				SDRM_EC_COPY(Pw[0], Pw[(-chain[i + 1]+1)/2]);
				SDRM_BN_Sub(Pw[0]->y, ctx->ECC_p, Pw[0]->y);
				SDRM_CTX_EC_Add_Jc(EC_Dst, EC_Dst, Pw[0], new_a, new_b, Mont);	
			}
			SDRM_Mont_Jc2Jm(EC_Dst, new_a, new_b, Mont);
		}
	}
	
	// montgomery reduction of EC_Dst
	SDRM_MONT_Rzn2zn(EC_Dst->x, EC_Dst->x, Mont);
	SDRM_MONT_Rzn2zn(EC_Dst->y, EC_Dst->y, Mont);
	SDRM_MONT_Rzn2zn(EC_Dst->z, EC_Dst->z, Mont);
	
	if (EC_Dst->z->Length == 0)
	{
		for(i = 0; i < 9; i++)
		{
			free(Pw[i]);
		}
		free(pbBuf);
		SDRM_MONT_Free(Mont);

		EC_Dst->IsInfinity = 1;

		return CRYPTO_INFINITY_INPUT;
	}
	// Convert coordinate :  "Modified Jacobian" => "Affine"
	//  (EC_Dst->x) <= (EC_Dst->x) * { ((EC_Dst->z)^2)^-1 }
	//  (EC_Dst->y) <= (EC_Dst->y) * { (2*((EC_Dst->z)^3))^-1 }

	SDRM_BN_ModMul(t1, EC_Dst->z, EC_Dst->z, ctx->ECC_p);
	SDRM_BN_ModInv(t2, t1, ctx->ECC_p);
	SDRM_BN_ModMul(EC_Dst->x, EC_Dst->x, t2, ctx->ECC_p);

	SDRM_BN_ModMul(t1, t1, EC_Dst->z, ctx->ECC_p);
	SDRM_BN_SHL(t1, t1, 1);
	SDRM_BN_ModInv(t2, t1, ctx->ECC_p);
	SDRM_BN_ModMul(EC_Dst->y, EC_Dst->y, t2, ctx->ECC_p);
	
	// Memory Free
	for(i = 0; i < 9; i++)
	{
		free(Pw[i]);
	}

	free(pbBuf);
	SDRM_MONT_Free(Mont);

	return CRYPTO_SUCCESS; 
}

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
CRYPTOCORE_INTERNAL int SDRM_CTX_EC_2kP(SDRM_ECC_CTX *ctx, SDRM_EC_POINT *EC_Dst, SDRM_BIG_NUM *k1, SDRM_EC_POINT *EC_Src1, SDRM_BIG_NUM *k2, SDRM_EC_POINT *EC_Src2)
{
	signed char		chain[2][2 * SDRM_MAX_DIMENSION_ECC];		// addition/subtrction chain of k1  k2
	cc_u32			length[2];								// addition/subtrction chain length of k1  k2
	cc_u32			lenD[2];								// # of doubling of addition/subtrction chain of k1  k2	
	cc_u32			idx[2];
	int				window_size = 4;						// window size
	int				w2 = (1 << (window_size - 1)) + 1;		// 2^(window_size-1)+1 : the precomputation point number
	int				i, j, res;
	SDRM_EC_POINT	*Pw[2][9]={0,};								// precomputation data
	SDRM_BIG_MONT	*Mont=NULL;
	SDRM_BIG_NUM	*new_a, *new_b;
	SDRM_BIG_NUM	*t1, *t2;								// Used in coordinate change from "Modified Jacobian" to "Affine"

	cc_u8 *pbBuf = (cc_u8*)malloc(SDRM_ECC_ALLOC_SIZE * 4);
	if (!pbBuf)
	{
		return CRYPTO_MEMORY_ALLOC_FAIL;
	}

	// k1 & k2 & C1 & C2 유효성 check
	if (k1->sign | k2->sign)
	{
		free(pbBuf);

		return CRYPTO_ERROR;
	}

	if (EC_Src1->x->sign | EC_Src1->y->sign | EC_Src2->x->sign | EC_Src2->y->sign)
	{
		free(pbBuf);

		return CRYPTO_ERROR;
	}

	Mont = SDRM_MONT_Init(ctx->ECC_p->Size);
	SDRM_MONT_Set(Mont, ctx->ECC_p);

	new_a = SDRM_BN_Alloc(pbBuf,							  SDRM_ECC_BN_BUFSIZE);
	new_b = SDRM_BN_Alloc((cc_u8*)new_a + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	t1    = SDRM_BN_Alloc((cc_u8*)new_b + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	t2    = SDRM_BN_Alloc((cc_u8*)t1	   + SDRM_ECC_ALLOC_SIZE, SDRM_ECC_BN_BUFSIZE);
	
	if (SDRM_MONT_Zn2rzn(new_a, ctx->ECC_a, Mont) != CRYPTO_SUCCESS)
	{
		free(pbBuf);
		SDRM_MONT_Free(Mont);
		return CRYPTO_ERROR;
	}

	if (SDRM_MONT_Zn2rzn(new_b, ctx->ECC_b, Mont) != CRYPTO_SUCCESS)
	{
		free(pbBuf);
		SDRM_MONT_Free(Mont);
		return CRYPTO_ERROR;
	}

	// chain 계산
	res = SDRM_CTX_EC_Chain(chain[0], &length[0], &lenD[0], k1, window_size);
	if (res != CRYPTO_SUCCESS)
	{
		free(pbBuf); 
		SDRM_MONT_Free(Mont);
		return res;
	}

	res = SDRM_CTX_EC_Chain(chain[1], &length[1], &lenD[1], k2, window_size);
	if (res != CRYPTO_SUCCESS)
	{
		free(pbBuf);
		SDRM_MONT_Free(Mont);
		return res;
	}

	// Precomputation data
	for(i = 0; i < 2; i++)
	{
//		Pw[i] = (SDRM_EC_POINT **)malloc(sizeof(SDRM_EC_POINT *) * w2);
//		if (!Pw[i]) return CRYPTO_MEMORY_ALLOC_FAIL;
		for(j = 0; j < 9; j++)
		{
			Pw[i][j] =  SDRM_ECC_Init();
		}
	}
	SDRM_EC_COPY(Pw[0][1], EC_Src1);
	SDRM_EC_COPY(Pw[1][1], EC_Src2);

	for (i=0;i<2;i++)
	{
		SDRM_MONT_Zn2rzn(Pw[i][1]->x, Pw[i][1]->x, Mont);
		SDRM_MONT_Zn2rzn(Pw[i][1]->y, Pw[i][1]->y, Mont);
		SDRM_MONT_Zn2rzn(Pw[i][1]->z, BN_One, Mont);
		SDRM_BN_Copy(Pw[i][1]->z2, Pw[i][1]->z);
		SDRM_BN_Copy(Pw[i][1]->z3, Pw[i][1]->z);
		SDRM_CTX_EC_Double_Jc(Pw[i][0], Pw[i][1], new_a, new_b, Mont);
		
		for (j=2;j<w2;j++)
		{
			SDRM_CTX_EC_Add_Jc(Pw[i][j], Pw[i][j-1], Pw[i][0], new_a, new_b, Mont);
			SDRM_MONT_Mul(Pw[i][j]->z2, Pw[i][j]->z, Pw[i][j]->z, Mont);
			SDRM_MONT_Mul(Pw[i][j]->z3, Pw[i][j]->z2, Pw[i][j]->z, Mont);
		}
	}
	
	EC_Dst->IsInfinity = 1;
	idx[0] = idx[1] = 1;

	// 우선 doubling 개수가 같아질때까지 큰 쪽 계산
	if (lenD[0] != lenD[1])
	{
		i = ((lenD[0] > lenD[1]) ? 0 : 1);
		for (;lenD[0] != lenD[1]; idx[i]++)
		{
			if (chain[i][idx[i]] == 0)
			{
				// EC_Dst = 2EC_Dst
				SDRM_CTX_EC_Double_Jm(EC_Dst, EC_Dst, new_a, new_b, Mont);
				lenD[i]--;
			}
			else
			{
				SDRM_Mont_Jm2Jc(EC_Dst, new_a, new_b, Mont);

				if (chain[i][idx[i]]>0)
				{
					// EC_Dst = EC_Dst + Pw[i][(chain[i][idx[i]]+1)/2]
					SDRM_CTX_EC_Add_Jc(EC_Dst, EC_Dst, Pw[i][(chain[i][idx[i]]+1)/2], new_a, new_b, Mont);
				}
				else
				{
					// EC_Dst = EC_Dst - Pw[i][(chain[i][idx[i]]+1)/2]
					SDRM_EC_COPY(Pw[i][0], Pw[i][(-chain[i][idx[i]]+1)/2]);
					SDRM_BN_Sub(Pw[i][0]->y, ctx->ECC_p, Pw[i][0]->y);
					SDRM_CTX_EC_Add_Jc(EC_Dst, EC_Dst, Pw[i][0], new_a, new_b, Mont);	
				}
				SDRM_Mont_Jc2Jm(EC_Dst, new_a, new_b, Mont);
			}
		}
	}

	while ((idx[0] <= length[0]) && (idx[1] <= length[1]))
	{
		if ((chain[0][idx[0]] == 0) && (chain[1][idx[1]] == 0))
		{
			// EC_Dst = 2EC_Dst
			SDRM_CTX_EC_Double_Jm(EC_Dst, EC_Dst, new_a, new_b, Mont);
			idx[0]++;
			idx[1]++;
			continue;
		}

		SDRM_Mont_Jm2Jc(EC_Dst, new_a, new_b, Mont);

		if (chain[0][idx[0]]!=0)
		{
			if (chain[0][idx[0]]>0)
			{
				// EC_Dst = EC_Dst + Pw[0][(chain[0][idx[0]]+1)/2]
				SDRM_CTX_EC_Add_Jc(EC_Dst, EC_Dst, Pw[0][(chain[0][idx[0]] + 1) / 2], new_a, new_b, Mont);
			}
			else
			{
				// EC_Dst = EC_Dst - Pw[0][(chain[0][idx[0]]+1)/2]
				SDRM_EC_COPY(Pw[0][0], Pw[0][(-chain[0][idx[0]] + 1) / 2]);
				SDRM_BN_Sub(Pw[0][0]->y, ctx->ECC_p, Pw[0][0]->y);
				SDRM_CTX_EC_Add_Jc(EC_Dst, EC_Dst, Pw[0][0], new_a, new_b, Mont);
			}

			idx[0]++;

			if (chain[1][idx[1]] != 0)
			{
				// make z^2, z^3 for next computation
				SDRM_MONT_Mul(EC_Dst->z2, EC_Dst->z, EC_Dst->z, Mont);
				SDRM_MONT_Mul(EC_Dst->z3, EC_Dst->z2, EC_Dst->z, Mont);
			}
		}

		if (chain[1][idx[1]]!=0)
		{
			if (chain[1][idx[1]]>0)
			{
				// EC_Dst = EC_Dst + Pw[1][(chain[1][idx[1]]+1)/2]
				SDRM_CTX_EC_Add_Jc(EC_Dst, EC_Dst, Pw[1][(chain[1][idx[1]]+1)/2], new_a, new_b, Mont);
			}
			else
			{
				// EC_Dst = EC_Dst - Pw[1][(chain[1][idx[1]]+1)/2]
				SDRM_EC_COPY(Pw[1][0], Pw[1][(-chain[1][idx[1]]+1)/2]);
				SDRM_BN_Sub(Pw[1][0]->y, ctx->ECC_p, Pw[1][0]->y);
				SDRM_CTX_EC_Add_Jc(EC_Dst, EC_Dst, Pw[1][0], new_a, new_b, Mont);
			}
			idx[1]++;
		}
		SDRM_Mont_Jc2Jm(EC_Dst, new_a, new_b, Mont);
	}

	if ((idx[0]==length[0]) || (idx[1]==length[1]))
	{
		i = ((idx[0]==length[0]) ? 0 : 1);

		SDRM_Mont_Jm2Jc(EC_Dst, new_a, new_b, Mont);

		if (chain[i][idx[i]]>0)
		{
			// EC_Dst = EC_Dst + Pw[i][(chain[i][idx[i]]+1)/2]
			SDRM_CTX_EC_Add_Jc(EC_Dst, EC_Dst, Pw[i][(chain[i][idx[i]] + 1) / 2], new_a, new_b, Mont);
		}
		else
		{
			// EC_Dst = EC_Dst - Pw[i][(chain[i][idx[i]]+1)/2]
			SDRM_EC_COPY(Pw[i][0], Pw[i][(-chain[i][idx[i]] + 1) / 2]);
			SDRM_BN_Sub(Pw[i][0]->y, ctx->ECC_p, Pw[i][0]->y);
			SDRM_CTX_EC_Add_Jc(EC_Dst, EC_Dst, Pw[i][0], new_a, new_b, Mont);
		}
		SDRM_Mont_Jc2Jm(EC_Dst, new_a, new_b, Mont);
	}


	// montgomery reduction of EC_Dst
	SDRM_MONT_Rzn2zn(EC_Dst->x, EC_Dst->x, Mont);
	SDRM_MONT_Rzn2zn(EC_Dst->y, EC_Dst->y, Mont);
	SDRM_MONT_Rzn2zn(EC_Dst->z, EC_Dst->z, Mont);
	
	if (EC_Dst->z->Length == 0)
	{
		for(i = 0; i < 2; i++)
		{
			for(j = 0; j < 9; j++)
			{
				free(Pw[i][j]);
			}
		}

		free(pbBuf);
		SDRM_MONT_Free(Mont);

		EC_Dst->IsInfinity = 1;

		return CRYPTO_INFINITY_INPUT;
	}

	// 좌표변환 : Modified Jacobian	=>	Affine
	//  (EC_Dst->x) <= (EC_Dst->x) * { ((EC_Dst->z)^2)^-1 }
	//  (EC_Dst->y) <= (EC_Dst->y) * { (2*((EC_Dst->z)^3))^-1 }
	SDRM_BN_ModMul(t1, EC_Dst->z, EC_Dst->z, ctx->ECC_p);
	SDRM_BN_ModInv(t2, t1, ctx->ECC_p);
	SDRM_BN_ModMul(EC_Dst->x, EC_Dst->x, t2, ctx->ECC_p);

	SDRM_BN_ModMul(t2, t1, EC_Dst->z, ctx->ECC_p);
	SDRM_BN_SHL(t2, t2, 1);
	SDRM_BN_ModInv(t1, t2, ctx->ECC_p);
	SDRM_BN_ModMul(EC_Dst->y, EC_Dst->y, t1, ctx->ECC_p);

	for(i = 0; i < 2; i++)
	{
		for(j = 0; j < 9; j++)
		{
			free(Pw[i][j]);
		}
	}

	free(pbBuf);
	SDRM_MONT_Free(Mont);

	return CRYPTO_SUCCESS;
}

/***************************** End of File *****************************/
