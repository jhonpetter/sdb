/**
 * \file	CC_Context.h
 * @brief	context definitions for samsung Crypto Library
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Jisoon, Park
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/11/07
 */

#ifndef _DRM_CONTEXT_H
#define _DRM_CONTEXT_H

#include "CC_Type.h"

////////////////////////////////////////////////////////////////////////////
// constant & context for Big Number Operation
////////////////////////////////////////////////////////////////////////////
/**
 * @brief	Big number structure
 *
 * used for big number representation
 */
typedef struct {						
	cc_u32 sign;						/**<	0 for positive, 1 for negative number	*/
	cc_u32 Length;						/**<	number of valid integers				*/
	cc_u32 Size;						/**<	unsigned long size of allocated memory	*/
	cc_u32 *pData;						/**<	unsigned long array					*/
} SDRM_BIG_NUM;

/**
 * @brief	Parameter sturcture
 *
 * Montgomery 알고리즘을 사용하기 위해 사용하는 Parameter structure
 */
typedef struct {						/**<	Structure to keep parameters for Montgomery	*/
	cc_u32	ri;							/**<	Length of Modulus							*/
	SDRM_BIG_NUM	*R;					/**<	R^2 mod m									*/
	SDRM_BIG_NUM	*Mod;				/**<	modulus										*/
	SDRM_BIG_NUM	*Inv_Mod;			/**<	Inverse of Modulus							*/
	cc_u32	N0;							/**<	m'											*/
} SDRM_BIG_MONT;

////////////////////////////////////////////////////////////////////////////
// constant & context for Elliptic Curve Crypto System
////////////////////////////////////////////////////////////////////////////
#define SDRM_ECC_BN_BUFSIZE			19				//allows max 256 bit curve(uint32_len * 2 + 3)
#define SDRM_ECC_ALLOC_SIZE			(sizeof(SDRM_BIG_NUM) + SDRM_ECC_BN_BUFSIZE * SDRM_SIZE_OF_DWORD)

/**
 * @brief	EC Point structure
 *
 * used for representation of one point at ECC curve
 */
typedef struct {
		cc_u32			IsInfinity;		/**<	if infinity , then 1  else 0		*/
		SDRM_BIG_NUM 	*x;				/**<	prime(1024 + 128i bits i=0..8)		*/
		SDRM_BIG_NUM 	*y;				/**<	subprime(128 + 32j bits j=0..4)		*/
		SDRM_BIG_NUM	*z;
		SDRM_BIG_NUM	*z2;
		SDRM_BIG_NUM	*z3;
} SDRM_EC_POINT;

/**
 * @brief	ECC Context structure
 *
 * used for parameters for ECC curve
 */
typedef struct {
		cc_u32				uDimension;		/**<	Dimension			*/
		SDRM_BIG_NUM 		*ECC_p;			/**<	GF(p)				*/
		SDRM_BIG_NUM 		*ECC_a;			/**<	y^2 = x^3 + ax + b	*/
		SDRM_BIG_NUM 		*ECC_b;
		SDRM_BIG_NUM 		*ECC_n;			/**<	order of base point	*/
		SDRM_EC_POINT 		*ECC_G;			/**<	Base point			*/
		SDRM_BIG_NUM 		*PRIV_KEY;		/**<	private key			*/
		SDRM_EC_POINT		*PUBLIC_KEY; 
} SDRM_ECC_CTX;

typedef SDRM_ECC_CTX		SDRM_ECDSAContext;
typedef SDRM_ECC_CTX		SDRM_ECELContext;
typedef SDRM_ECC_CTX		SDRM_ECDHContext;

////////////////////////////////////////////////////////////////////////////
// constant & context for ANSI X9.31 PRNG
////////////////////////////////////////////////////////////////////////////
#define SDRM_X931_SEED_SIZ		16

/**
 * @brief	X931 Context structure
 *
 * used for maintain seed vaule for random number generation
 */
typedef struct {
	cc_u8 Seed[SDRM_X931_SEED_SIZ];			/**<	Seed			*/
} SDRM_X931Context;

////////////////////////////////////////////////////////////////////////////
// constant & context for AES-128
////////////////////////////////////////////////////////////////////////////
#define SDRM_AES_BLOCK_SIZ	16

/**
 * @brief	AES Context structure
 *
 * used for aes parameters
 */
typedef struct {
	cc_u32	moo;							/**<	mode of operations		*/
	cc_u32	padding;						/**<	padding method			*/
	cc_u8	IV[SDRM_AES_BLOCK_SIZ];			/**<	Initial Vector			*/
	cc_u8	Block[SDRM_AES_BLOCK_SIZ];		/**<	remained msg block		*/
	cc_u32	BlockLen;						/**<	length of Block			*/
	cc_u8	RoundKey[16*(14 + 1)];			/**<	round key				*/
	cc_u32	CTR_Count;						/**<	counter for CTR mode	*/
} SDRM_AESContext;

////////////////////////////////////////////////////////////////////////////
// constant & context for SHA-1
////////////////////////////////////////////////////////////////////////////
#define SDRM_SHA1_BLOCK_SIZ		20
#define SDRM_SHA1_DATA_SIZE		64
/**
 * @brief	SHA1 Context structure
 *
 * used for SHA1 parameters
 */
typedef struct {
	cc_u32 digest[SDRM_SHA1_BLOCK_SIZ / 4];		/**<	Message digest		*/
	cc_u32 countLo, countHi;					/**<	64-bit bit count	*/
	cc_u32 data[16];							/**<	SHS data buffer		*/
	int Endianness;
} SDRM_SHA1Context;

////////////////////////////////////////////////////////////////////////////
// constant & context for SHA-256
////////////////////////////////////////////////////////////////////////////
#define SDRM_SHA256_BLOCK_SIZ		32
#define SDRM_SHA256_DATA_SIZE		(512 / 8)
/**
 * @brief	SHA256 Context structure
 *
 * used for SHA256 parameters
 */
typedef struct {
    cc_u32 tot_len;
    cc_u32 len;
    cc_u8 block[2 * SDRM_SHA256_DATA_SIZE];
    cc_u32 h[8];
} SDRM_SHA256Context;

#ifndef _OP64_NOTSUPPORTED

////////////////////////////////////////////////////////////////////////////
// constant & context for SHA-384
////////////////////////////////////////////////////////////////////////////
#define SDRM_SHA384_BLOCK_SIZ		48
#define SDRM_SHA384_DATA_SIZE		(1024 / 8)
/**
 * @brief	SHA384 Context structure
 *
 * used for SHA384 parameters
 */
typedef struct {
    cc_u32 tot_len;
    cc_u32 len;
    cc_u8 block[2 * SDRM_SHA384_DATA_SIZE];
    cc_u64 h[8];
} SDRM_SHA384Context;

////////////////////////////////////////////////////////////////////////////
// constant & context for SHA-512
////////////////////////////////////////////////////////////////////////////
#define SDRM_SHA512_BLOCK_SIZ		64
#define SDRM_SHA512_DATA_SIZE		SDRM_SHA384_DATA_SIZE
/**
 * @brief	SHA512 Context structure
 *
 * used for SHA512 parameters
 */
typedef SDRM_SHA384Context SDRM_SHA512Context;

#endif //_OP64_NOTSUPPORTED

////////////////////////////////////////////////////////////////////////////
// constant & context for SHA-224
////////////////////////////////////////////////////////////////////////////
#define SDRM_SHA224_BLOCK_SIZ		28
#define SDRM_SHA224_DATA_SIZE		SDRM_SHA256_DATA_SIZE
/**
 * \brief	SHA224 Context structure
 *
 * used for SHA224 parameters
 */
typedef SDRM_SHA256Context SDRM_SHA224Context;

////////////////////////////////////////////////////////////////////////////
// constant & context for MD5
////////////////////////////////////////////////////////////////////////////
#define SDRM_MD5_BLOCK_SIZ		16
#define SDRM_MD5_DATA_SIZE		64
/**
 * @brief	MD5 Context structure
 *
 * used for MD5 parameters
 */
typedef struct {
	cc_u32	state[4];							/**<	state *ABCD								*/
	cc_u32	count[2];							/**<	number of bits, modulo 2^64 (lsb first)	*/
	cc_u8	buffer[64];							/**<	input buffer							*/
} SDRM_MD5Context;

////////////////////////////////////////////////////////////////////////////
// constant & context for C-MAC Generation
////////////////////////////////////////////////////////////////////////////
/**
 * @brief	C-MAC Context structure
 *
 * used for aes parameters
 */
typedef struct {
	cc_u8	IV[SDRM_AES_BLOCK_SIZ];			/**<	Initial Vector		*/
	cc_u8	Block[SDRM_AES_BLOCK_SIZ];		/**<	remained msg block	*/
	cc_u32	BlockLen;							/**<	length of Block		*/
	cc_u8	K1[SDRM_AES_BLOCK_SIZ];
	cc_u8	K2[SDRM_AES_BLOCK_SIZ];
	cc_u8	RoundKey[16*(10 + 1)];
} SDRM_CMACContext;

////////////////////////////////////////////////////////////////////////////
// constant & context for H-MAC Generation
////////////////////////////////////////////////////////////////////////////
/**
 * @brief	C-MAC Context structure
 *
 * used for aes parameters
 */
typedef struct {
	cc_u32				algorithm;				/**<	algorithm			*/
	SDRM_SHA1Context	*sha1_ctx;				/**<	SHA-160 context		*/
	SDRM_SHA224Context	*sha224_ctx;			/**<	SHA-224 context		*/
	SDRM_SHA256Context	*sha256_ctx;			/**<	SHA-256 context		*/
#ifndef _OP64_NOTSUPPORTED
	SDRM_SHA384Context	*sha384_ctx;			/**<	SHA-384 context		*/
	SDRM_SHA512Context	*sha512_ctx;			/**<	SHA-512 context		*/
#endif //_OP64_NOTSUPPORTED
	SDRM_MD5Context		*md5_ctx;				/**<	MD5 context			*/

	cc_u32				B;
	cc_u8				*k0;
} SDRM_HMACContext;

////////////////////////////////////////////////////////////////////
// constant & context for RSA
////////////////////////////////////////////////////////////////////////////
#define SDRM_RSA_BN_BUFSIZE		(RSA_KeyByteLen / 2 + 1)
#define SDRM_RSA_ALLOC_SIZE		(sizeof(SDRM_BIG_NUM) + SDRM_RSA_BN_BUFSIZE * SDRM_SIZE_OF_DWORD)

/**
 * @brief	RSA Context structure
 *
 * used for rsa parameters
 */
typedef struct {
	SDRM_BIG_NUM* n;					/**<	n value		*/
	SDRM_BIG_NUM* e;					/**<	public key	*/
	SDRM_BIG_NUM* d;					/**<	private key	*/
	SDRM_BIG_NUM* p;					/**<	p			*/
	SDRM_BIG_NUM* q;					/**<	q			*/
	SDRM_BIG_NUM* dmodp1;				/**<	d mod p-1	*/
	SDRM_BIG_NUM* dmodq1;				/**<	d mod q-1	*/
	SDRM_BIG_NUM* iqmodp;				/**<	q^-1 mod p	*/

	cc_u32	crt_operation;				/**<	CRT Algorithm indicator	*/
	cc_u32	k;							/**<	byte-length of n	*/
	cc_u32	pm;							/**<	padding method		*/
	cc_u32	hash_algorithm;				/**<	used hash algorithm for pkcs padding	*/
} SDRM_RSAContext;

////////////////////////////////////////////////////////////////////////////
// constant & context for DSA
////////////////////////////////////////////////////////////////////////////
#define SDRM_DSA_BN_BUFSIZE			(128 / 2 + 1)
#define SDRM_DSA_ALLOC_SIZE			(sizeof(SDRM_BIG_NUM) + SDRM_DSA_BN_BUFSIZE * SDRM_SIZE_OF_DWORD)

/**
 * @brief	Parameter sturcture
 *
 * used for DSA parameters
 */
typedef struct {
	SDRM_BIG_NUM* p;					/**<	'p' value - prime modulus	*/
	SDRM_BIG_NUM* q;					/**<	'q' value - prime Divisor	*/
	SDRM_BIG_NUM* al;					/**<	'alpha' value - generator	*/
	SDRM_BIG_NUM* y;					/**<	'y' value - public key		*/
	SDRM_BIG_NUM* a;					/**<	'a' value - private key		*/
} SDRM_DSAContext;

////////////////////////////////////////////////////////////////////////////
// constant & context for RC4
////////////////////////////////////////////////////////////////////////////
typedef struct {
	cc_u32 keyLen;

	cc_u32	i;
	cc_u32	j;

	cc_u8	s[256];
	cc_u8	key[32];
} SDRM_RC4Context;

////////////////////////////////////////////////////////////////////////////
// constant & context for SNOW2
////////////////////////////////////////////////////////////////////////////
typedef struct {
	cc_u32	s[16];
	cc_u32	r1;
	cc_u32	r2;
	cc_u32	keyStream;
	cc_u32	usedKeyLen;

	cc_u32	t;
	cc_u32	endian;					//0 if little endian, 1 if bigendian

} SDRM_SNOW2Context;

////////////////////////////////////////////////////////////////////////////
// constant & context for DES
////////////////////////////////////////////////////////////////////////////
#define SDRM_DES_BLOCK_SIZ	8

/**
 * @brief	DES Context structure
 *
 * used for aes parameters
 */
typedef struct {
	cc_u32	moo;							//mode of operations
	cc_u32	padding;
	cc_u8	IV[SDRM_DES_BLOCK_SIZ];				//Initial Vector
	cc_u8	UserKey[SDRM_DES_BLOCK_SIZ];
	cc_u8	Block[SDRM_DES_BLOCK_SIZ];
	cc_u32	BlockLen;
	cc_u32	RoundKey[16][2];				//each round key, expanded
	cc_u32	CTR_Count;
} SDRM_DESContext;

////////////////////////////////////////////////////////////////////////////
// constant & context for Triple DES
////////////////////////////////////////////////////////////////////////////
#define SDRM_TDES_BLOCK_SIZ	SDRM_DES_BLOCK_SIZ

/**
 * @brief	DES Context structure
 *
 * used for aes parameters
 */
typedef struct {
	cc_u32	moo;							//mode of operations
	cc_u32	padding;
	cc_u8	IV[SDRM_DES_BLOCK_SIZ];				//Initial Vector
	cc_u8	UserKey[SDRM_DES_BLOCK_SIZ * 3];
	cc_u8	Block[SDRM_DES_BLOCK_SIZ];
	cc_u32	BlockLen;
	cc_u32	RoundKey[48][2];				//each round key, expanded
	cc_u32	CTR_Count;
} SDRM_TDESContext;

////////////////////////////////////////////////////////////////////////////
// constant & context for Deffie-Hellman protocol
////////////////////////////////////////////////////////////////////////////
/**
 * @brief	Diffie-Hellman Context structure
 *
 * used for dh parameters
 */
typedef struct {
	unsigned int PrimeLen;				/**<	length of prime	*/
	SDRM_BIG_NUM* p;					/**<	Prime			*/
	SDRM_BIG_NUM* g;					/**<	generator		*/
} SDRM_DHContext;

#endif

/***************************** End of File *****************************/
