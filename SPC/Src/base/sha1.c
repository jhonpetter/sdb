/* For torrentcheck.c, main() commented out */
/* sha1.c : Implementation of the Secure Hash Algorithm */

/* SHA: NIST's Secure Hash Algorithm */

/*	This version written November 2000 by David Ireland of 
	DI Management Services Pty Limited <code@di-mgt.com.au>

	Adapted from code in the Python Cryptography Toolkit, 
	version 1.0.0 by A.M. Kuchling 1995.
*/

/* AM Kuchling's posting:- 
   Based on SHA code originally posted to sci.crypt by Peter Gutmann
   in message <30ajo5$oe8@ccu2.auckland.ac.nz>.
   Modified to test for endianness on creation of SHA objects by AMK.
   Also, the original specification of SHA was found to have a weakness
   by NSA/NIST.  This code implements the fixed version of SHA.
*/

/* Here's the first paragraph of Peter Gutmann's posting:
   
The following is my SHA (FIPS 180) code updated to allow use of the "fixed"
SHA, thanks to Jim Gillogly and an anonymous contributor for the information on
what's changed in the new version.  The fix is a simple change which involves
adding a single rotate in the initial expansion function.  It is unknown
whether this is an optimal solution to the problem which was discovered in the
SHA or whether it's simply a bandaid which fixes the problem with a minimum of
effort (for example the reengineering of a great many Capstone chips).
*/

/* JS Park's posting:
	Modification for naming confilct.
	 - Attach prefix 'SDRM_SHA1_' for all function and constants.
	 - Change name of data context to 'SDRM_SHA1Context'
	endianTest code is modified to avoid gcc warning.
	Primitive data types are used, instead of user-defined data types.
	Prototypes are moved to header file.
	Not using functions are commented out.
 */


void SDRM_endianTest(int *endianness);

/* sha.c */

#include "sha1.h"

static void SDRM_SHAtoByte(unsigned char *output, unsigned int *input, unsigned int len);

/* The SHS block size and message digest sizes, in bytes */

#define SDRM_SHA1_DATASIZE    64
#define SDRM_SHA1_DIGESTSIZE  20


/* The SHS f()-functions.  The f1 and f3 functions can be optimized to
   save one boolean operation each - thanks to Rich Schroeppel,
   rcs@cs.arizona.edu for discovering this */

/*#define SDRM_SHA1_f1(x,y,z) ((x & y) | (~x & z))			     // Rounds  0-19 */
#define SDRM_SHA1_f1(x,y,z)   (z ^ (x & (y ^ z)))				 /* Rounds  0-19 */
#define SDRM_SHA1_f2(x,y,z)   (x ^ y ^ z)						 /* Rounds 20-39 */
/*#define SDRM_SHA1_f3(x,y,z) ((x & y) | (x & z) | (y & z))		 // Rounds 40-59 */
#define SDRM_SHA1_f3(x,y,z)   ((x & y) | (z & (x | y)))			 /* Rounds 40-59 */
#define SDRM_SHA1_f4(x,y,z)   (x ^ y ^ z)						 /* Rounds 60-79 */

/* The SHS Mysterious Constants */

#define SDRM_SHA1_K1  0x5A827999L                                 /* Rounds  0-19 */
#define SDRM_SHA1_K2  0x6ED9EBA1L                                 /* Rounds 20-39 */
#define SDRM_SHA1_K3  0x8F1BBCDCL                                 /* Rounds 40-59 */
#define SDRM_SHA1_K4  0xCA62C1D6L                                 /* Rounds 60-79 */

/* SHS initial values */

#define SDRM_SHA1_h0init  0x67452301L
#define SDRM_SHA1_h1init  0xEFCDAB89L
#define SDRM_SHA1_h2init  0x98BADCFEL
#define SDRM_SHA1_h3init  0x10325476L
#define SDRM_SHA1_h4init  0xC3D2E1F0L

/* Note that it may be necessary to add parentheses to these macros if they
   are to be called with expressions as arguments */
/* 32-bit rotate left - kludged with shifts */

#define SDRM_SHA1_ROTL(n, X)  (((X) << n) | ((X) >> (32 - n)))

/* The initial expanding function.  The hash function is defined over an
   80-UINT2 expanded input array W, where the first 16 are copies of the input
   data, and the remaining 64 are defined by

        W[ i ] = W[ i - 16 ] ^ W[ i - 14 ] ^ W[ i - 8 ] ^ W[ i - 3 ]

   This implementation generates these values on the fly in a circular
   buffer - thanks to Colin Plumb, colin@nyx10.cs.du.edu for this
   optimization.

   The updated SHS changes the expanding function by adding a rotate of 1
   bit.  Thanks to Jim Gillogly, jim@rand.org, and an anonymous contributor
   for this information */

#define SDRM_SHA1_expand(W, i) (W[i & 15] = SDRM_SHA1_ROTL(1, (W[i & 15] ^ W[(i - 14) & 15] ^ \
                                                 W[(i - 8) & 15] ^ W[(i - 3) & 15])))


/* The prototype SHS sub-round.  The fundamental sub-round is:

        a' = e + ROTL( 5, a ) + f( b, c, d ) + k + data;
        b' = a;
        c' = ROTL( 30, b );
        d' = c;
        e' = d;

   but this is implemented by unrolling the loop 5 times and renaming the
   variables ( e, a, b, c, d ) = ( a', b', c', d', e' ) each iteration.
   This code is then replicated 20 times for each of the 4 functions, using
   the next 20 values from the W[] array each time */

#define SDRM_SHA1_subRound(a, b, c, d, e, f, k, data) \
    (e += SDRM_SHA1_ROTL(5, a) + f(b, c, d) + k + data, b = SDRM_SHA1_ROTL(30, b))

/* Initialize the SHS values */

CRYPTOCORE_INTERNAL void SDRM_SHA1_Init(SDRM_SHA1Context  *shsInfo)
{
    SDRM_endianTest(&shsInfo->Endianness);
    /* Set the h-vars to their initial values */
    shsInfo->digest[ 0 ] = SDRM_SHA1_h0init;
    shsInfo->digest[ 1 ] = SDRM_SHA1_h1init;
    shsInfo->digest[ 2 ] = SDRM_SHA1_h2init;
    shsInfo->digest[ 3 ] = SDRM_SHA1_h3init;
    shsInfo->digest[ 4 ] = SDRM_SHA1_h4init;

    /* Initialise bit count */
    shsInfo->countLo = shsInfo->countHi = 0;
}


/* Perform the SHS transformation.  Note that this code, like MD5, seems to
   break some optimizing compilers due to the complexity of the expressions
   and the size of the basic block.  It may be necessary to split it into
   sections, e.g. based on the four subrounds

   Note that this corrupts the shsInfo->data area */

static void SDRM_SHSTransform(unsigned int *digest, unsigned int *data )
    {
    unsigned int A, B, C, D, E;     /* Local vars */
    unsigned int eData[ 16 ];       /* Expanded data */

    /* Set up first buffer and local data buffer */
    A = digest[ 0 ];
    B = digest[ 1 ];
    C = digest[ 2 ];
    D = digest[ 3 ];
    E = digest[ 4 ];
    memcpy( (unsigned char*)eData, (unsigned char*)data, SDRM_SHA1_DATASIZE );

    /* Heavy mangling, in 4 sub-rounds of 20 interations each. */
    SDRM_SHA1_subRound( A, B, C, D, E, SDRM_SHA1_f1, SDRM_SHA1_K1, eData[  0 ] );
    SDRM_SHA1_subRound( E, A, B, C, D, SDRM_SHA1_f1, SDRM_SHA1_K1, eData[  1 ] );
    SDRM_SHA1_subRound( D, E, A, B, C, SDRM_SHA1_f1, SDRM_SHA1_K1, eData[  2 ] );
    SDRM_SHA1_subRound( C, D, E, A, B, SDRM_SHA1_f1, SDRM_SHA1_K1, eData[  3 ] );
    SDRM_SHA1_subRound( B, C, D, E, A, SDRM_SHA1_f1, SDRM_SHA1_K1, eData[  4 ] );
    SDRM_SHA1_subRound( A, B, C, D, E, SDRM_SHA1_f1, SDRM_SHA1_K1, eData[  5 ] );
    SDRM_SHA1_subRound( E, A, B, C, D, SDRM_SHA1_f1, SDRM_SHA1_K1, eData[  6 ] );
    SDRM_SHA1_subRound( D, E, A, B, C, SDRM_SHA1_f1, SDRM_SHA1_K1, eData[  7 ] );
    SDRM_SHA1_subRound( C, D, E, A, B, SDRM_SHA1_f1, SDRM_SHA1_K1, eData[  8 ] );
    SDRM_SHA1_subRound( B, C, D, E, A, SDRM_SHA1_f1, SDRM_SHA1_K1, eData[  9 ] );
    SDRM_SHA1_subRound( A, B, C, D, E, SDRM_SHA1_f1, SDRM_SHA1_K1, eData[ 10 ] );
    SDRM_SHA1_subRound( E, A, B, C, D, SDRM_SHA1_f1, SDRM_SHA1_K1, eData[ 11 ] );
    SDRM_SHA1_subRound( D, E, A, B, C, SDRM_SHA1_f1, SDRM_SHA1_K1, eData[ 12 ] );
    SDRM_SHA1_subRound( C, D, E, A, B, SDRM_SHA1_f1, SDRM_SHA1_K1, eData[ 13 ] );
    SDRM_SHA1_subRound( B, C, D, E, A, SDRM_SHA1_f1, SDRM_SHA1_K1, eData[ 14 ] );
    SDRM_SHA1_subRound( A, B, C, D, E, SDRM_SHA1_f1, SDRM_SHA1_K1, eData[ 15 ] );
    SDRM_SHA1_subRound( E, A, B, C, D, SDRM_SHA1_f1, SDRM_SHA1_K1, SDRM_SHA1_expand( eData, 16 ) );
    SDRM_SHA1_subRound( D, E, A, B, C, SDRM_SHA1_f1, SDRM_SHA1_K1, SDRM_SHA1_expand( eData, 17 ) );
    SDRM_SHA1_subRound( C, D, E, A, B, SDRM_SHA1_f1, SDRM_SHA1_K1, SDRM_SHA1_expand( eData, 18 ) );
    SDRM_SHA1_subRound( B, C, D, E, A, SDRM_SHA1_f1, SDRM_SHA1_K1, SDRM_SHA1_expand( eData, 19 ) );

    SDRM_SHA1_subRound( A, B, C, D, E, SDRM_SHA1_f2, SDRM_SHA1_K2, SDRM_SHA1_expand( eData, 20 ) );
    SDRM_SHA1_subRound( E, A, B, C, D, SDRM_SHA1_f2, SDRM_SHA1_K2, SDRM_SHA1_expand( eData, 21 ) );
    SDRM_SHA1_subRound( D, E, A, B, C, SDRM_SHA1_f2, SDRM_SHA1_K2, SDRM_SHA1_expand( eData, 22 ) );
    SDRM_SHA1_subRound( C, D, E, A, B, SDRM_SHA1_f2, SDRM_SHA1_K2, SDRM_SHA1_expand( eData, 23 ) );
    SDRM_SHA1_subRound( B, C, D, E, A, SDRM_SHA1_f2, SDRM_SHA1_K2, SDRM_SHA1_expand( eData, 24 ) );
    SDRM_SHA1_subRound( A, B, C, D, E, SDRM_SHA1_f2, SDRM_SHA1_K2, SDRM_SHA1_expand( eData, 25 ) );
    SDRM_SHA1_subRound( E, A, B, C, D, SDRM_SHA1_f2, SDRM_SHA1_K2, SDRM_SHA1_expand( eData, 26 ) );
    SDRM_SHA1_subRound( D, E, A, B, C, SDRM_SHA1_f2, SDRM_SHA1_K2, SDRM_SHA1_expand( eData, 27 ) );
    SDRM_SHA1_subRound( C, D, E, A, B, SDRM_SHA1_f2, SDRM_SHA1_K2, SDRM_SHA1_expand( eData, 28 ) );
    SDRM_SHA1_subRound( B, C, D, E, A, SDRM_SHA1_f2, SDRM_SHA1_K2, SDRM_SHA1_expand( eData, 29 ) );
    SDRM_SHA1_subRound( A, B, C, D, E, SDRM_SHA1_f2, SDRM_SHA1_K2, SDRM_SHA1_expand( eData, 30 ) );
    SDRM_SHA1_subRound( E, A, B, C, D, SDRM_SHA1_f2, SDRM_SHA1_K2, SDRM_SHA1_expand( eData, 31 ) );
    SDRM_SHA1_subRound( D, E, A, B, C, SDRM_SHA1_f2, SDRM_SHA1_K2, SDRM_SHA1_expand( eData, 32 ) );
    SDRM_SHA1_subRound( C, D, E, A, B, SDRM_SHA1_f2, SDRM_SHA1_K2, SDRM_SHA1_expand( eData, 33 ) );
    SDRM_SHA1_subRound( B, C, D, E, A, SDRM_SHA1_f2, SDRM_SHA1_K2, SDRM_SHA1_expand( eData, 34 ) );
    SDRM_SHA1_subRound( A, B, C, D, E, SDRM_SHA1_f2, SDRM_SHA1_K2, SDRM_SHA1_expand( eData, 35 ) );
    SDRM_SHA1_subRound( E, A, B, C, D, SDRM_SHA1_f2, SDRM_SHA1_K2, SDRM_SHA1_expand( eData, 36 ) );
    SDRM_SHA1_subRound( D, E, A, B, C, SDRM_SHA1_f2, SDRM_SHA1_K2, SDRM_SHA1_expand( eData, 37 ) );
    SDRM_SHA1_subRound( C, D, E, A, B, SDRM_SHA1_f2, SDRM_SHA1_K2, SDRM_SHA1_expand( eData, 38 ) );
    SDRM_SHA1_subRound( B, C, D, E, A, SDRM_SHA1_f2, SDRM_SHA1_K2, SDRM_SHA1_expand( eData, 39 ) );

    SDRM_SHA1_subRound( A, B, C, D, E, SDRM_SHA1_f3, SDRM_SHA1_K3, SDRM_SHA1_expand( eData, 40 ) );
    SDRM_SHA1_subRound( E, A, B, C, D, SDRM_SHA1_f3, SDRM_SHA1_K3, SDRM_SHA1_expand( eData, 41 ) );
    SDRM_SHA1_subRound( D, E, A, B, C, SDRM_SHA1_f3, SDRM_SHA1_K3, SDRM_SHA1_expand( eData, 42 ) );
    SDRM_SHA1_subRound( C, D, E, A, B, SDRM_SHA1_f3, SDRM_SHA1_K3, SDRM_SHA1_expand( eData, 43 ) );
    SDRM_SHA1_subRound( B, C, D, E, A, SDRM_SHA1_f3, SDRM_SHA1_K3, SDRM_SHA1_expand( eData, 44 ) );
    SDRM_SHA1_subRound( A, B, C, D, E, SDRM_SHA1_f3, SDRM_SHA1_K3, SDRM_SHA1_expand( eData, 45 ) );
    SDRM_SHA1_subRound( E, A, B, C, D, SDRM_SHA1_f3, SDRM_SHA1_K3, SDRM_SHA1_expand( eData, 46 ) );
    SDRM_SHA1_subRound( D, E, A, B, C, SDRM_SHA1_f3, SDRM_SHA1_K3, SDRM_SHA1_expand( eData, 47 ) );
    SDRM_SHA1_subRound( C, D, E, A, B, SDRM_SHA1_f3, SDRM_SHA1_K3, SDRM_SHA1_expand( eData, 48 ) );
    SDRM_SHA1_subRound( B, C, D, E, A, SDRM_SHA1_f3, SDRM_SHA1_K3, SDRM_SHA1_expand( eData, 49 ) );
    SDRM_SHA1_subRound( A, B, C, D, E, SDRM_SHA1_f3, SDRM_SHA1_K3, SDRM_SHA1_expand( eData, 50 ) );
    SDRM_SHA1_subRound( E, A, B, C, D, SDRM_SHA1_f3, SDRM_SHA1_K3, SDRM_SHA1_expand( eData, 51 ) );
    SDRM_SHA1_subRound( D, E, A, B, C, SDRM_SHA1_f3, SDRM_SHA1_K3, SDRM_SHA1_expand( eData, 52 ) );
    SDRM_SHA1_subRound( C, D, E, A, B, SDRM_SHA1_f3, SDRM_SHA1_K3, SDRM_SHA1_expand( eData, 53 ) );
    SDRM_SHA1_subRound( B, C, D, E, A, SDRM_SHA1_f3, SDRM_SHA1_K3, SDRM_SHA1_expand( eData, 54 ) );
    SDRM_SHA1_subRound( A, B, C, D, E, SDRM_SHA1_f3, SDRM_SHA1_K3, SDRM_SHA1_expand( eData, 55 ) );
    SDRM_SHA1_subRound( E, A, B, C, D, SDRM_SHA1_f3, SDRM_SHA1_K3, SDRM_SHA1_expand( eData, 56 ) );
    SDRM_SHA1_subRound( D, E, A, B, C, SDRM_SHA1_f3, SDRM_SHA1_K3, SDRM_SHA1_expand( eData, 57 ) );
    SDRM_SHA1_subRound( C, D, E, A, B, SDRM_SHA1_f3, SDRM_SHA1_K3, SDRM_SHA1_expand( eData, 58 ) );
    SDRM_SHA1_subRound( B, C, D, E, A, SDRM_SHA1_f3, SDRM_SHA1_K3, SDRM_SHA1_expand( eData, 59 ) );

    SDRM_SHA1_subRound( A, B, C, D, E, SDRM_SHA1_f4, SDRM_SHA1_K4, SDRM_SHA1_expand( eData, 60 ) );
    SDRM_SHA1_subRound( E, A, B, C, D, SDRM_SHA1_f4, SDRM_SHA1_K4, SDRM_SHA1_expand( eData, 61 ) );
    SDRM_SHA1_subRound( D, E, A, B, C, SDRM_SHA1_f4, SDRM_SHA1_K4, SDRM_SHA1_expand( eData, 62 ) );
    SDRM_SHA1_subRound( C, D, E, A, B, SDRM_SHA1_f4, SDRM_SHA1_K4, SDRM_SHA1_expand( eData, 63 ) );
    SDRM_SHA1_subRound( B, C, D, E, A, SDRM_SHA1_f4, SDRM_SHA1_K4, SDRM_SHA1_expand( eData, 64 ) );
    SDRM_SHA1_subRound( A, B, C, D, E, SDRM_SHA1_f4, SDRM_SHA1_K4, SDRM_SHA1_expand( eData, 65 ) );
    SDRM_SHA1_subRound( E, A, B, C, D, SDRM_SHA1_f4, SDRM_SHA1_K4, SDRM_SHA1_expand( eData, 66 ) );
    SDRM_SHA1_subRound( D, E, A, B, C, SDRM_SHA1_f4, SDRM_SHA1_K4, SDRM_SHA1_expand( eData, 67 ) );
    SDRM_SHA1_subRound( C, D, E, A, B, SDRM_SHA1_f4, SDRM_SHA1_K4, SDRM_SHA1_expand( eData, 68 ) );
    SDRM_SHA1_subRound( B, C, D, E, A, SDRM_SHA1_f4, SDRM_SHA1_K4, SDRM_SHA1_expand( eData, 69 ) );
    SDRM_SHA1_subRound( A, B, C, D, E, SDRM_SHA1_f4, SDRM_SHA1_K4, SDRM_SHA1_expand( eData, 70 ) );
    SDRM_SHA1_subRound( E, A, B, C, D, SDRM_SHA1_f4, SDRM_SHA1_K4, SDRM_SHA1_expand( eData, 71 ) );
    SDRM_SHA1_subRound( D, E, A, B, C, SDRM_SHA1_f4, SDRM_SHA1_K4, SDRM_SHA1_expand( eData, 72 ) );
    SDRM_SHA1_subRound( C, D, E, A, B, SDRM_SHA1_f4, SDRM_SHA1_K4, SDRM_SHA1_expand( eData, 73 ) );
    SDRM_SHA1_subRound( B, C, D, E, A, SDRM_SHA1_f4, SDRM_SHA1_K4, SDRM_SHA1_expand( eData, 74 ) );
    SDRM_SHA1_subRound( A, B, C, D, E, SDRM_SHA1_f4, SDRM_SHA1_K4, SDRM_SHA1_expand( eData, 75 ) );
    SDRM_SHA1_subRound( E, A, B, C, D, SDRM_SHA1_f4, SDRM_SHA1_K4, SDRM_SHA1_expand( eData, 76 ) );
    SDRM_SHA1_subRound( D, E, A, B, C, SDRM_SHA1_f4, SDRM_SHA1_K4, SDRM_SHA1_expand( eData, 77 ) );
    SDRM_SHA1_subRound( C, D, E, A, B, SDRM_SHA1_f4, SDRM_SHA1_K4, SDRM_SHA1_expand( eData, 78 ) );
    SDRM_SHA1_subRound( B, C, D, E, A, SDRM_SHA1_f4, SDRM_SHA1_K4, SDRM_SHA1_expand( eData, 79 ) );

    /* Build message digest */
    digest[ 0 ] += A;
    digest[ 1 ] += B;
    digest[ 2 ] += C;
    digest[ 3 ] += D;
    digest[ 4 ] += E;
    }

/* When run on a little-endian CPU we need to perform byte reversal on an
   array of long words. */

static void SDRM_longReverse(unsigned int *buffer, int byteCount, int Endianness)
{
    unsigned int value;

    if (Endianness == !(0)) return;
    byteCount /= sizeof( unsigned int );
    while(byteCount--)
    {
        value = *buffer;
        value = ((value & 0xFF00FF00L) >> 8) | \
                ((value & 0x00FF00FFL ) << 8);
         *buffer++ = (value << 16) | (value >> 16);
	}
}

/* Update SHS for a block of data */

CRYPTOCORE_INTERNAL void SDRM_SHA1_Update(SDRM_SHA1Context  *shsInfo, const unsigned char *buffer, int count)
{
    unsigned int	tmp;
    int		dataCount;

    /* Update bitcount */
    tmp = shsInfo->countLo;
    if ((shsInfo->countLo = tmp + ((unsigned int)count << 3)) < tmp)
        shsInfo->countHi++;             /* Carry from low to high */

    shsInfo->countHi += count >> 29;

    /* Get count of bytes already in data */
    dataCount = (int)(tmp >> 3) & 0x3F;

    /* Handle any leading odd-sized chunks */
    if (dataCount)
    {
        unsigned char *p = (unsigned char*) shsInfo->data + dataCount;

        dataCount = SDRM_SHA1_DATASIZE - dataCount;
        if(count < dataCount)
        {
            memcpy(p, buffer, count);
            return;
        }
        memcpy(p, buffer, dataCount);
        SDRM_longReverse(shsInfo->data, SDRM_SHA1_DATASIZE, shsInfo->Endianness);
        SDRM_SHSTransform(shsInfo->digest, shsInfo->data);
        buffer += dataCount;
        count -= dataCount;
    }

    /* Process data in SHS_DATASIZE chunks */
    while(count >= SDRM_SHA1_DATASIZE)
    {
        memcpy((unsigned char*)shsInfo->data, buffer, SDRM_SHA1_DATASIZE);
        SDRM_longReverse(shsInfo->data, SDRM_SHA1_DATASIZE, shsInfo->Endianness);
        SDRM_SHSTransform(shsInfo->digest, shsInfo->data);
        buffer += SDRM_SHA1_DATASIZE;
        count -= SDRM_SHA1_DATASIZE;
    }

    /* Handle any remaining bytes of data. */
    memcpy( (unsigned char*)shsInfo->data, buffer, count);
    }

/* Final wrapup - pad to SHS_DATASIZE-byte boundary with the bit pattern
   1 0* (64-bit count of bits processed, MSB-first) */

CRYPTOCORE_INTERNAL void SDRM_SHA1_Final(SDRM_SHA1Context  *shsInfo, unsigned char *output)
{
    int count;
    unsigned char *dataPtr;

    /* Compute number of bytes mod 64 */
    count = (int) shsInfo->countLo;
    count = (count >> 3) & 0x3F;

    /* Set the first char of padding to 0x80.  This is safe since there is
       always at least one byte free */
    dataPtr = (unsigned char*) shsInfo->data + count;
    *dataPtr++ = 0x80;

    /* Bytes of padding needed to make 64 bytes */
    count = SDRM_SHA1_DATASIZE - 1 - count;

    /* Pad out to 56 mod 64 */
    if( count < 8 )
    {
        /* Two lots of padding:  Pad the first block to 64 bytes */
        memset(dataPtr, 0, count);
        SDRM_longReverse(shsInfo->data, SDRM_SHA1_DATASIZE, shsInfo->Endianness);
        SDRM_SHSTransform(shsInfo->digest, shsInfo->data);

        /* Now fill the next block with 56 bytes */
        memset((unsigned char*)shsInfo->data, 0, SDRM_SHA1_DATASIZE - 8);
    }
    else
        /* Pad block to 56 bytes */
        memset(dataPtr, 0, count - 8);

    /* Append length in bits and transform */
    shsInfo->data[14] = shsInfo->countHi;
    shsInfo->data[15] = shsInfo->countLo;

    SDRM_longReverse(shsInfo->data, SDRM_SHA1_DATASIZE - 8, shsInfo->Endianness);
    SDRM_SHSTransform(shsInfo->digest, shsInfo->data);

	/* Output to an array of bytes */
	SDRM_SHAtoByte(output, shsInfo->digest, SDRM_SHA1_DIGESTSIZE);

	/* Zeroise sensitive stuff */
	memset((unsigned char*)shsInfo, 0, sizeof(SDRM_SHA1Context));
}

static void SDRM_SHAtoByte(unsigned char *output, unsigned int *input, unsigned int len)
{	/* Output SHA digest in byte array */
	unsigned int i, j;

	for(i = 0, j = 0; j < len; i++, j += 4) 
	{
        output[j+3] = (unsigned char)( input[i]        & 0xff);
        output[j+2] = (unsigned char)((input[i] >> 8 ) & 0xff);
        output[j+1] = (unsigned char)((input[i] >> 16) & 0xff);
        output[j  ] = (unsigned char)((input[i] >> 24) & 0xff);
	}
}


//unsigned char digest[20];
//unsigned char message[3] = {'a', 'b', 'c' };
//unsigned char *mess56 = 
//	"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

/* Correct solutions from FIPS PUB 180-1 */
//char *dig1 = "A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D";
//char *dig2 = "84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1";
//char *dig3 = "34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F";

/* Output should look like:-
 a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d
 A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D <= correct
 84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1
 84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1 <= correct
 34aa973c d4c4daa4 f61eeb2b dbad2731 6534016f
 34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F <= correct
*/

//main()
//{
//	SHA_CTX sha;
//	int i;
//	BYTE big[1000];
//
//	SHAInit(&sha);
//	SHAUpdate(&sha, message, 3);
//	SHAFinal(digest, &sha);
//
//	for (i = 0; i < 20; i++)
//	{
//		if ((i % 4) == 0) printf(" ");
//		printf("%02x", digest[i]);
//	}
//	printf("\n");
//	printf(" %s <= correct\n", dig1);
//
//	SHAInit(&sha);
//	SHAUpdate(&sha, mess56, 56);
//	SHAFinal(digest, &sha);
//
//	for (i = 0; i < 20; i++)
//	{
//		if ((i % 4) == 0) printf(" ");
//		printf("%02x", digest[i]);
//	}
//	printf("\n");
//	printf(" %s <= correct\n", dig2);
//
//	/* Fill up big array */
//	for (i = 0; i < 1000; i++)
//		big[i] = 'a';
//
//	SHAInit(&sha);
//	/* Digest 1 million x 'a' */
//	for (i = 0; i < 1000; i++)
//		SHAUpdate(&sha, big, 1000);
//	SHAFinal(digest, &sha);
//
//	for (i = 0; i < 20; i++)
//	{
//		if ((i % 4) == 0) printf(" ");
//		printf("%02x", digest[i]);
//	}
//	printf("\n");
//	printf(" %s <= correct\n", dig3);
//
//	return 0;
//}

/* endian.c */

CRYPTOCORE_INTERNAL void SDRM_endianTest(int *endian_ness)
{
    static short test = 1;

    if ( *((char *) &test) != 1)
    {
		/* printf("Big endian = no change\n"); */
		*endian_ness = !(0);
    }
    else
    {
		/* printf("Little endian = swap\n"); */
		*endian_ness = 0;
    }
}

/***************************** End of File *****************************/

