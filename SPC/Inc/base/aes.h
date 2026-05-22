/**
 * rijndael-alg-fst.h
 *
 * @version 3.0 (December 2000)
 *
 * Optimised ANSI C code for the Rijndael cipher (now AES)
 *
 * @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 * @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
 * @author Paulo Barreto <paulo.barreto@terra.com.br>
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _AES_H
#define _AES_H

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include "CryptoCore.h"

////////////////////////////////////////////////////////////////////////////
// Function Prototypes
////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @fn		SDRM_rijndaelKeySetupEnc
 * @brief	Expand the cipher key into the encryption key schedule
 *
 * @param	rk					[out]expanded round key
 * @param	cipherKey			[in]user key
 * @param	keyBits				[in]bit-length of cipherKey
 *
 * @return	the number of rounds for the given cipher key size
 */
CRYPTOCORE_INTERNAL int SDRM_rijndaelKeySetupEnc(cc_u32 rk[/*4*(Nr + 1)*/], const cc_u8 cipherKey[], int keyBits);

/*
 * @fn		SDRM_rijndaelKeySetupDec
 * @brief	Expand the cipher key into the decryption key schedule
 *
 * @param	rk					[out]expanded round key
 * @param	cipherKey			[in]user key
 * @param	keyBits				[in]bit-length of cipherKey
 *
 * @return	the number of rounds for the given cipher key size
 */
CRYPTOCORE_INTERNAL int SDRM_rijndaelKeySetupDec(cc_u32 rk[/*4*(Nr + 1)*/], const cc_u8 cipherKey[], int keyBits);

/*
 * @fn		SDRM_rijndaelEncrypt
 * @brief	16 byte AES Encryption with round key
 *
 * @param	rk					[in]expanded round key
 * @param	Nr					[in]numer of rounds
 * @param	pt					[in]plain text
 * @param	ct					[out]cipher text
 *
 * @return	void
 */
CRYPTOCORE_INTERNAL void SDRM_rijndaelEncrypt(const cc_u32 rk[/*4*(Nr + 1)*/], int Nr, const cc_u8 pt[16], cc_u8 ct[16]);

/*
 * @fn		SDRM_rijndaelDecrypt
 * @brief	16 byte AES Decryption with round key
 *
 * @param	rk					[in]expanded round key
 * @param	Nr					[in]numer of rounds
 * @param	ct					[in]cipher text
 * @param	pt					[out]plain text
 *
 * @return	void
 */
CRYPTOCORE_INTERNAL void SDRM_rijndaelDecrypt(const cc_u32 rk[/*4*(Nr + 1)*/], int Nr, const cc_u8 ct[16], cc_u8 pt[16]);

/*
 * @fn		SDRM_AES128_Encryption
 * @brief	AES-128 Encryption
 *
 * @param	cipherText	[out]encrypted text
 * @param	plainText	[in]plain text
 * @param	UserKey		[in]user key
 *
 * @return	CRYPTO_SUCCESS if success
 */
CRYPTOCORE_INTERNAL int SDRM_AES128_Encryption(cc_u8 *cipherText, cc_u8 *plainText, cc_u8 *UserKey);

/*
 * @fn		SDRM_AES128_Decryption
 * @brief	AES-128 Decryption
 *
 * @param	plainText	[out]decrypted text
 * @param	cipherText	[in]cipher text
 * @param	UserKey		[in]user key
 *
 * @return	CRYPTO_SUCCESS if success
 */
CRYPTOCORE_INTERNAL int SDRM_AES128_Decryption(cc_u8 *plainText, cc_u8 *cipherText, cc_u8 *UserKey);

/*
 * @fn		SDRM_AES192_Encryption
 * @brief	AES-192 Encryption
 *
 * @param	cipherText	[out]encrypted text
 * @param	plainText	[in]plain text
 * @param	UserKey		[in]user key
 *
 * @return	CRYPTO_SUCCESS if success
 */
CRYPTOCORE_INTERNAL int SDRM_AES192_Encryption(cc_u8 *cipherText, cc_u8 *plainText,	cc_u8 *UserKey);

/*
 * @fn		SDRM_AES192_Decryption
 * @brief	AES-192 Decryption
 *
 * @param	plainText	[out]decrypted text
 * @param	cipherText	[in]cipher text
 * @param	UserKey		[in]user key
 *
 * @return	CRYPTO_SUCCESS if success
 */
CRYPTOCORE_INTERNAL int SDRM_AES192_Decryption(cc_u8 *plainText, cc_u8 *cipherText,	cc_u8 *UserKey);

/*
 * @fn		SDRM_AES256_Encryption
 * @brief	AES-256 Encryption
 *
 * @param	cipherText	[out]encrypted text
 * @param	plainText	[in]plain text
 * @param	UserKey		[in]user key
 *
 * @return	CRYPTO_SUCCESS if success
 */
CRYPTOCORE_INTERNAL int SDRM_AES256_Encryption(cc_u8 *cipherText, cc_u8 *plainText,	cc_u8 *UserKey);

/*
 * @fn		SDRM_AES256_Decryption
 * @brief	AES-256 Decryption
 *
 * @param	plainText	[out]decrypted text
 * @param	cipherText	[in]cipher text
 * @param	UserKey		[in]user key
 *
 * @return	CRYPTO_SUCCESS if success
 */
CRYPTOCORE_INTERNAL int SDRM_AES256_Decryption(cc_u8 *plainText, cc_u8 *cipherText,	cc_u8 *UserKey);

#ifdef __cplusplus
}
#endif

#endif

/***************************** End of File *****************************/
