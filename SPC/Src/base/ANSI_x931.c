/**
 * \file	ANSI_x931.c
 * @brief	Pseudorandom number generator based on a design described in ANSI X9.31
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : Junbum Shin
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/08/23
 * Edited : Use date data, and update seed, by Jisoon Park, 06/11/08
 */

////////////////////////////////////////////////////////////////////////////
// Include Header Files
////////////////////////////////////////////////////////////////////////////
#include <time.h>
#include "aes.h"
#include "ANSI_x931.h"

////////////////////////////////////////////////////////////////////////////
// Constants
////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////
// Functions
////////////////////////////////////////////////////////////////////////////
/*
 * @fn		SDRM_RNG_X931
 * @brief	generate random number with seed
 *
 * @param	Seed				[in]seed for RNG System
 * @param	bitLength			[in]bit length of data to generate
 * @param	data				[out]generated data
 *
 * @return	CRYPTO_SUCCESS		if success
 */
CRYPTOCORE_INTERNAL int	SDRM_RNG_X931(cc_u8 *Si_ANSI_X9_31, cc_u32 bitLength, cc_u8 *data)
{
	static cc_u8 K_ANSI_X9_31[SDRM_X931_SEED_SIZ] = {0xfd, 0x74, 0x3d, 0xe1, 0xdc, 0x08, 0xdc, 0x3d, 0x0f, 0xea, 0xf5, 0xa3, 0x6e, 0xb1, 0xc0, 0x7f};
	int		res = CRYPTO_SUCCESS;
	int		i, offset; 
	int		byteLength, residue; 
	int		numBlock, residueBlock;
	cc_u8	*DT;
	cc_u8	I[SDRM_X931_SEED_SIZ] = {0};
	cc_u8	Ri_ANSI_X9_31[SDRM_X931_SEED_SIZ];
	cc_u32	Date[SDRM_X931_SEED_SIZ / 4];
	cc_u32	RoundKey[4*(10 + 1)];			//AES Round Key

	time_t nowTime;

	time(&nowTime);
	Date[0] = (cc_u32)nowTime;
	Date[1] = clock();
	Date[2] = rand();
	Date[3] = rand();

	DT = (cc_u8*)Date;						//DT : Time | Clock | RND | RND

	SDRM_rijndaelKeySetupDec(RoundKey, K_ANSI_X9_31, 128);

	byteLength = bitLength / 8 ; 
	residue = bitLength - byteLength * 8; 

	if (residue == 0)
	{
		memset(data, 0x0, byteLength); 
	}
	else
	{
		byteLength += 1; 
		memset(data, 0x0, byteLength); 
	}

	numBlock = byteLength / SDRM_X931_SEED_SIZ; 
	residueBlock = byteLength - numBlock * SDRM_X931_SEED_SIZ; 
	offset = 0; 

	for(i = 0; i < numBlock; i++)
	{
		SDRM_rijndaelDecrypt(RoundKey, 10, DT, I);
		BlockXor(I, I, Si_ANSI_X9_31); 

		SDRM_rijndaelDecrypt(RoundKey, 10, I, Ri_ANSI_X9_31);
		BlockXor(I, I, Ri_ANSI_X9_31); 

		SDRM_rijndaelDecrypt(RoundKey, 10, I, Si_ANSI_X9_31);
		memcpy(data + offset, Ri_ANSI_X9_31, SDRM_X931_SEED_SIZ); 
		offset += SDRM_X931_SEED_SIZ; 		
	}

	if (residueBlock != 0)
	{
		SDRM_rijndaelDecrypt(RoundKey, 10, DT, I);
		BlockXor(I, I, Si_ANSI_X9_31); 

		SDRM_rijndaelDecrypt(RoundKey, 10, I, Ri_ANSI_X9_31);
		BlockXor(I, I, Ri_ANSI_X9_31); 

		SDRM_rijndaelDecrypt(RoundKey, 10, I, Si_ANSI_X9_31);
		memcpy(data + offset, Ri_ANSI_X9_31, residueBlock); 
	}

	BlockXor(Si_ANSI_X9_31, I, Si_ANSI_X9_31);

	return res;
}

/***************************** End of File *****************************/
