/**
 * \file	CryptoCore.h
 * @brief	main header file of crypto library
 *
 * - Copyright : Samsung Electronics CO.LTD.,
 *
 * \internal
 * Author : 
 * Dept : DRM Lab, Digital Media Laboratory
 * Creation date : 2006/08/02
 */

#ifndef _CRYPTOCORE_H
#define _CRYPTOCORE_H

#ifdef _USRDLL
	#if defined(CRYPTOLIB_EXPORTS)
		#define ECRYPTO_API __declspec(dllexport)
	#elif defined(CRYPTOLIB_IMPORTS)
		#define ECRYPTO_API __declspec(dllimport)
	#else
		#define ECRYPTO_API
	#endif
#else
	#define ECRYPTO_API
#endif

////////////////////////////////////////////////////////////////////////////
// Header File Include
////////////////////////////////////////////////////////////////////////////
#include <stdlib.h>
#include <string.h>
#include "CC_Type.h"
#include "drm_macro.h"
#include "CC_Constants.h"
#include "CC_Context.h"

#ifdef _WIN32_WCE
	#include <Winbase.h>
#else
	#include <time.h>
#endif

////////////////////////////////////////////////////////////////////////////
// Global Variable
////////////////////////////////////////////////////////////////////////////

#endif

/***************************** End of File *****************************/

