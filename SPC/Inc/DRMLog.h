#ifndef _DRMLOG_H_
#define _DRMLOG_H_

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#ifdef _MSC_VER
	#ifdef DRMLOG_EXPORTS
		#define DRMLOG_API __declspec(dllexport) __cdecl
	#elif defined(DRMLOG_DLL)
		#define DRMLOG_API __declspec(dllimport) __cdecl
	#else
		#define DRMLOG_API __cdecl
	#endif
#elif __linux
		#define DRMLOG_API
#else
		#define DRMLOG_API __attribute__((cdecl))
#endif

#define LOG_BUFFER_LEN		1024

typedef struct
{
	FILE* file;
	int level;
	int format;
} DRMLOG_CTX;


/* Log level */
typedef enum
{
	LOG_DEBUG	= 1,
	LOG_INFO	= 2,
	LOG_WARN	= 3,
	LOG_ERROR	= 4,
	LOG_FATAL	= 5
} DRMLOG_LEVEL;


/* Constants for logging format */
typedef enum
{
	LOG_FORMAT_LEVEL	= 0x0001,
	LOG_FORMAT_TICK		= 0x0002,
	LOG_FORMAT_TIME		= 0x0004,
	LOG_FORMAT_FILE		= 0x0008,
	LOG_FORMAT_ALL		= 0x000F
} DRMLOG_FORMAT;

/* Macro Functions */
//#define DRMLOG_Msg(CTX, LEV, ...) DRMLOG_Message(CTX, LEV, __FILE__, __LINE__, __VA_ARGS__)
#define DRMLOG_Msg(CTX, LEV, ...)				DRMLOG_Message(CTX, LEV, __FILE__, __LINE__, ##__VA_ARGS__)
#define DRMLOG_Hexa(CTX, LEV, MSG, BUF, LEN)	DRMLOG_HexaBytes(CTX, LEV, __FILE__, __LINE__, MSG, BUF, LEN)

#ifdef __cplusplus
extern "C" {
#endif

/*! \brief Set log format
 * \param ctx log context
 * \param format log format(Ex. "LOG_FORMAT_LEVEL | LOG_FORMAT_TIME")
 */
void DRMLOG_API DRMLOG_SetFormat(DRMLOG_CTX* ctx, int format);

/*! \brief Set logging level
 * \param ctx log context
 * \param level logging level
 */
void DRMLOG_API DRMLOG_SetLevel(DRMLOG_CTX* ctx, int level);

/*! \brief Set \c FILE* to be written log strings
 * \param ctx log context
 * \param stream Destination \c FILE*. \c stdout can be used
 */
void DRMLOG_API DRMLOG_SetOutput(DRMLOG_CTX* ctx, FILE* output_file);

/*! \brief Log a message
 * \param ctx log context
 * \param level logging level
 * \param format [IN] formatted string like printf followed by variable number of arguments
 */
void DRMLOG_API DRMLOG_Message(DRMLOG_CTX* ctx, int level, const char* file_name, int line_number, const char* format, ...);

/*! \brief Log a byte array in hexadecimal format
 * \param ctx log context
 * \param level logging level
 * \param szMsg [IN] null-terminated string for short description
 * \param bytes [IN] Pointer to buffer to print
 * \param len length of \a bytes in bytes
 */
void DRMLOG_API DRMLOG_HexaBytes(DRMLOG_CTX* ctx, int level, const char* file_name, int line_number, 
								 const char* szMsg, const unsigned char* bytes, int len);

#ifdef __cplusplus
}
#endif

#endif // _DRMLOG_H_
