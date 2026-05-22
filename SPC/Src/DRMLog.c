#include <time.h>
#if defined(_WIN32_WCE)
#include <winbase.h>
#endif
#include "DRMLog.h"

void DRMLOG_API DRMLOG_SetFormat(DRMLOG_CTX* ctx, int format)
{
	if (ctx == NULL)
	{
		return;
	}

	ctx->format = format;
}

void DRMLOG_API DRMLOG_SetLevel(DRMLOG_CTX* ctx, int level)
{
	if ((ctx == NULL) || ((level < LOG_DEBUG) && (level > LOG_FATAL)))
	{
		return;
	}

	ctx->level = level;
}

void DRMLOG_API DRMLOG_SetOutput(DRMLOG_CTX* ctx, FILE *output_file)
{
	if (ctx == NULL)
	{
		return;
	}

	ctx->file = output_file;
}

static void PrintHeader(DRMLOG_CTX* ctx, int level, const char* filename, int line_number)
{
#ifdef _DRMLOG_DISABLE
	return;
#else

#if defined(_WIN32_WCE)
	SYSTEMTIME stm;
#else
	time_t long_time;
	struct tm* tm;
#endif

	static const char* _level_str[] = {"DEBUG", "INFO", "WARN", "ERROR", "FATAL"};

	if(ctx == NULL)
	{
		return;
	}

	// level
	if (ctx->format & LOG_FORMAT_LEVEL)
	{
		fprintf(ctx->file, "[%s]", _level_str[level-1]);
	}

	// tick
	if (ctx->format & LOG_FORMAT_TICK)
	{
		#if defined(_WIN32_WCE)
			fprintf(ctx->file, "[%ul]", GetTickCount());
		#endif
	}

	// date / time
	if (ctx->format & LOG_FORMAT_TIME)
	{
		#ifdef _WIN32_WCE
			GetSystemTime(&stm);
			fprintf(ctx->file, "[%04d/%02d/%02d,%02d:%02d:%02d.%03d]", 
				stm.wYear, stm.wMonth, stm.wDay, stm.wHour, stm.wMinute, stm.wSecond, stm.wMilliseconds);
		#else
			time(&long_time);
			tm = localtime(&long_time);
			fprintf(ctx->file, "[%04d/%02d/%02d,%02d:%02d:%02d]", 
				tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
		#endif
	}

	// file and line-number
	if(ctx->format & LOG_FORMAT_FILE)
	{
		char* file_name;
		#if defined(_WIN32) || defined(_WIN32_WCE)
			file_name = strrchr(filename, '\\');
		#else
			file_name = strrchr(filename, '/');
		#endif
		fprintf(ctx->file, "[%s:%d]", (file_name ? (file_name + 1) : filename), line_number);
	}
#endif
}

void DRMLOG_API DRMLOG_Message(DRMLOG_CTX* ctx, int level, const char* file_name, int line_number, const char* format, ...)
{
#ifdef _DRMLOG_DISABLE
	return;
#else
	if ((ctx != NULL) && (ctx->file != NULL) && (ctx->level <= level))
	{
		va_list lArg;
		char log_buffer[LOG_BUFFER_LEN] = {0};

		va_start(lArg, format);
		vsprintf(log_buffer, format, lArg);
		va_end(lArg);
				
		PrintHeader(ctx, level, file_name, line_number);
		fprintf(ctx->file, "%s", log_buffer);
		fflush(ctx->file);
	}
#endif
}

void DRMLOG_API DRMLOG_HexaBytes(DRMLOG_CTX* ctx, int level, const char* file_name, int line_number, 
									 const char* szMsg, const unsigned char* bytes, int len)
{
#ifdef _DRMLOG_DISABLE
	return;
#else
	int idx;
	if ((ctx != NULL) && (ctx->file != NULL) && (ctx->level <= level))
	{
		PrintHeader(ctx, level, file_name, line_number);
		fprintf(ctx->file, "%s =>\n", szMsg);
		for(idx = 0; idx < (int)len; idx++)
		{
			if((idx != 0) && ((idx % 16) == 0))
			{
				fprintf(ctx->file, "\n");
			}

			if ((idx % 4) == 0)
			{
				fprintf(ctx->file, " 0x");
			}

			fprintf(ctx->file, "%.2x", bytes[idx]);
		}

		fprintf(ctx->file, "\n");
		fflush(ctx->file);
	}
#endif
}
