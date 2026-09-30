#pragma once
#include <ntifs.h>


#define EACFUCKER_LOG_PATH L"\\??\\C:\\eacfucker\\eacfucker.log"

NTSTATUS LoggerInit(VOID);
VOID LoggerShutdown(VOID);
VOID LoggerPrint(const char* message);
VOID LoggerPrintF(const char* format, ...);