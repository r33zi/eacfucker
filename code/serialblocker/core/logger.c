#include "logger.h"
#include "types.h"
#include "strings.h"

static HANDLE g_LogHandle = NULL;
static BOOLEAN g_LogReady = FALSE;

NTSTATUS LoggerInit(VOID)
{
    if (g_LogReady) return STATUS_SUCCESS;

    UNICODE_STRING logPath;
    RtlInitUnicodeString(&logPath, EACFUCKER_LOG_PATH);

    OBJECT_ATTRIBUTES logAttributes;
    InitializeObjectAttributes(&logAttributes, &logPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    IO_STATUS_BLOCK iosb;
    NTSTATUS status = ZwCreateFile(
        &g_LogHandle,
        FILE_APPEND_DATA | SYNCHRONIZE,
        &logAttributes,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[EACFucker] Logger init failed: 0x%X\n", status);
        return status;
    }

    g_LogReady = TRUE;
    LoggerPrint("-- EACFucker driver loaded --\n");
    return STATUS_SUCCESS;
}

VOID LoggerShutdown(VOID)
{
    if (g_LogHandle) {
        LoggerPrint("-- EACFucker driver unloaded --\n");
        ZwClose(g_LogHandle);
        g_LogHandle = NULL;
    }
    g_LogReady = FALSE;
}

VOID LoggerPrint(const char* message)
{
    if (!message) return;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[EACFucker] %s", message);

    if (g_LogHandle && g_LogReady) {
        IO_STATUS_BLOCK iosb;
        SIZE_T len = 0;
        const char* p = message;
        while (*p && len < 500) { p++; len++; }

        ZwWriteFile(g_LogHandle, NULL, NULL, NULL, &iosb,
            (PVOID)message, (ULONG)len, NULL, NULL);
    }
}

VOID LoggerPrintF(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, args);
    va_end(args);
}