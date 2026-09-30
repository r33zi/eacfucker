#pragma once

#include "types.h"
#include "kernel.h"

typedef struct _SSDT_HOOK_ENTRY {
    ULONG SyscallIndex;
    ULONG64 HandlerAddress;
    PVOID HookFunction;
    PVOID* OriginalAddress;
    CHAR FunctionName[64];
    BOOLEAN Active;
} SSDT_HOOK_ENTRY, *PSSDT_HOOK_ENTRY;

ULONG SsdtGetSyscallIndex(const char* name);
ULONG64 SsdtGetHandler(ULONG index);
BOOLEAN SsdtFindShadowTable(VOID);
NTSTATUS SsdtInstallHook(const char* name, PVOID hook, PVOID* original);
NTSTATUS SsdtRemoveHook(PSSDT_HOOK_ENTRY entry);