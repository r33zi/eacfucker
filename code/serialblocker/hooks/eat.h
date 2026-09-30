#pragma once

#include "types.h"
#include "kernel.h"
#include "logger.h"
#include "strings.h"

typedef struct _EAT_HOOK_STATE {
    const char* ExportName;
    ULONG64     ModuleBase;
    ULONG64     OriginalAddress;
    ULONG32*    SlotAddress;
    ULONG32     OriginalRva;
    ULONG32     HookRva;
    BOOLEAN     Active;
} EAT_HOOK_STATE, *PEAT_HOOK_STATE;

NTSTATUS EatHookInstall(ULONG64 moduleBase, const char* name, PVOID hook, PVOID* original);
NTSTATUS EatHookRemove(PEAT_HOOK_STATE state);
NTSTATUS EatHookRestore(PEAT_HOOK_STATE state);