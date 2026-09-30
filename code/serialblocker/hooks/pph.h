#pragma once

#include "types.h"
#include "kernel.h"
#include "memory.h"
#include "pagetable.h"
#include "physical.h"
#include "logger.h"
#include "shadow.h"
#include "../hde/hde.h"

typedef struct _PPH_HOOK_STATE {
    UCHAR  OriginalBytes[64];
    SIZE_T HookSize;
    ULONG64 TrampolineAddress;
    ULONG64 HookedPageAddress;
    ULONG64 HookedPagePhysical;
    ULONG64 TargetPhysical;
    ULONG64 OriginalPtePhysical;
    ULONG64 OriginalPteValue;
    SHADOW_MAPPING Shadow;
} PPH_HOOK_STATE;

typedef PPH_HOOK_STATE* PPPH_HOOK_STATE;

NTSTATUS PphHookCreate(ULONG64 targetAddress, PVOID* original, PPPH_HOOK_STATE* outState);
NTSTATUS PphHookEnable(PPPH_HOOK_STATE state, PVOID hookFunction);
NTSTATUS PphHookDisable(PPPH_HOOK_STATE state);
NTSTATUS PphHookRemove(PPPH_HOOK_STATE state);