#pragma once

#include "types.h"
#include "physical.h"
#include "pagetable.h"
#include "logger.h"

typedef struct _SHADOW_MAPPING {
    ULONG64 Pml4Physical;
    ULONG64 PdptPhysical;
    ULONG64 PdPhysical;
    ULONG64 PtPhysical;
    ULONG64 PtePhysical;
    ULONG64 ShadowAddress;
    ULONG32 Pml4Index;
    ULONG64 CanonicalPtePhysical;
    ULONG64 CanonicalPteValue;
    BOOLEAN Active;
} SHADOW_MAPPING, *PSHADOW_MAPPING;

BOOLEAN ShadowBuild(ULONG64 privatePa, ULONG64 hookedVa, PSHADOW_MAPPING mapping);
BOOLEAN ShadowSwapToHooked(PSHADOW_MAPPING mapping);
BOOLEAN ShadowSwapToClean(PSHADOW_MAPPING mapping);
BOOLEAN ShadowTeardown(PSHADOW_MAPPING mapping);