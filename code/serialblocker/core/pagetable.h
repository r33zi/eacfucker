#pragma once

#include "types.h"
#include "physical.h"

extern ULONG64 g_Cr3Value;

BOOLEAN PageTableWalk(ULONG64 va, PPAGE_TABLE_WALK walk);
BOOLEAN PageTableTranslate(ULONG64 va, ULONG64* pa, ULONG32* pageSize);
BOOLEAN PageTableGetPteAddress(ULONG64 va, ULONG64* ptePa);
BOOLEAN PageTableSetProtection(ULONG64 va, BOOLEAN write, BOOLEAN execute, BOOLEAN user);
BOOLEAN PageTableSplitLargePage(ULONG64 va);