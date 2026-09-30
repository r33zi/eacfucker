#pragma once

#include "types.h"

ULONG64 MemoryFindCave(ULONG64 moduleBase, SIZE_T size);
ULONG64 MemoryFindCaveInDriver(SIZE_T size);
BOOLEAN MemoryIsAddressValid(PVOID addr);
BOOLEAN MemoryGetImageFileName(PEPROCESS process, char* buffer, SIZE_T size);
BOOLEAN MemoryIsCoveredByRuntimeFunction(ULONG64 moduleBase, ULONG64 address, SIZE_T size);