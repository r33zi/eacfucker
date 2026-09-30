#pragma once

#include "types.h"

BOOLEAN PhysMemInit(VOID);
VOID PhysMemCleanup(VOID);
BOOLEAN PhysMemRead(ULONG64 pa, PVOID buffer, SIZE_T size);
BOOLEAN PhysMemWrite(ULONG64 pa, PVOID buffer, SIZE_T size);
BOOLEAN PhysMemIsValid(ULONG64 pa, SIZE_T size);