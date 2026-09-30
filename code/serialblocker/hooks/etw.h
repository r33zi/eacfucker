#pragma once

#include "types.h"
#include "kernel.h"
#include "pph.h"
#include "ssdt.h"
#include "logger.h"

NTSTATUS EtwInitialize(VOID);
NTSTATUS EtwUnload(VOID);
NTSTATUS EtwRegisterSyscallHook(const char* name, PVOID hook, PVOID* original);
NTSTATUS EtwRegisterAllSyscallHooks(VOID);
BOOLEAN EtwConfigureTrace(ULONG operation);
BOOLEAN EtwIsTargetProcess(PEPROCESS process);