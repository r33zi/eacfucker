#pragma once

#include "types.h"
#include "kernel.h"
#include "eat.h"
#include "ssdt.h"
#include "logger.h"
#include "strings.h"

NTSTATUS SyscallHooksCreate(VOID);
VOID SyscallHooksRemove(VOID);