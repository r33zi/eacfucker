#pragma once

#include "types.h"
#include "kernel.h"
#include "eat.h"
#include "logger.h"

NTSTATUS KernelHooksCreate(VOID);
VOID KernelHooksRemove(VOID);