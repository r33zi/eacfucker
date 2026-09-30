#pragma once

#include "types.h"
#include "kernel.h"
#include "pph.h"
#include "logger.h"

NTSTATUS ExceptionHooksCreate(VOID);
NTSTATUS ExceptionHooksRemove(VOID);