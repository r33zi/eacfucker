#pragma once

#include "types.h"
#include "kernel.h"
#include "logger.h"
#include "strings.h"

NTSTATUS ImageCallbackCreate(VOID);
NTSTATUS ImageCallbackRemove(VOID);
BOOLEAN ImageContains(PVOID address);