#pragma once

#include "types.h"
#include "kernel.h"
#include "logger.h"
#include "strings.h"

NTSTATUS ProcessSpoofInit(VOID);
VOID ProcessSpoofCleanup(VOID);