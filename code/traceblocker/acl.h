#pragma once

#include "types.h"
#include "logger.h"
#include "strings.h"

NTSTATUS AclBlockerRun(VOID);
NTSTATUS AclBlockerStart(VOID);
VOID AclBlockerStop(VOID);