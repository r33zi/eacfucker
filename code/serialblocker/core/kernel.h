#pragma once

#include "types.h"
#include "strings.h"
#include "logger.h"

extern ULONG_PTR g_KernelBase;
extern ULONG g_KernelSize;
extern ULONG_PTR g_DriverBase;
extern ULONG g_DriverSize;

PVOID KernelGetExport(const char* name);
BOOLEAN KernelGetSection(const char* name, ULONG64* base, ULONG64* size);
NTSTATUS KernelResolveSymbols(VOID);

typedef struct _KERNEL_SYMBOLS {
    ULONG64 MmAllocateIndependentPages;
    ULONG64 MmFreeIndependentPages;
    ULONG64 MmSetPageProtection;
    ULONG64 MiLockPageTablePage;
    ULONG64 MiCopyOnWrite;
    ULONG64 RtlpDebugPrintCallbackList;
    ULONG64 KdpReport;
    ULONG64 EtwTraceSiloKernelEvent;
    ULONG64 KeServiceDescriptorTable;
    ULONG64 KiSystemCall64;
    ULONG64 KeBugCheckEx;
    ULONG64 MmGetPhysicalMemoryRanges;
    ULONG64 ObReferenceObjectByHandle;
    ULONG64 IoFileObjectType;
    ULONG64 ObDereferenceObject;
    ULONG64 ZwQueryInformationFile;
    ULONG64 ZwClose;
    ULONG64 MmGetVirtualForPhysical;
    ULONG64 MmGetPhysicalAddress;
    ULONG64 KeGetCurrentProcessorNumberEx;
    ULONG64 KeQuerySystemTimePrecise;
    ULONG64 KeQueryTickCount;
    ULONG64 RtlRandomEx;
    ULONG64 ObQueryNameString;
    ULONG64 MmIsAddressValid;
    ULONG64 IoGetDeviceInterfaces;
    ULONG64 IoEnumerateDeviceObjectList;
    ULONG64 IoGetDeviceObjectPointer;
    ULONG64 IoQueryFileDosDeviceName;
    ULONG64 PsLookupProcessByProcessId;
    ULONG64 PsGetProcessId;
    ULONG64 PsGetProcessImageFileName;
    ULONG64 PsGetProcessInheritedFromUniqueProcessId;
    ULONG64 PsGetProcessCreateTimeQuadPart;
    ULONG64 PsIsProtectedProcess;
    ULONG64 PsSetLoadImageNotifyRoutineEx;
    ULONG64 PsRemoveLoadImageNotifyRoutine;
    ULONG64 ExAllocatePoolWithTag;
    ULONG64 ExFreePoolWithTag;
    ULONG64 ZwTraceControl;
    ULONG64 RtlInitUnicodeString;
    ULONG64 RtlCompareUnicodeString;
    ULONG64 RtlLookupFunctionEntry;
    ULONG64 RtlVirtualUnwind;
    ULONG64 RtlCaptureContext;
    ULONG64 RtlPcToFileHeader;
    ULONG64 RtlRestoreContext;
    ULONG64 RtlLengthSid;
    ULONG64 RtlConvertSidToUnicodeString;
    ULONG64 RtlFreeUnicodeString;
    ULONG64 ZwContinue;
    ULONG64 PsGetCurrentProcess;
    ULONG64 PsGetCurrentThread;
    ULONG64 IoGetInitialStack;
    ULONG64 PsTerminateSystemThread;
    ULONG64 KeSetSystemAffinityThread;
    ULONG64 KeFlushSingleTb;
    ULONG64 KeFlushEntireTb;
    ULONG64 KeInvalidateAllCaches;
    ULONG64 HalPrivateDispatchTable;
    ULONG64 KeQueryActiveProcessorCountEx;
} KERNEL_SYMBOLS, *PKERNEL_SYMBOLS;

extern KERNEL_SYMBOLS g_KernelSymbols;