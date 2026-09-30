#include "kernel.h"

ULONG_PTR g_KernelBase = 0;
ULONG g_KernelSize = 0;
ULONG_PTR g_DriverBase = 0;
ULONG g_DriverSize = 0;
KERNEL_SYMBOLS g_KernelSymbols = {0};

PVOID KernelGetExport(const char* name)
{
    if (!g_KernelBase) return NULL;

    PDOS_HEADER dos = (PDOS_HEADER)g_KernelBase;
    if (dos->e_magic != 0x5A4D) return NULL;

    PNT_HEADERS nt = (PNT_HEADERS)(g_KernelBase + dos->e_lfanew);
    if (nt->Signature != 0x4550) return NULL;

    PEXPORT_DIRECTORY exp = (PEXPORT_DIRECTORY)PTR_FROM_RVA(g_KernelBase, nt->ExportTable.VirtualAddress);
    if (!exp || !exp->NumberOfNames) return NULL;

    DWORD* names = (DWORD*)PTR_FROM_RVA(g_KernelBase, exp->AddressOfNames);
    DWORD* funcs = (DWORD*)PTR_FROM_RVA(g_KernelBase, exp->AddressOfFunctions);
    WORD* ords = (WORD*)PTR_FROM_RVA(g_KernelBase, exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* cur = (char*)PTR_FROM_RVA(g_KernelBase, names[i]);
        if (!cur) continue;
        if (StrCmpA(cur, name) == 0) {
            DWORD rva = funcs[ords[i]];
            return (PVOID)(g_KernelBase + rva);
        }
    }
    return NULL;
}

BOOLEAN KernelGetSection(const char* name, ULONG64* base, ULONG64* size)
{
    if (!g_KernelBase) return FALSE;

    PDOS_HEADER dos = (PDOS_HEADER)g_KernelBase;
    if (dos->e_magic != 0x5A4D) return FALSE;

    PNT_HEADERS nt = (PNT_HEADERS)(g_KernelBase + dos->e_lfanew);
    if (nt->Signature != 0x4550) return FALSE;

    PSECTION_HEADER sec = (PSECTION_HEADER)((ULONG_PTR)nt + 
                          nt->SizeOfOptionalHeader + 0x18);

    for (WORD i = 0; i < nt->NumberOfSections; i++) {
        if (StrCmpA(sec[i].Name, name) == 0) {
            if (base) *base = g_KernelBase + sec[i].VirtualAddress;
            if (size) *size = sec[i].VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

NTSTATUS KernelResolveSymbols(VOID)
{
    #define RESOLVE(name) \
        g_KernelSymbols.name = (ULONG64)KernelGetExport(#name); \
        if (!g_KernelSymbols.name) { \
            LoggerPrintF("[Kernel] Failed to resolve: %s\n", #name); \
            return STATUS_UNSUCCESSFUL; \
        }

    RESOLVE(ExAllocatePoolWithTag);
    RESOLVE(ExFreePoolWithTag);
    RESOLVE(MmIsAddressValid);
    RESOLVE(ObDereferenceObject);
    RESOLVE(RtlInitUnicodeString);
    RESOLVE(PsGetCurrentProcess);
    RESOLVE(PsGetCurrentThread);
    RESOLVE(KeQueryTickCount);
    RESOLVE(RtlRandomEx);
    RESOLVE(KeQuerySystemTimePrecise);
    RESOLVE(KeGetCurrentProcessorNumberEx);
    RESOLVE(MmGetPhysicalAddress);
    RESOLVE(MmGetVirtualForPhysical);
    RESOLVE(ZwClose);
    RESOLVE(ZwQueryInformationFile);
    RESOLVE(ObReferenceObjectByHandle);
    RESOLVE(IoFileObjectType);
    RESOLVE(MmGetPhysicalMemoryRanges);
    RESOLVE(PsSetLoadImageNotifyRoutineEx);
    RESOLVE(PsRemoveLoadImageNotifyRoutine);
    RESOLVE(KeBugCheckEx);
    RESOLVE(RtlLookupFunctionEntry);
    RESOLVE(RtlVirtualUnwind);
    RESOLVE(RtlCaptureContext);
    RESOLVE(RtlPcToFileHeader);
    RESOLVE(RtlRestoreContext);
    RESOLVE(ZwContinue);
    RESOLVE(IoGetInitialStack);
    RESOLVE(PsTerminateSystemThread);
    RESOLVE(KeFlushSingleTb);
    RESOLVE(KeFlushEntireTb);
    RESOLVE(KeInvalidateAllCaches);
    RESOLVE(KeQueryActiveProcessorCountEx);
    RESOLVE(KeSetSystemAffinityThread);
    RESOLVE(RtlLengthSid);
    RESOLVE(RtlConvertSidToUnicodeString);
    RESOLVE(RtlFreeUnicodeString);
    RESOLVE(ZwTraceControl);
    RESOLVE(ObQueryNameString);
    RESOLVE(IoGetDeviceInterfaces);
    RESOLVE(IoEnumerateDeviceObjectList);
    RESOLVE(IoGetDeviceObjectPointer);
    RESOLVE(IoQueryFileDosDeviceName);
    RESOLVE(PsLookupProcessByProcessId);
    RESOLVE(PsGetProcessId);
    RESOLVE(PsGetProcessImageFileName);
    RESOLVE(PsGetProcessInheritedFromUniqueProcessId);
    RESOLVE(PsGetProcessCreateTimeQuadPart);
    RESOLVE(PsIsProtectedProcess);

    g_KernelSymbols.MmAllocateIndependentPages = 
        (ULONG64)KernelGetExport("MmAllocateIndependentPages");
    g_KernelSymbols.MmFreeIndependentPages = 
        (ULONG64)KernelGetExport("MmFreeIndependentPages");
    g_KernelSymbols.MmSetPageProtection = 
        (ULONG64)KernelGetExport("MmSetPageProtection");
    g_KernelSymbols.MiLockPageTablePage = 
        (ULONG64)KernelGetExport("MiLockPageTablePage");
    g_KernelSymbols.MiCopyOnWrite = 
        (ULONG64)KernelGetExport("MiCopyOnWrite");
    g_KernelSymbols.RtlpDebugPrintCallbackList = 
        (ULONG64)KernelGetExport("RtlpDebugPrintCallbackList");
    g_KernelSymbols.KdpReport = 
        (ULONG64)KernelGetExport("KdpReport");
    g_KernelSymbols.EtwTraceSiloKernelEvent = 
        (ULONG64)KernelGetExport("EtwTraceSiloKernelEvent");
    g_KernelSymbols.KeServiceDescriptorTable = 
        (ULONG64)KernelGetExport("KeServiceDescriptorTable");
    g_KernelSymbols.KiSystemCall64 = 
        (ULONG64)KernelGetExport("KiSystemCall64");
    g_KernelSymbols.HalPrivateDispatchTable = 
        (ULONG64)KernelGetExport("HalPrivateDispatchTable");

    LoggerPrintF("[Kernel] All symbols resolved\n");
    return STATUS_SUCCESS;
}