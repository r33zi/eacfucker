// made by Enamey - enameydev on github - .gg/enamey

#include "types.h"
#include "logger.h"
#include "kernel.h"
#include "physical.h"
#include "pagetable.h"
#include "eat.h"
#include "pph.h"
#include "etw.h"
#include "exceptions.h"
#include "syscalls.h"
#include "kernel_hooks.h"
#include "process.h"
#include "image.h"
#include "acl.h"
#include <ntddk.h>
#include <ntstatus.h>

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

#ifndef SystemModuleInformation
#define SystemModuleInformation 11
#endif

NTSTATUS DriverThread(PVOID Context);
NTSTATUS InitializeAll(VOID);
VOID CleanupAll(VOID);
VOID DriverUnload(PDRIVER_OBJECT DriverObject);

extern ULONG_PTR g_KernelBase;
extern ULONG g_KernelSize;
extern ULONG_PTR g_DriverBase;
extern ULONG g_DriverSize;
extern ULONG64 g_Cr3Value;

NTSTATUS DriverThread(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    NTSTATUS status;
    BOOLEAN initialized = FALSE;

    DbgPrint("[EACFucker] Driver thread started\n");

    LARGE_INTEGER delay;
    delay.QuadPart = -10000000LL;
    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    status = LoggerInit();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EACFucker] Logger init failed: 0x%X\n", status);
        goto cleanup;
    }

    LoggerPrintF("[EACFucker] Driver loaded\n");
    LoggerPrintF("[EACFucker] Kernel base: 0x%llX\n", g_KernelBase);
    LoggerPrintF("[EACFucker] Driver base: 0x%llX\n", g_DriverBase);

    status = KernelResolveSymbols();
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[EACFucker] Symbol resolution failed: 0x%X\n", status);
        goto cleanup;
    }
    LoggerPrintF("[EACFucker] Symbols resolved\n");

    if (!PhysMemInit()) {
        LoggerPrintF("[EACFucker] Physical memory init failed\n");
        goto cleanup;
        goto cleanup;
    }
    LoggerPrintF("[EACFucker] Physical memory initialized\n");

    g_Cr3Value = __readcr3();
    LoggerPrintF("[EACFucker] CR3: 0x%llX\n", g_Cr3Value);

    status = ExceptionHooksCreate();
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[EACFucker] Exception hooks failed: 0x%X\n", status);
        goto cleanup;
    }
    LoggerPrintF("[EACFucker] Exception hooks created\n");

    status = EtwInitialize();
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[EACFucker] ETW init failed: 0x%X\n", status);
        goto cleanup;
    }
    LoggerPrintF("[EACFucker] ETW initialized\n");

    status = SyscallHooksCreate();
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[EACFucker] Syscall hooks failed: 0x%X\n", status);
        goto cleanup;
    }
    LoggerPrintF("[EACFucker] Syscall hooks created\n");

    status = KernelHooksCreate();
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[EACFucker] Kernel hooks failed: 0x%X\n", status);
        goto cleanup;
    }
    LoggerPrintF("[EACFucker] Kernel hooks created\n");

    status = ProcessSpoofInit();
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[EACFucker] Process spoof init failed: 0x%X\n", status);
        goto cleanup;
    }
    LoggerPrintF("[EACFucker] Process spoofing initialized\n");

    status = ImageCallbackCreate();
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[EACFucker] Image callback failed: 0x%X\n", status);
        goto cleanup;
    }
    LoggerPrintF("[EACFucker] Image callback created\n");

    status = AclBlockerStart();
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[EACFucker] ACL blocker failed: 0x%X\n", status);
        goto cleanup;
    }
    LoggerPrintF("[EACFucker] ACL blocker started\n");

    initialized = TRUE;
    LoggerPrintF("[EACFucker] All systems initialized\n");

    while (TRUE) {
        LARGE_INTEGER sleep;
        sleep.QuadPart = -50000000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &sleep);
    }

cleanup:
    LoggerPrintF("[EACFucker] Driver thread exiting, cleaning up...\n");

    AclBlockerStop();
    ImageCallbackRemove();
    ProcessSpoofCleanup();
    KernelHooksRemove();
    SyscallHooksRemove();
    EtwUnload();
    ExceptionHooksRemove();
    PhysMemCleanup();
    LoggerShutdown();

    PsTerminateSystemThread(STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    LoggerPrintF("[EACFucker] Unloading...\n");
    AclBlockerStop();
    CleanupAll();
    LoggerShutdown();
}

NTSTATUS InitializeAll(VOID)
{
    NTSTATUS status;

    status = LoggerInit();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EACFucker] Logger init failed: 0x%X\n", status);
        return status;
    }

    LoggerPrintF("[EACFucker] Loading driver...\n");

    status = KernelResolveSymbols();
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[EACFucker] Symbol resolution failed: 0x%X\n", status);
        return status;
    }

    if (!PhysMemInit()) {
        LoggerPrintF("[EACFucker] Physical memory init failed\n");
        return STATUS_UNSUCCESSFUL;
    }

    g_Cr3Value = __readcr3();
    LoggerPrintF("[EACFucker] CR3: 0x%llX\n", g_Cr3Value);

    status = ExceptionHooksCreate();
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[EACFucker] Exception hooks failed: 0x%X\n", status);
        return status;
    }

    status = EtwInitialize();
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[EACFucker] ETW init failed: 0x%X\n", status);
        return status;
    }

    status = SyscallHooksCreate();
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[EACFucker] Syscall hooks failed: 0x%X\n", status);
        return status;
    }

    status = KernelHooksCreate();
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[EACFucker] Kernel hooks failed: 0x%X\n", status);
        return status;
    }

    status = ProcessSpoofInit();
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[EACFucker] Process spoof init failed: 0x%X\n", status);
        return status;
    }

    status = ImageCallbackCreate();
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[EACFucker] Image callback failed: 0x%X\n", status);
        return status;
    }

    status = AclBlockerStart();
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[EACFucker] ACL blocker failed: 0x%X\n", status);
        return status;
    }

    LoggerPrintF("[EACFucker] All subsystems initialized\n");
    return STATUS_SUCCESS;
}

VOID CleanupAll(VOID)
{
    ImageCallbackRemove();
    ProcessSpoofCleanup();
    KernelHooksRemove();
    SyscallHooksRemove();
    EtwUnload();
    ExceptionHooksRemove();
    PhysMemCleanup();
    LoggerPrintF("[EACFucker] All subsystems cleaned up\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    ULONG64 ntBase = 0;
    ULONG ntSize = 0;

    PRTL_PROCESS_MODULES moduleInfo = NULL;
    ULONG moduleInfoSize = 0;

    ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &moduleInfoSize);
    if (moduleInfoSize) {
        moduleInfo = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, moduleInfoSize, 'fuEC');
        if (moduleInfo) {
            status = ZwQuerySystemInformation(SystemModuleInformation, moduleInfo, moduleInfoSize, &moduleInfoSize);
            if (NT_SUCCESS(status) && moduleInfo->NumberOfModules > 0) {
                ntBase = (ULONG64)moduleInfo->Modules[0].ImageBase;
                ntSize = moduleInfo->Modules[0].ImageSize;
                DbgPrint("[EACFucker] Kernel base: 0x%llX, size: 0x%X\n", ntBase, ntSize);
            }
            ExFreePoolWithTag(moduleInfo, 'fuEC');
        }
    }

    if (!ntBase) {
        DbgPrint("[EACFucker] Failed to find kernel base\n");
        return STATUS_UNSUCCESSFUL;
    }

    g_KernelBase = ntBase;
    g_KernelSize = ntSize;
    g_DriverBase = (ULONG_PTR)DriverObject->DriverStart;
    g_DriverSize = DriverObject->DriverSize;

    DriverObject->DriverUnload = DriverUnload;

    HANDLE hThread;
    status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL,
        (PKSTART_ROUTINE)DriverThread, NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EACFucker] Failed to create thread: 0x%X\n", status);
        return status;
    }
    ZwClose(hThread);

    return STATUS_SUCCESS;
}