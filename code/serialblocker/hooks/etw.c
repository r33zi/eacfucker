#include "etw.h"
#include "memory.h"
#include "ssdt.h"

#define ETWP_START_TRACE 1
#define ETWP_STOP_TRACE 2
#define ETWP_UPDATE_TRACE 4

#define WNODE_FLAG_TRACED_GUID 0x00020000
#define EVENT_TRACE_BUFFERING_MODE 0x00000400
#define EVENT_TRACE_FLAG_SYSTEMCALL 0x00000080

#define MAX_ETW_HOOKS 512

typedef struct _ETW_HOOK_ENTRY {
    ULONG SyscallIndex;
    ULONG64 SsdtHandler;
    PVOID HookFunction;
    PVOID* OriginalAddress;
    CHAR FunctionName[64];
    BOOLEAN Active;
} ETW_HOOK_ENTRY, * PETW_HOOK_ENTRY;

static ETW_HOOK_ENTRY g_EtwHooks[MAX_ETW_HOOKS];
static ULONG g_EtwHookCount = 0;
static ULONG64 g_KiSystemCall64Start = 0;
static ULONG64 g_KiSystemCall64End = 0;
static ULONG_PTR g_EtwOriginal = 0;

static PPPH_HOOK_STATE g_EtwHookState = NULL;

static CKCL_TRACE_PROPERTIES g_TraceProperties = { 0 };

static GUID g_CkclSessionGuid =
{ 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };

extern NTSTATUS HookNtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
extern NTSTATUS HookNtQueryVolumeInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
extern NTSTATUS HookNtDeviceIoControlFile(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
extern NTSTATUS HookNtAllocateUuids(PLARGE_INTEGER, PULONG, PULONG, PUCHAR);
extern NTSTATUS HookNtQueryLicenseValue(PUNICODE_STRING, PULONG, PVOID, ULONG, PULONG);
extern NTSTATUS HookNtPowerInformation(ULONG, PVOID, ULONG, PVOID, ULONG);
extern NTSTATUS HookNtQuerySystemEnvironmentValueEx(PUNICODE_STRING, GUID*, PVOID, PULONG, PULONG);
extern NTSTATUS HookNtEnumerateBootEntries(PVOID, PULONG);
extern NTSTATUS HookNtQuerySystemEnvironmentValue(PUNICODE_STRING, PWCH, ULONG, PULONG);

static ULONG64 EtwTraceSiloKernelEventHook(
    ULONG64 siloContext,
    ULONG64 eventData,
    ULONG32 eventCount,
    ULONG32 groupMask,
    USHORT hookId,
    ULONG32 eventFlags)
{
    if (hookId != 0xF33) goto original;

    if (KeGetCurrentIrql() > DISPATCH_LEVEL) goto original;
    if (ExGetPreviousMode() != UserMode) goto original;

    PEPROCESS process = PsGetCurrentProcess();
    if (!process || !MemoryIsAddressValid(process)) goto original;

    char imageName[16];
    if (!MemoryGetImageFileName(process, imageName, sizeof(imageName))) goto original;

    BOOLEAN isTarget = StrStrLowerA(imageName, "fortnite") ||
        StrStrLowerA(imageName, "eac") ||
        StrStrLowerA(imageName, "rust") ||
        StrStrLowerA(imageName, "easyanticheat");

    if (!isTarget) goto original;

    PKTHREAD thread = (PKTHREAD)PsGetCurrentThread();
    if (!thread || !MemoryIsAddressValid(thread)) goto original;

    ULONG syscallNumber = *(ULONG*)((PUCHAR)thread + 0x80);
    if (!syscallNumber) goto original;

    for (ULONG i = 0; i < g_EtwHookCount; i++) {
        if (g_EtwHooks[i].SyscallIndex == syscallNumber && g_EtwHooks[i].Active) {
            ULONG_PTR* stackBottom = (ULONG_PTR*)_AddressOfReturnAddress();
            ULONG_PTR* stackTop = (ULONG_PTR*)__readgsqword(0x1A8);

            for (ULONG_PTR* p = stackBottom; p < stackTop; p++) {
                if (!MemoryIsAddressValid(p)) continue;
                ULONG_PTR val = *p;
                if (val < g_KiSystemCall64Start || val >= g_KiSystemCall64End) continue;

                for (int fwd = 1; fwd < 128; fwd++) {
                    ULONG_PTR* slot = p + fwd;
                    if (!MemoryIsAddressValid(slot)) break;
                    if (*slot == g_EtwHooks[i].SsdtHandler) {
                        if (g_EtwHooks[i].OriginalAddress && !*g_EtwHooks[i].OriginalAddress) {
                            *g_EtwHooks[i].OriginalAddress = (PVOID)*slot;
                        }
                        *slot = (ULONG_PTR)g_EtwHooks[i].HookFunction;
                        goto original;
                    }
                }
                break;
            }
        }
    }

original:
    if (g_EtwOriginal) {
        typedef ULONG64(*EtwTraceFn)(ULONG64, ULONG64, ULONG32, ULONG32, USHORT, ULONG32);
        return ((EtwTraceFn)g_EtwOriginal)(siloContext, eventData, eventCount, groupMask, hookId, eventFlags);
    }
    return 0;
}

NTSTATUS EtwRegisterSyscallHook(const char* functionName, PVOID hookHandler, PVOID* original)
{
    if (g_EtwHookCount >= MAX_ETW_HOOKS) {
        LoggerPrintF("[ETW] Too many hooks registered\n");
        return STATUS_TOO_MANY_NAMES;
    }

    if (!functionName || !hookHandler) {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG syscallIndex = SsdtGetSyscallIndex(functionName);
    if (syscallIndex == (ULONG)-1) {
        LoggerPrintF("[ETW] Failed to resolve syscall: %s\n", functionName);
        return STATUS_NOT_FOUND;
    }

    ULONG64 ssdtHandler = SsdtGetHandler(syscallIndex);
    if (!ssdtHandler) {
        LoggerPrintF("[ETW] Failed to get SSDT handler for %s (0x%X)\n",
            functionName, syscallIndex);
        return STATUS_NOT_FOUND;
    }

    for (ULONG i = 0; i < g_EtwHookCount; i++) {
        if (g_EtwHooks[i].SyscallIndex == syscallIndex) {
            LoggerPrintF("[ETW] Syscall 0x%X already registered\n", syscallIndex);
            return STATUS_ALREADY_COMMITTED;
        }
    }

    ETW_HOOK_ENTRY* entry = &g_EtwHooks[g_EtwHookCount++];
    entry->SyscallIndex = syscallIndex;
    entry->SsdtHandler = ssdtHandler;
    entry->HookFunction = hookHandler;
    entry->OriginalAddress = original;
    strncpy(entry->FunctionName, functionName, sizeof(entry->FunctionName) - 1);
    entry->FunctionName[sizeof(entry->FunctionName) - 1] = '\0';
    entry->Active = TRUE;

    LoggerPrintF("[ETW] Registered %s (index=0x%X, handler=0x%llX)\n",
        functionName, syscallIndex, ssdtHandler);
    return STATUS_SUCCESS;
}

NTSTATUS EtwInitialize(VOID)
{
    NTSTATUS status;

    ULONG64 imageBase = 0;
    PRUNTIME_FUNCTION rf = (PRUNTIME_FUNCTION)RtlLookupFunctionEntry(
        g_KernelSymbols.KiSystemCall64, &imageBase, NULL
    );
    if (!rf) {
        LoggerPrintF("[ETW] Failed to get KiSystemCall64\n");
        return STATUS_UNSUCCESSFUL;
    }

    g_KiSystemCall64Start = imageBase + rf->BeginAddress;
    g_KiSystemCall64End = imageBase + rf->EndAddress;

    LoggerPrintF("[ETW] KiSystemCall64: 0x%llX - 0x%llX\n",
        g_KiSystemCall64Start, g_KiSystemCall64End);

    ULONG64 target = g_KernelSymbols.EtwTraceSiloKernelEvent;
    if (!target) {
        LoggerPrintF("[ETW] EtwTraceSiloKernelEvent not found\n");
        return STATUS_NOT_FOUND;
    }

    g_EtwHookState = (PPPH_HOOK_STATE)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(PPH_HOOK_STATE), 'fuEC'
    );
    if (!g_EtwHookState) return STATUS_INSUFFICIENT_RESOURCES;

    status = PphHookCreate(target, (PVOID*)&g_EtwOriginal, &g_EtwHookState);
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[ETW] Failed to create PPH hook: 0x%X\n", status);
        return status;
    }

    status = PphHookEnable(g_EtwHookState, EtwTraceSiloKernelEventHook);
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[ETW] Failed to enable PPH hook: 0x%X\n", status);
        PphHookRemove(g_EtwHookState);
        g_EtwHookState = NULL;
        return status;
    }

    status = EtwRegisterAllSyscallHooks();
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[ETW] Failed to register syscall hooks: 0x%X\n", status);
        PphHookDisable(g_EtwHookState);
        PphHookRemove(g_EtwHookState);
        g_EtwHookState = NULL;
        return status;
    }

    if (!EtwConfigureTrace(ETWP_START_TRACE)) {
        if (!EtwConfigureTrace(ETWP_UPDATE_TRACE)) {
            LoggerPrintF("[ETW] Failed to configure CKCL trace\n");
            PphHookDisable(g_EtwHookState);
            PphHookRemove(g_EtwHookState);
            g_EtwHookState = NULL;
            return STATUS_UNSUCCESSFUL;
        }
    }

    LoggerPrintF("[ETW] Initialized with %u hooks\n", g_EtwHookCount);
    return STATUS_SUCCESS;
}

NTSTATUS EtwRegisterAllSyscallHooks(VOID)
{
    NTSTATUS status;

    typedef struct {
        const char* name;
        PVOID hook;
        PVOID* original;
    } SYSCALL_HOOK_ENTRY;

    SYSCALL_HOOK_ENTRY hooks[] = {
        {"NtQuerySystemInformation", HookNtQuerySystemInformation, NULL},
        {"NtQueryVolumeInformationFile", HookNtQueryVolumeInformationFile, NULL},
        {"NtDeviceIoControlFile", HookNtDeviceIoControlFile, NULL},
        {"NtAllocateUuids", HookNtAllocateUuids, NULL},
        {"NtQueryLicenseValue", HookNtQueryLicenseValue, NULL},
        {"NtPowerInformation", HookNtPowerInformation, NULL},
        {"NtQuerySystemEnvironmentValueEx", HookNtQuerySystemEnvironmentValueEx, NULL},
        {"NtEnumerateBootEntries", HookNtEnumerateBootEntries, NULL},
        {"NtQuerySystemEnvironmentValue", HookNtQuerySystemEnvironmentValue, NULL},
    };

    for (ULONG i = 0; i < sizeof(hooks) / sizeof(hooks[0]); i++) {
        status = EtwRegisterSyscallHook(hooks[i].name, hooks[i].hook, hooks[i].original);
        if (!NT_SUCCESS(status)) {
            LoggerPrintF("[ETW] Failed to register %s: 0x%X\n", hooks[i].name, status);
        }
    }

    return STATUS_SUCCESS;
}

BOOLEAN EtwConfigureTrace(ULONG operation)
{
    CKCL_TRACE_PROPERTIES props = { 0 };
    props.Properties.Wnode.BufferSize = PAGE_SIZE;
    props.Properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props.Properties.Wnode.Guid = g_CkclSessionGuid;
    props.Properties.Wnode.ClientContext = 1;
    props.Properties.BufferSize = sizeof(ULONG);
    props.Properties.MinimumBuffers = 2;
    props.Properties.MaximumBuffers = 2;
    props.Properties.LogFileMode = EVENT_TRACE_BUFFERING_MODE;

    RtlInitUnicodeString(&props.ProviderName,
        L"Circular Kernel Context Logger");

    if (operation == ETWP_UPDATE_TRACE) {
        props.Properties.EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;
    }

    ULONG retLen = 0;
    typedef NTSTATUS(NTAPI* ZwTraceControl_t)(ULONG, PVOID, ULONG, PVOID, ULONG, PULONG);
    ZwTraceControl_t fn = (ZwTraceControl_t)g_KernelSymbols.ZwTraceControl;
    if (!fn) return FALSE;

    NTSTATUS status = fn(operation, &props, PAGE_SIZE, &props, PAGE_SIZE, &retLen);
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[ETW] ZwTraceControl (op=%lu) failed: 0x%X\n", operation, status);
        return FALSE;
    }

    return TRUE;
}

NTSTATUS EtwUnload(VOID)
{
    EtwConfigureTrace(ETWP_STOP_TRACE);

    if (g_EtwHookState) {
        PphHookRemove(g_EtwHookState);
        g_EtwHookState = NULL;
    }

    for (ULONG i = 0; i < g_EtwHookCount; i++) {
        g_EtwHooks[i].Active = FALSE;
    }
    g_EtwHookCount = 0;

    LoggerPrintF("[ETW] Unloaded\n");
    return STATUS_SUCCESS;
}

BOOLEAN EtwIsTargetProcess(PEPROCESS process)
{
    char imageName[16];
    if (!MemoryGetImageFileName(process, imageName, sizeof(imageName))) return FALSE;
    return StrStrLowerA(imageName, "fortnite") ||
        StrStrLowerA(imageName, "eac") ||
        StrStrLowerA(imageName, "rust") ||
        StrStrLowerA(imageName, "easyanticheat");
}