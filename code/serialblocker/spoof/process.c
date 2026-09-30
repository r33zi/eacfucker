#include "process.h"
#include "memory.h"
#include "eat.h"
#include <ntddk.h>

#pragma comment(lib, "hal.lib")

extern VOID KeQuerySystemTime(PLARGE_INTEGER SystemTime);


typedef struct _FAKE_PROCESS_ENTRY {
    PEPROCESS Process;
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    ULONG64 CreateTime;
    CHAR ImageFileName[16];
} FAKE_PROCESS_ENTRY, *PFAKE_PROCESS_ENTRY;

static FAKE_PROCESS_ENTRY g_FakeProcesses[128];
static volatile LONG g_FakeProcessCount = 0;
static EAT_HOOK_STATE g_ProcessHookStates[8];
static ULONG g_ProcessHookCount = 0;

static CHAR g_FakeImageName[16] = "svchost.exe";

static PFAKE_PROCESS_ENTRY FindFakeProcess(PEPROCESS process)
{
    if (!process) return NULL;

    LONG count = g_FakeProcessCount;
    if (count < 0) count = 0;
    if (count > 128) count = 128;

    for (LONG i = 0; i < count; i++) {
        if (g_FakeProcesses[i].Process == process) {
            return &g_FakeProcesses[i];
        }
    }
    return NULL;
}

static PFAKE_PROCESS_ENTRY AddFakeProcess(PEPROCESS process, HANDLE pid)
{
    if (!process) return NULL;

    PFAKE_PROCESS_ENTRY existing = FindFakeProcess(process);
    if (existing) return existing;

    LONG idx = InterlockedIncrement(&g_FakeProcessCount) - 1;
    if (idx < 0 || idx >= 128) {
        g_FakeProcessCount = 128;
        return NULL;
    }

    g_FakeProcesses[idx].Process = process;
    g_FakeProcesses[idx].ProcessId = pid;
    g_FakeProcesses[idx].ParentProcessId = (HANDLE)4;

    LARGE_INTEGER currentTime;
    KeQueryPerformanceCounter(&currentTime);
    g_FakeProcesses[idx].CreateTime = currentTime.QuadPart;

    CopyMem(g_FakeProcesses[idx].ImageFileName, g_FakeImageName, sizeof(g_FakeImageName));
    g_FakeProcesses[idx].ImageFileName[15] = '\0';

    return &g_FakeProcesses[idx];
}

static NTSTATUS HookPsLookupProcessByProcessId(
    HANDLE processId,
    PEPROCESS* process)
{
    typedef NTSTATUS (*PsLookupProcessByProcessId_t)(HANDLE, PEPROCESS*);
    PsLookupProcessByProcessId_t orig = (PsLookupProcessByProcessId_t)
        g_ProcessHookStates[0].OriginalAddress;

    NTSTATUS status = orig(processId, process);
    if (NT_SUCCESS(status) && process && *process) {
        AddFakeProcess(*process, processId);
    }
    return status;
}

static HANDLE HookPsGetProcessId(PEPROCESS process)
{
    PFAKE_PROCESS_ENTRY entry = FindFakeProcess(process);
    if (entry) {
        return entry->ProcessId;
    }

    typedef HANDLE (*PsGetProcessId_t)(PEPROCESS);
    PsGetProcessId_t orig = (PsGetProcessId_t)
        g_ProcessHookStates[1].OriginalAddress;
    return orig(process);
}

static HANDLE HookPsGetProcessInheritedFromUniqueProcessId(PEPROCESS process)
{
    PFAKE_PROCESS_ENTRY entry = FindFakeProcess(process);
    if (entry) {
        return entry->ParentProcessId;
    }

    typedef HANDLE (*PsGetProcessInheritedFromUniqueProcessId_t)(PEPROCESS);
    PsGetProcessInheritedFromUniqueProcessId_t orig = 
        (PsGetProcessInheritedFromUniqueProcessId_t)
        g_ProcessHookStates[2].OriginalAddress;
    return orig(process);
}

static ULONG64 HookPsGetProcessCreateTimeQuadPart(PEPROCESS process)
{
    PFAKE_PROCESS_ENTRY entry = FindFakeProcess(process);
    if (entry) {
        return entry->CreateTime;
    }

    typedef ULONG64 (*PsGetProcessCreateTimeQuadPart_t)(PEPROCESS);
    PsGetProcessCreateTimeQuadPart_t orig = 
        (PsGetProcessCreateTimeQuadPart_t)
        g_ProcessHookStates[3].OriginalAddress;
    return orig(process);
}

static BOOLEAN HookPsIsProtectedProcess(PEPROCESS process)
{
    PFAKE_PROCESS_ENTRY entry = FindFakeProcess(process);
    if (entry) {
        return FALSE;
    }

    typedef BOOLEAN (*PsIsProtectedProcess_t)(PEPROCESS);
    PsIsProtectedProcess_t orig = 
        (PsIsProtectedProcess_t)
        g_ProcessHookStates[4].OriginalAddress;
    return orig(process);
}

NTSTATUS ProcessSpoofInit(VOID)
{
    NTSTATUS status;

    status = EatHookInstall(g_KernelBase, "PsLookupProcessByProcessId",
                            HookPsLookupProcessByProcessId,
                            (PVOID*)&g_ProcessHookStates[g_ProcessHookCount].OriginalAddress);
    if (NT_SUCCESS(status)) {
        g_ProcessHookStates[g_ProcessHookCount].ExportName = "PsLookupProcessByProcessId";
        g_ProcessHookStates[g_ProcessHookCount].Active = TRUE;
        g_ProcessHookCount++;
    }

    status = EatHookInstall(g_KernelBase, "PsGetProcessId",
                            HookPsGetProcessId,
                            (PVOID*)&g_ProcessHookStates[g_ProcessHookCount].OriginalAddress);
    if (NT_SUCCESS(status)) {
        g_ProcessHookStates[g_ProcessHookCount].ExportName = "PsGetProcessId";
        g_ProcessHookStates[g_ProcessHookCount].Active = TRUE;
        g_ProcessHookCount++;
    }

    status = EatHookInstall(g_KernelBase, "PsGetProcessInheritedFromUniqueProcessId",
                            HookPsGetProcessInheritedFromUniqueProcessId,
                            (PVOID*)&g_ProcessHookStates[g_ProcessHookCount].OriginalAddress);
    if (NT_SUCCESS(status)) {
        g_ProcessHookStates[g_ProcessHookCount].ExportName = "PsGetProcessInheritedFromUniqueProcessId";
        g_ProcessHookStates[g_ProcessHookCount].Active = TRUE;
        g_ProcessHookCount++;
    }

    status = EatHookInstall(g_KernelBase, "PsGetProcessCreateTimeQuadPart",
                            HookPsGetProcessCreateTimeQuadPart,
                            (PVOID*)&g_ProcessHookStates[g_ProcessHookCount].OriginalAddress);
    if (NT_SUCCESS(status)) {
        g_ProcessHookStates[g_ProcessHookCount].ExportName = "PsGetProcessCreateTimeQuadPart";
        g_ProcessHookStates[g_ProcessHookCount].Active = TRUE;
        g_ProcessHookCount++;
    }

    status = EatHookInstall(g_KernelBase, "PsIsProtectedProcess",
                            HookPsIsProtectedProcess,
                            (PVOID*)&g_ProcessHookStates[g_ProcessHookCount].OriginalAddress);
    if (NT_SUCCESS(status)) {
        g_ProcessHookStates[g_ProcessHookCount].ExportName = "PsIsProtectedProcess";
        g_ProcessHookStates[g_ProcessHookCount].Active = TRUE;
        g_ProcessHookCount++;
    }

    LoggerPrintF("[ProcessSpoof] Initialized with %u hooks\n", g_ProcessHookCount);
    return STATUS_SUCCESS;
}

VOID ProcessSpoofCleanup(VOID)
{
    for (ULONG i = 0; i < g_ProcessHookCount; i++) {
        if (g_ProcessHookStates[i].Active) {
            EatHookRemove(&g_ProcessHookStates[i]);
        }
    }
    g_ProcessHookCount = 0;
    LoggerPrintF("[ProcessSpoof] Cleaned up\n");
}