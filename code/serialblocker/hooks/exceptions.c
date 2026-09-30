#include "exceptions.h"
#include "memory.h"

static PPPH_HOOK_STATE g_BugCheckHookState = NULL;
static PPPH_HOOK_STATE g_KdpReportHookState = NULL;
static ULONG_PTR g_OriginalKeBugCheckEx = 0;
static ULONG_PTR g_OriginalKdpReport = 0;

static VOID SleepForever(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    LARGE_INTEGER delay;
    delay.QuadPart = 0x80000000;
    KeDelayExecutionThread(KernelMode, FALSE, &delay);
}

static VOID KeBugCheckExHook(
    ULONG bugCheckCode,
    ULONG_PTR parameter1,
    ULONG_PTR parameter2,
    ULONG_PTR parameter3,
    ULONG_PTR parameter4)
{
    if (bugCheckCode == 0x109) {
        LoggerPrintF("[Exception] Intercepted PatchGuard bugcheck 0x109\n");
        SleepForever(NULL);
        return;
    }

    typedef VOID(*KeBugCheckEx_t)(ULONG, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
    if (g_OriginalKeBugCheckEx) {
        ((KeBugCheckEx_t)g_OriginalKeBugCheckEx)(bugCheckCode, parameter1, parameter2, parameter3, parameter4);
    }
}

static BOOLEAN KdpReportHook(
    ULONG64 trapFrame,
    ULONG64 excFrame,
    PEXCEPTION_RECORD exceptionRecord,
    PCONTEXT contextRecord,
    KPROCESSOR_MODE processorMode,
    BOOLEAN firstChance)
{
    if (!exceptionRecord || !contextRecord) goto original;
    if (!MemoryIsAddressValid(exceptionRecord) || !MemoryIsAddressValid(contextRecord)) goto original;

    if (firstChance && exceptionRecord->ExceptionCode == STATUS_PRIVILEGED_INSTRUCTION) {
        UCHAR* rip = (UCHAR*)contextRecord->Rip;
        BOOLEAN isMovCr0 = FALSE;

        if (rip[0] == 0x0F && rip[1] == 0x22 && (rip[2] & 0xF8) == 0xC0) {
            isMovCr0 = TRUE;
        }
        else if (rip[0] == 0x48 && rip[1] == 0x0F && rip[2] == 0x22 && (rip[3] & 0xF8) == 0xC0) {
            isMovCr0 = TRUE;
        }

        if (isMovCr0) {
            LoggerPrintF("[Exception] Intercepted mov cr0 instruction at 0x%llX\n", contextRecord->Rip);
            SleepForever(NULL);
            return TRUE;
        }
    }

    if (firstChance && exceptionRecord->ExceptionCode == STATUS_BREAKPOINT) {
        contextRecord->Rip += 1;
        return TRUE;
    }

original:
    typedef BOOLEAN(*KdpReport_t)(ULONG64, ULONG64, PEXCEPTION_RECORD, PCONTEXT, KPROCESSOR_MODE, BOOLEAN);
    if (g_OriginalKdpReport) {
        return ((KdpReport_t)g_OriginalKdpReport)(trapFrame, excFrame, exceptionRecord,
            contextRecord, processorMode, firstChance);
    }
    return FALSE;
}

NTSTATUS ExceptionHooksCreate(VOID)
{
    NTSTATUS status;

    ULONG64 targetBugCheck = g_KernelSymbols.KeBugCheckEx;
    if (targetBugCheck) {
        g_BugCheckHookState = (PPPH_HOOK_STATE)ExAllocatePoolWithTag(
            NonPagedPool, sizeof(PPH_HOOK_STATE), 'fuEC'
        );
        if (!g_BugCheckHookState) return STATUS_INSUFFICIENT_RESOURCES;

        status = PphHookCreate(targetBugCheck, (PVOID*)&g_OriginalKeBugCheckEx, &g_BugCheckHookState);
        if (NT_SUCCESS(status)) {
            status = PphHookEnable(g_BugCheckHookState, KeBugCheckExHook);
            if (!NT_SUCCESS(status)) {
                PphHookRemove(g_BugCheckHookState);
                ExFreePoolWithTag(g_BugCheckHookState, 'fuEC');
                g_BugCheckHookState = NULL;
            }
        }
    }

    ULONG64 targetKdp = g_KernelSymbols.KdpReport;
    if (targetKdp) {
        g_KdpReportHookState = (PPPH_HOOK_STATE)ExAllocatePoolWithTag(
            NonPagedPool, sizeof(PPH_HOOK_STATE), 'fuEC'
        );
        if (!g_KdpReportHookState) return STATUS_INSUFFICIENT_RESOURCES;

        status = PphHookCreate(targetKdp, (PVOID*)&g_OriginalKdpReport, &g_KdpReportHookState);
        if (NT_SUCCESS(status)) {
            status = PphHookEnable(g_KdpReportHookState, KdpReportHook);
            if (!NT_SUCCESS(status)) {
                PphHookRemove(g_KdpReportHookState);
                ExFreePoolWithTag(g_KdpReportHookState, 'fuEC');
                g_KdpReportHookState = NULL;
            }
        }
    }

    LoggerPrintF("[Exception] Hooks created\n");
    return STATUS_SUCCESS;
}

NTSTATUS ExceptionHooksRemove(VOID)
{
    if (g_BugCheckHookState) {
        PphHookRemove(g_BugCheckHookState);
        ExFreePoolWithTag(g_BugCheckHookState, 'fuEC');
        g_BugCheckHookState = NULL;
    }

    if (g_KdpReportHookState) {
        PphHookRemove(g_KdpReportHookState);
        ExFreePoolWithTag(g_KdpReportHookState, 'fuEC');
        g_KdpReportHookState = NULL;
    }

    LoggerPrintF("[Exception] Hooks removed\n");
    return STATUS_SUCCESS;
}