#include "kernel_hooks.h"
#include "memory.h"
#include "strings.h"

static EAT_HOOK_STATE g_KernelHookStates[32];
static ULONG g_KernelHookCount = 0;

static NTSTATUS NtQuerySystemInformationHook(
    ULONG infoClass,
    PVOID info,
    ULONG infoLen,
    PULONG retLen)
{
    typedef NTSTATUS(*NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
    NtQuerySystemInformation_t orig = (NtQuerySystemInformation_t)
        g_KernelHookStates[0].OriginalAddress;

    NTSTATUS status = orig(infoClass, info, infoLen, retLen);

    if (!NT_SUCCESS(status) || !info) return status;

    if (infoClass == 0x4B || infoClass == 0x60 || infoClass == 0x62 ||
        infoClass == 0x77 || infoClass == 0x7C || infoClass == 0x91 ||
        infoClass == 0xA0) {
        RtlZeroMemory(info, *retLen);
        LoggerPrintF("[KernelHook] Zeroed sensitive class 0x%X (kernel caller)\n", infoClass);
    }

    return status;
}

NTSTATUS KernelHooksCreate(VOID)
{
    NTSTATUS status;

    status = EatHookInstall(g_KernelBase, "NtQuerySystemInformation",
        NtQuerySystemInformationHook,
        (PVOID*)&g_KernelHookStates[g_KernelHookCount].OriginalAddress);
    if (NT_SUCCESS(status)) {
        g_KernelHookStates[g_KernelHookCount].ExportName = "NtQuerySystemInformation";
        g_KernelHookStates[g_KernelHookCount].Active = TRUE;
        g_KernelHookCount++;
    }

    LoggerPrintF("[KernelHook] Created %u hooks\n", g_KernelHookCount);
    return STATUS_SUCCESS;
}

VOID KernelHooksRemove(VOID)
{
    for (ULONG i = 0; i < g_KernelHookCount; i++) {
        if (g_KernelHookStates[i].Active) {
            EatHookRemove(&g_KernelHookStates[i]);
        }
    }
    g_KernelHookCount = 0;
    LoggerPrintF("[KernelHook] Removed all hooks\n");
}