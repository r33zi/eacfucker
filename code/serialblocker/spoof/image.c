#include "image.h"
#include "memory.h"

static ULONG_PTR g_EacImageBase = 0;
static ULONG g_EacImageSize = 0;

static VOID ImageLoadCallback(
    PUNICODE_STRING imageName,
    HANDLE processId,
    PIMAGE_INFO imageInfo)
{
    if (!imageName || !imageName->Buffer || !imageInfo) return;

    // Find EAC driver
    WCHAR* fileName = wcsrchr(imageName->Buffer, L'\\');
    if (fileName) fileName++;
    else fileName = imageName->Buffer;

    if (StrCmpNoCaseW(fileName, L"EMAC-Driver-x64.sys") == 0 ||
        StrCmpNoCaseW(fileName, L"EasyAntiCheat.sys") == 0) {
        g_EacImageBase = (ULONG_PTR)imageInfo->ImageBase;
        g_EacImageSize = imageInfo->ImageSize;

        LoggerPrintF("[Image] Detected EAC driver at 0x%p (size: 0x%X)\n",
                    imageInfo->ImageBase, imageInfo->ImageSize);

        PLIST_ENTRY callbackList = (PLIST_ENTRY)g_KernelSymbols.RtlpDebugPrintCallbackList;
        if (callbackList) {
            PLIST_ENTRY entry = callbackList->Flink;
            while (entry != callbackList) {
                PLIST_ENTRY next = entry->Flink;
                // Check if callback is in our image or EAC image
                PVOID callback = *(PVOID*)((PUCHAR)entry + 0x10);
                if (ImageContains(callback) || 
                    ((ULONG_PTR)callback >= g_EacImageBase && 
                     (ULONG_PTR)callback < g_EacImageBase + g_EacImageSize)) {
                    // Remove entry
                    entry->Blink->Flink = entry->Flink;
                    entry->Flink->Blink = entry->Blink;
                    LoggerPrintF("[Image] Removed debug callback\n");
                }
                entry = next;
            }
        }
    }
}

BOOLEAN ImageContains(PVOID address)
{
    if (!g_DriverBase || !g_DriverSize) return FALSE;
    ULONG_PTR addr = (ULONG_PTR)address;
    return addr >= g_DriverBase && addr < g_DriverBase + g_DriverSize;
}

NTSTATUS ImageCallbackCreate(VOID)
{
    typedef NTSTATUS (*PsSetLoadImageNotifyRoutineEx_t)(PVOID, ULONG64);
    PsSetLoadImageNotifyRoutineEx_t fn = 
        (PsSetLoadImageNotifyRoutineEx_t)g_KernelSymbols.PsSetLoadImageNotifyRoutineEx;
    if (!fn) return STATUS_UNSUCCESSFUL;

    NTSTATUS status = fn(ImageLoadCallback, 0);
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[Image] Failed to register callback: 0x%X\n", status);
        return status;
    }

    LoggerPrintF("[Image] Callback registered\n");
    return STATUS_SUCCESS;
}

NTSTATUS ImageCallbackRemove(VOID)
{
    typedef NTSTATUS (*PsRemoveLoadImageNotifyRoutine_t)(PVOID);
    PsRemoveLoadImageNotifyRoutine_t fn = 
        (PsRemoveLoadImageNotifyRoutine_t)g_KernelSymbols.PsRemoveLoadImageNotifyRoutine;
    if (!fn) return STATUS_UNSUCCESSFUL;

    NTSTATUS status = fn(ImageLoadCallback);
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[Image] Failed to remove callback: 0x%X\n", status);
        return status;
    }

    LoggerPrintF("[Image] Callback removed\n");
    return STATUS_SUCCESS;
}