#include "syscalls.h"
#include "memory.h"
#include <ntddk.h>

#pragma comment(lib, "hal.lib")

extern ULONG KeQueryTickCount(VOID);

static EAT_HOOK_STATE g_SyscallHookStates[32];
static ULONG g_SyscallHookCount = 0;

static ULONG g_FakeVolumeSerial = 0;
static ULONG g_FakeDisplaySerials[4] = { 0 };
static ULONG g_FakeUuidSequence = 0;
static UCHAR g_FakeUuidSeed[6] = { 0 };
static ULONG64 g_LastSidTime = 0;

NTSTATUS HookNtQuerySystemInformation(
    ULONG infoClass,
    PVOID info,
    ULONG infoLen,
    PULONG retLen)
{
    typedef NTSTATUS(*NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
    NtQuerySystemInformation_t orig = (NtQuerySystemInformation_t)
        g_SyscallHookStates[0].OriginalAddress;

    NTSTATUS status = orig(infoClass, info, infoLen, retLen);

    if (!NT_SUCCESS(status) || !info || !retLen) return status;

    // Spoof SystemBasicInformation (class 0)
    if (infoClass == 0 && *retLen >= 5 * sizeof(ULONG)) {
        ULONG* basic = (ULONG*)info;
        basic[1] = 1;                    // Number of processors
        basic[2] = 0x1000;               // Page size
        basic[3] = 0x40000000;           // Low memory
        basic[4] = 0x80000000;           // High memory
        LoggerPrintF("[Syscall] Spoofed SystemBasicInformation\n");
    }

    // Spoof SystemProcessorInformation (class 1)
    if (infoClass == 1 && *retLen >= 4 * sizeof(USHORT) + sizeof(ULONG)) {
        USHORT* proc = (USHORT*)info;
        proc[0] = 0;
        proc[1] = 6;
        proc[2] = 0x3C;
        proc[3] = 0;
        ULONG* feat = (ULONG*)(proc + 4);
        *feat = 0;
        LoggerPrintF("[Syscall] Spoofed SystemProcessorInformation\n");
    }

    // Spoof SystemKernelDebuggerInformation (class 0x23)
    if (infoClass == 0x23 && *retLen >= sizeof(BOOLEAN)) {
        *(BOOLEAN*)info = FALSE;
        LoggerPrintF("[Syscall] Spoofed SystemKernelDebuggerInformation\n");
    }

    // Spoof SystemBootEnvironmentInformation (class 0x60)
    if (infoClass == 0x60 && *retLen >= sizeof(BOOLEAN)) {
        *(BOOLEAN*)info = FALSE;
        LoggerPrintF("[Syscall] Spoofed SystemBootEnvironmentInformation\n");
    }

    // Spoof SystemSecureBootInformation (class 0x91)
    if (infoClass == 0x91 && *retLen >= sizeof(BOOLEAN)) {
        *(BOOLEAN*)info = FALSE;
        LoggerPrintF("[Syscall] Spoofed SystemSecureBootInformation\n");
    }

    // Zero out sensitive classes
    if (infoClass == 0x4B || infoClass == 0x62 || infoClass == 0x77 ||
        infoClass == 0x7C || infoClass == 0xA0) {
        RtlZeroMemory(info, *retLen);
        LoggerPrintF("[Syscall] Zeroed sensitive class 0x%X\n", infoClass);
    }

    return status;
}

NTSTATUS HookNtQueryVolumeInformationFile(
    HANDLE handle,
    PIO_STATUS_BLOCK iosb,
    PVOID info,
    ULONG len,
    ULONG infoClass)
{
    typedef NTSTATUS(*NtQueryVolumeInformationFile_t)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
    NtQueryVolumeInformationFile_t orig = (NtQueryVolumeInformationFile_t)
        g_SyscallHookStates[1].OriginalAddress;

    NTSTATUS status = orig(handle, iosb, info, len, infoClass);

    if (!NT_SUCCESS(status) || !info || infoClass != 1) return status;

    if (!g_FakeVolumeSerial) {
        LARGE_INTEGER tick;
        KeQueryPerformanceCounter(&tick);
        g_FakeVolumeSerial = (ULONG)(tick.LowPart ^ tick.HighPart ^ 0xA5C35A3C);
        LoggerPrintF("[Syscall] Generated fake volume serial: 0x%X\n", g_FakeVolumeSerial);
    }

    __try {
        ULONG* serial = (ULONG*)((PUCHAR)info + sizeof(LARGE_INTEGER));
        *serial = g_FakeVolumeSerial;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }

    return status;
}

NTSTATUS HookNtDeviceIoControlFile(
    HANDLE handle,
    HANDLE event,
    PVOID apcRoutine,
    PVOID apcContext,
    PIO_STATUS_BLOCK iosb,
    ULONG ioctl,
    PVOID input,
    ULONG inputLen,
    PVOID output,
    ULONG outputLen)
{
    typedef NTSTATUS(*NtDeviceIoControlFile_t)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
    NtDeviceIoControlFile_t orig = (NtDeviceIoControlFile_t)
        g_SyscallHookStates[2].OriginalAddress;

    if (ioctl == 0x00070020 || ioctl == 0x0007002C || ioctl == 0x000700A0) {
        LoggerPrintF("[Syscall] Blocked disk IOCTL 0x%X\n", ioctl);
        if (iosb) {
            iosb->Status = STATUS_ACCESS_DENIED;
            iosb->Information = 0;
        }
        return STATUS_ACCESS_DENIED;
    }

    // Log EAC IOCTLs
    if (ioctl == 0x00226003 || ioctl == 0x00226013 ||
        ioctl == 0x0022E007 || ioctl == 0x0022E01F ||
        ioctl == 0x0022E04B || ioctl == 0x0022E04F ||
        ioctl == 0x0022E067 || ioctl == 0x0022E023 ||
        ioctl == 0x0022E053 || ioctl == 0x0022E05B ||
        ioctl == 0x0022E017 || ioctl == 0x0022605F ||
        ioctl == 0x0022E06B) {
        LoggerPrintF("[Syscall] EAC IOCTL 0x%X (input=%lu, output=%lu)\n",
            ioctl, inputLen, outputLen);
    }

    if (ioctl == 0x00470803) {
        if (output && outputLen >= 0x14) {
            const WCHAR fakeDeviceList[] =
                L"ROOT\\DISPLAY\\0000\0"
                L"DISPLAY\\EACFUCKER0000\\0000\0"
                L"\0";
            ULONG payloadLen = (ULONG)sizeof(fakeDeviceList);
            ULONG totalLen = payloadLen + 0x14;

            if (outputLen < totalLen) {
                if (iosb) {
                    iosb->Status = STATUS_BUFFER_TOO_SMALL;
                    iosb->Information = totalLen;
                }
                return STATUS_BUFFER_TOO_SMALL;
            }

            RtlZeroMemory(output, outputLen);
            PUCHAR out = (PUCHAR)output;
            *(ULONG*)(out + 0x00) = 0x14;
            *(ULONG*)(out + 0x08) = payloadLen;
            *(ULONG*)(out + 0x0C) = 0;
            RtlCopyMemory(out + 0x10, (PVOID)fakeDeviceList, payloadLen);

            if (iosb) {
                iosb->Status = STATUS_SUCCESS;
                iosb->Information = totalLen;
            }
            LoggerPrintF("[Syscall] Spoofed DeviceApi query\n");
            return STATUS_SUCCESS;
        }
    }

    if (ioctl == 0x0047081B) {
        if (output && outputLen >= 0x14) {
            const WCHAR fakeProperty[] = L"Generic Display Adapter";
            ULONG payloadLen = (ULONG)((wcslen(fakeProperty) + 1) * sizeof(WCHAR));
            ULONG totalLen = payloadLen + 0x14;

            if (outputLen < totalLen) {
                if (iosb) {
                    iosb->Status = STATUS_BUFFER_TOO_SMALL;
                    iosb->Information = totalLen;
                }
                return STATUS_BUFFER_TOO_SMALL;
            }

            RtlZeroMemory(output, outputLen);
            PUCHAR out = (PUCHAR)output;
            *(ULONG*)(out + 0x00) = 0x14;
            *(ULONG*)(out + 0x08) = payloadLen;
            *(ULONG*)(out + 0x0C) = 0x12;
            RtlCopyMemory(out + 0x10, (PVOID)fakeProperty, payloadLen);

            if (iosb) {
                iosb->Status = STATUS_SUCCESS;
                iosb->Information = totalLen;
            }
            LoggerPrintF("[Syscall] Spoofed DeviceApi property\n");
            return STATUS_SUCCESS;
        }
    }

    return orig(handle, event, apcRoutine, apcContext, iosb,
        ioctl, input, inputLen, output, outputLen);
}

NTSTATUS HookNtAllocateUuids(
    PLARGE_INTEGER time,
    PULONG range,
    PULONG sequence,
    PUCHAR seed)
{
    typedef NTSTATUS(*NtAllocateUuids_t)(PLARGE_INTEGER, PULONG, PULONG, PUCHAR);
    NtAllocateUuids_t orig = (NtAllocateUuids_t)
        g_SyscallHookStates[3].OriginalAddress;

    NTSTATUS status = orig(time, range, sequence, seed);

    if (!NT_SUCCESS(status)) return status;

    __try {
        if (!g_FakeUuidSequence) {
            LARGE_INTEGER tick;
            KeQueryPerformanceCounter(&tick);
            ULONG randomSeed = tick.LowPart ^ tick.HighPart ^ 0x55754944;
            ULONG randomA = RtlRandomEx(&randomSeed);
            ULONG randomB = RtlRandomEx(&randomSeed);

            g_FakeUuidSequence = (randomA & 0x3FFF) | 0x8000;
            g_FakeUuidSeed[0] = 0x02;
            g_FakeUuidSeed[1] = (UCHAR)(randomA >> 8);
            g_FakeUuidSeed[2] = (UCHAR)(randomA >> 16);
            g_FakeUuidSeed[3] = (UCHAR)(randomA >> 24);
            g_FakeUuidSeed[4] = (UCHAR)(randomB);
            g_FakeUuidSeed[5] = (UCHAR)(randomB >> 8);
            LoggerPrintF("[Syscall] Generated fake UUID seed\n");
        }

        if (time) time->QuadPart = 0x01DB1C8F00000000ULL;
        if (range) *range = 0x100000;
        if (sequence) *sequence = g_FakeUuidSequence;
        if (seed) RtlCopyMemory(seed, g_FakeUuidSeed, sizeof(g_FakeUuidSeed));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }

    return status;
}

NTSTATUS HookNtQueryLicenseValue(
    PUNICODE_STRING valueName,
    PULONG type,
    PVOID data,
    ULONG dataSize,
    PULONG resultDataSize)
{
    UNICODE_STRING allowKey;
    RtlInitUnicodeString(&allowKey,
        L"TerminalServices-RemoteConnectionManager-AllowAppServerMode");

    if (valueName && valueName->Buffer &&
        RtlCompareUnicodeString(valueName, &allowKey, TRUE) == 0) {
        typedef NTSTATUS(*NtQueryLicenseValue_t)(PUNICODE_STRING, PULONG, PVOID, ULONG, PULONG);
        NtQueryLicenseValue_t orig = (NtQueryLicenseValue_t)
            g_SyscallHookStates[4].OriginalAddress;
        return orig(valueName, type, data, dataSize, resultDataSize);
    }

    if (data && dataSize) RtlZeroMemory(data, dataSize);
    if (resultDataSize) *resultDataSize = 0;
    if (valueName && valueName->Buffer) {
        LoggerPrintF("[Syscall] Blocked license query: %wZ\n", valueName);
    }
    return STATUS_ACCESS_VIOLATION;
}

NTSTATUS HookNtPowerInformation(
    ULONG infoLevel,
    PVOID input,
    ULONG inputLen,
    PVOID output,
    ULONG outputLen)
{
    typedef NTSTATUS(*NtPowerInformation_t)(ULONG, PVOID, ULONG, PVOID, ULONG);
    NtPowerInformation_t orig = (NtPowerInformation_t)
        g_SyscallHookStates[5].OriginalAddress;

    if (infoLevel == 0x05 || infoLevel == 0x1F) {
        return orig(infoLevel, input, inputLen, output, outputLen);
    }

    NTSTATUS status = orig(infoLevel, input, inputLen, output, outputLen);

    if (!NT_SUCCESS(status)) return status;

    // Spoof CPU performance information (class 0x0B)
    if (infoLevel == 0x0B && output && outputLen >= 6 * sizeof(ULONG)) {
        ULONG* cpu = (ULONG*)output;
        ULONG count = outputLen / (6 * sizeof(ULONG));
        for (ULONG i = 0; i < count; i++) {
            ULONG* e = cpu + (i * 6);
            e[1] = 3000;  // Current frequency
            e[2] = 3000;  // Max frequency
            e[3] = 3000;  // Min frequency
            e[4] = 0;
            e[5] = 0;
        }
        LoggerPrintF("[Syscall] Spoofed CPU power information (%u cores)\n", count);
    }

    if (infoLevel == 0x04 && output) {
        RtlZeroMemory(output, outputLen);
        LoggerPrintF("[Syscall] Zeroed power info (class 0x04)\n");
    }

    return status;
}

NTSTATUS HookNtQuerySystemEnvironmentValueEx(
    PUNICODE_STRING variableName,
    GUID* vendorGuid,
    PVOID value,
    PULONG valueLength,
    PULONG attributes)
{
    LoggerPrintF("[Syscall] Blocked NtQuerySystemEnvironmentValueEx\n");
    if (valueLength) *valueLength = 0;
    if (attributes) *attributes = 0;
    return STATUS_ACCESS_VIOLATION;
}

NTSTATUS HookNtEnumerateBootEntries(
    PVOID buffer,
    PULONG bufferLength)
{
    LoggerPrintF("[Syscall] Blocked NtEnumerateBootEntries\n");
    if (bufferLength) *bufferLength = 0;
    return STATUS_ACCESS_VIOLATION;
}

NTSTATUS HookNtQuerySystemEnvironmentValue(
    PUNICODE_STRING variableName,
    PWCH valueBuffer,
    ULONG valueLength,
    PULONG returnLength)
{
    LoggerPrintF("[Syscall] Blocked NtQuerySystemEnvironmentValue\n");
    if (returnLength) *returnLength = 0;
    return STATUS_ACCESS_VIOLATION;
}

NTSTATUS SyscallHooksCreate(VOID)
{
    NTSTATUS status;

    status = EatHookInstall(g_KernelBase, "NtQuerySystemInformation",
        HookNtQuerySystemInformation,
        (PVOID*)&g_SyscallHookStates[g_SyscallHookCount].OriginalAddress);
    if (NT_SUCCESS(status)) {
        g_SyscallHookStates[g_SyscallHookCount].ExportName = "NtQuerySystemInformation";
        g_SyscallHookStates[g_SyscallHookCount].Active = TRUE;
        g_SyscallHookCount++;
    }
    else {
        LoggerPrintF("[Syscall] EAT hook for NtQuerySystemInformation failed: 0x%X\n", status);
    }

    status = EatHookInstall(g_KernelBase, "NtQueryVolumeInformationFile",
        HookNtQueryVolumeInformationFile,
        (PVOID*)&g_SyscallHookStates[g_SyscallHookCount].OriginalAddress);
    if (NT_SUCCESS(status)) {
        g_SyscallHookStates[g_SyscallHookCount].ExportName = "NtQueryVolumeInformationFile";
        g_SyscallHookStates[g_SyscallHookCount].Active = TRUE;
        g_SyscallHookCount++;
    }

    status = EatHookInstall(g_KernelBase, "NtDeviceIoControlFile",
        HookNtDeviceIoControlFile,
        (PVOID*)&g_SyscallHookStates[g_SyscallHookCount].OriginalAddress);
    if (NT_SUCCESS(status)) {
        g_SyscallHookStates[g_SyscallHookCount].ExportName = "NtDeviceIoControlFile";
        g_SyscallHookStates[g_SyscallHookCount].Active = TRUE;
        g_SyscallHookCount++;
    }

    status = EatHookInstall(g_KernelBase, "NtAllocateUuids",
        HookNtAllocateUuids,
        (PVOID*)&g_SyscallHookStates[g_SyscallHookCount].OriginalAddress);
    if (NT_SUCCESS(status)) {
        g_SyscallHookStates[g_SyscallHookCount].ExportName = "NtAllocateUuids";
        g_SyscallHookStates[g_SyscallHookCount].Active = TRUE;
        g_SyscallHookCount++;
    }

    status = EatHookInstall(g_KernelBase, "NtQueryLicenseValue",
        HookNtQueryLicenseValue,
        (PVOID*)&g_SyscallHookStates[g_SyscallHookCount].OriginalAddress);
    if (NT_SUCCESS(status)) {
        g_SyscallHookStates[g_SyscallHookCount].ExportName = "NtQueryLicenseValue";
        g_SyscallHookStates[g_SyscallHookCount].Active = TRUE;
        g_SyscallHookCount++;
    }

    status = EatHookInstall(g_KernelBase, "NtPowerInformation",
        HookNtPowerInformation,
        (PVOID*)&g_SyscallHookStates[g_SyscallHookCount].OriginalAddress);
    if (NT_SUCCESS(status)) {
        g_SyscallHookStates[g_SyscallHookCount].ExportName = "NtPowerInformation";
        g_SyscallHookStates[g_SyscallHookCount].Active = TRUE;
        g_SyscallHookCount++;
    }

    status = EatHookInstall(g_KernelBase, "NtQuerySystemEnvironmentValueEx",
        HookNtQuerySystemEnvironmentValueEx,
        (PVOID*)&g_SyscallHookStates[g_SyscallHookCount].OriginalAddress);
    if (NT_SUCCESS(status)) {
        g_SyscallHookStates[g_SyscallHookCount].ExportName = "NtQuerySystemEnvironmentValueEx";
        g_SyscallHookStates[g_SyscallHookCount].Active = TRUE;
        g_SyscallHookCount++;
    }

    status = EatHookInstall(g_KernelBase, "NtEnumerateBootEntries",
        HookNtEnumerateBootEntries,
        (PVOID*)&g_SyscallHookStates[g_SyscallHookCount].OriginalAddress);
    if (NT_SUCCESS(status)) {
        g_SyscallHookStates[g_SyscallHookCount].ExportName = "NtEnumerateBootEntries";
        g_SyscallHookStates[g_SyscallHookCount].Active = TRUE;
        g_SyscallHookCount++;
    }

    status = EatHookInstall(g_KernelBase, "NtQuerySystemEnvironmentValue",
        HookNtQuerySystemEnvironmentValue,
        (PVOID*)&g_SyscallHookStates[g_SyscallHookCount].OriginalAddress);
    if (NT_SUCCESS(status)) {
        g_SyscallHookStates[g_SyscallHookCount].ExportName = "NtQuerySystemEnvironmentValue";
        g_SyscallHookStates[g_SyscallHookCount].Active = TRUE;
        g_SyscallHookCount++;
    }

    LoggerPrintF("[Syscall] Created %u EAT hooks\n", g_SyscallHookCount);

    return STATUS_SUCCESS;
}

VOID SyscallHooksRemove(VOID)
{
    for (ULONG i = 0; i < g_SyscallHookCount; i++) {
        if (g_SyscallHookStates[i].Active) {
            EatHookRemove(&g_SyscallHookStates[i]);
        }
    }
    g_SyscallHookCount = 0;
    LoggerPrintF("[Syscall] Removed all hooks\n");
}