#include <ntddk.h>

DRIVER_UNLOAD KdasaUnload;
DRIVER_INITIALIZE DriverEntry;

static VOID KdasaLogUnicode(_In_ PCSTR Label, _In_opt_ PUNICODE_STRING Value)
{
    if (Value != NULL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "KDASA|%s=%wZ\n", Label, Value);
    }
    else
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "KDASA|%s=<null>\n", Label);
    }
}

static VOID KdasaProcessNotify(_In_ PEPROCESS Process, _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "KDASA|PROCESS_CREATE|PID=%p|ParentPID=%p\n",
            ProcessId, CreateInfo->ParentProcessId);
        KdasaLogUnicode("Image", CreateInfo->ImageFileName);
        KdasaLogUnicode("CommandLine", CreateInfo->CommandLine);
    }
    else
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "KDASA|PROCESS_EXIT|PID=%p\n", ProcessId);
    }
}

static VOID KdasaThreadNotify(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "KDASA|THREAD_%s|PID=%p|TID=%p\n",
        Create ? "CREATE" : "EXIT", ProcessId, ThreadId);
}

static VOID KdasaImageNotify(_In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo)
{
    BOOLEAN systemMode = FALSE;

    if (ImageInfo != NULL)
        systemMode = ImageInfo->SystemModeImage;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "KDASA|IMAGE_LOAD|PID=%p|SystemMode=%u\n",
        ProcessId, systemMode ? 1 : 0);

    KdasaLogUnicode("Image", FullImageName);

    if (ImageInfo != NULL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "KDASA|IMAGE_META|Base=%p|Size=%lu\n",
            ImageInfo->ImageBase, ImageInfo->ImageSize);
    }
}

VOID KdasaUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    PsSetCreateProcessNotifyRoutineEx(KdasaProcessNotify, TRUE);
    PsRemoveCreateThreadNotifyRoutine(KdasaThreadNotify);
    PsRemoveLoadImageNotifyRoutine(KdasaImageNotify);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "KDASA|UNLOAD\n");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = KdasaUnload;

    status = PsSetCreateProcessNotifyRoutineEx(KdasaProcessNotify, FALSE);
    if (!NT_SUCCESS(status))
        return status;

    status = PsSetCreateThreadNotifyRoutine(KdasaThreadNotify);
    if (!NT_SUCCESS(status))
    {
        PsSetCreateProcessNotifyRoutineEx(KdasaProcessNotify, TRUE);
        return status;
    }

    status = PsSetLoadImageNotifyRoutine(KdasaImageNotify);
    if (!NT_SUCCESS(status))
    {
        PsRemoveCreateThreadNotifyRoutine(KdasaThreadNotify);
        PsSetCreateProcessNotifyRoutineEx(KdasaProcessNotify, TRUE);
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "KDASA|LOAD|callbacks=process,thread,image\n");

    return STATUS_SUCCESS;
}
