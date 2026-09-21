#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "poc_common.h"

typedef LONG NTSTATUS;
typedef enum _THREADINFOCLASS_LAB {
    ThreadQuerySetWin32StartAddress = 9
} THREADINFOCLASS_LAB;

typedef NTSTATUS (NTAPI *PFN_NtQueryInformationThread)(
    HANDLE, THREADINFOCLASS_LAB, PVOID, ULONG, PULONG);

static DWORD WINAPI worker(LPVOID p)
{
    UNREFERENCED_PARAMETER(p);
    Sleep(800);
    return 0;
}

int main(void)
{
    const char *id = "A05_NATIVE_THREAD_INTROSPECTION";
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    PFN_NtQueryInformationThread ntq = ntdll ?
        (PFN_NtQueryInformationThread)GetProcAddress(ntdll, "NtQueryInformationThread") : NULL;

    if (!ntq) {
        adv_error(id, 1, "NATIVE_THREAD_INTROSPECTION", "resolve_NtQueryInformationThread");
        return 1;
    }

    HANDLE t = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    if (!t) {
        adv_error(id, 1, "NATIVE_THREAD_INTROSPECTION", "CreateThread");
        return 1;
    }

    PVOID native_start = NULL;
    ULONG returned = 0;
    NTSTATUS status = ntq(t, ThreadQuerySetWin32StartAddress,
                          &native_start, (ULONG)sizeof(native_start), &returned);

    char d[512];
    snprintf(d, sizeof(d),
             "{\"thread_tid\":%lu,\"ntstatus\":%ld,"
             "\"reported_start\":\"%p\",\"expected_start\":\"%p\","
             "\"match\":%s}",
             (unsigned long)GetThreadId(t),
             (long)status,
             native_start,
             (void *)worker,
             native_start == (PVOID)worker ? "true" : "false");
    adv_emit(id, 1, "NativeThreadQuery", "NATIVE_THREAD_INTROSPECTION", d);

    adv_emit(id, 2, "DetectionOracle", "NATIVE_THREAD_INTROSPECTION",
             "{\"expected_detection\":\"independent_thread_start_provenance\","
             "\"correlate\":[\"thread_identity\",\"start_address\"]}");

    WaitForSingleObject(t, 2000);
    CloseHandle(t);
    return 0;
}
