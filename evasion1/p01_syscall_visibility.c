#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include "poc_common.h"

typedef LONG (NTAPI *PFN_NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtection,
    PULONG OldProtection
);

static int call_ntprotect(PFN_NtProtectVirtualMemory fn, void *address, SIZE_T size,
                          ULONG new_protect, ULONG *old_protect, LONG *status_out)
{
    PVOID base = address;
    SIZE_T region = size;
    LONG status = fn(GetCurrentProcess(), &base, &region, new_protect, old_protect);
    *status_out = status;
    return status == 0;
}

int main(void)
{
    const char *poc = "P01_SYSCALL_VISIBILITY";
    unsigned long seq = 1;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    FARPROC export_addr = ntdll ? GetProcAddress(ntdll, "NtProtectVirtualMemory") : NULL;
    if (!ntdll || !export_addr) {
        poc_emit_error(poc, seq++, "SYSCALL_PATH_VISIBILITY", "resolve_ntdll_export");
        return 1;
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    SIZE_T size = si.dwPageSize;
    BYTE *page = (BYTE *)VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!page) {
        poc_emit_error(poc, seq++, "SYSCALL_PATH_VISIBILITY", "VirtualAlloc");
        return 1;
    }

    poc_emit(poc, seq++, "ProcessStart", "SYSCALL_PATH_VISIBILITY",
             "{\"architecture_tested\":\"native_process\",\"operational_bypass\":false}");

    char details[512];
    snprintf(details, sizeof(details),
             "{\"module\":\"ntdll.dll\",\"export\":\"NtProtectVirtualMemory\","
             "\"address\":\"%p\",\"page_size\":%llu}", export_addr,
             (unsigned long long)size);
    poc_emit(poc, seq++, "ApiResolution", "SYSCALL_PATH_VISIBILITY", details);

    page[0] = 0x41;
    DWORD old_win32 = 0;
    BOOL win32_ok = VirtualProtect(page, size, PAGE_READONLY, &old_win32);

    snprintf(details, sizeof(details),
             "{\"api_layer\":\"VirtualProtect\",\"operation\":\"RW_to_R\","
             "\"result\":\"%s\",\"old_protect\":%lu}",
             win32_ok ? "success" : "failure", (unsigned long)old_win32);
    poc_emit(poc, seq++, "UserApiOperation", "SYSCALL_PATH_VISIBILITY", details);

    DWORD ignored = 0;
    VirtualProtect(page, size, PAGE_READWRITE, &ignored);

    PFN_NtProtectVirtualMemory ntprotect = (PFN_NtProtectVirtualMemory)export_addr;
    ULONG old_nt = 0;
    LONG status = 0;
    int nt_ok = call_ntprotect(ntprotect, page, size, PAGE_READONLY, &old_nt, &status);

    snprintf(details, sizeof(details),
             "{\"api_layer\":\"ntdll_export\",\"export\":\"NtProtectVirtualMemory\","
             "\"operation\":\"RW_to_R\",\"result\":\"%s\","
             "\"ntstatus\":%ld,\"old_protect\":%lu,\"direct_syscall_executed\":false}",
             nt_ok ? "success" : "failure", (long)status, (unsigned long)old_nt);
    poc_emit(poc, seq++, "NtdllExportOperation", "SYSCALL_PATH_VISIBILITY", details);

    VirtualProtect(page, size, PAGE_READWRITE, &ignored);
    SecureZeroMemory(page, size);
    VirtualFree(page, 0, MEM_RELEASE);

    poc_emit(poc, seq++, "DetectionOracle", "SYSCALL_PATH_VISIBILITY",
             "{\"expected_detection\":\"semantic_memory_protection_activity\","
             "\"correlate\":[\"UserApiOperation\",\"NtdllExportOperation\"],"
             "\"do_not_require\":\"user_mode_hook\"}");
    poc_emit(poc, seq++, "ProcessStop", "SYSCALL_PATH_VISIBILITY",
             "{\"complete\":true,\"payload_execution\":false}");
    return 0;
}
