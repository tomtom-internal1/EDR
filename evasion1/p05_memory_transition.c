#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "poc_common.h"

static const char *protect_name(DWORD p)
{
    switch (p & 0xff) {
        case PAGE_READWRITE: return "RW";
        case PAGE_READONLY: return "R";
        case PAGE_EXECUTE_READ: return "RX";
        case PAGE_EXECUTE_READWRITE: return "RWX";
        default: return "OTHER";
    }
}

int main(void)
{
    const char *poc = "P05_MEMORY_TRANSITION";
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    SIZE_T size = (SIZE_T)si.dwPageSize * 2;
    BYTE *region = (BYTE *)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!region) {
        poc_emit_error(poc, 1, "MEMORY_PROTECTION_LIFECYCLE", "VirtualAlloc");
        return 1;
    }

    DWORD old_protect = 0;
    MEMORY_BASIC_INFORMATION mbi;

    VirtualQuery(region, &mbi, sizeof(mbi));
    char details[384];
    snprintf(details, sizeof(details),
             "{\"operation\":\"VirtualAlloc\",\"size\":%llu,\"before_protect\":\"%s\","
             "\"state\":\"MEM_COMMIT\",\"execute_after_transition\":false}",
             (unsigned long long)size, protect_name(mbi.Protect));
    poc_emit(poc, 1, "MemoryAllocate", "MEMORY_PROTECTION_LIFECYCLE", details);

    for (SIZE_T i = 0; i < size; ++i) region[i] = (BYTE)(i & 0xff);

    poc_emit(poc, 2, "MemoryWrite", "MEMORY_PROTECTION_LIFECYCLE",
             "{\"write_pattern\":\"incrementing_byte\",\"execution\":\"none\"}");

    BOOL ok = VirtualProtect(region, size, PAGE_EXECUTE_READ, &old_protect);
    VirtualQuery(region, &mbi, sizeof(mbi));

    snprintf(details, sizeof(details),
             "{\"operation\":\"VirtualProtect\",\"result\":\"%s\",\"before\":\"%s\","
             "\"after\":\"%s\",\"payload_executed\":false}",
             ok ? "success" : "failure",
             protect_name(old_protect),
             protect_name(mbi.Protect));
    poc_emit(poc, 3, "MemoryProtectionChange", "MEMORY_PROTECTION_LIFECYCLE", details);

    if (ok) {
        DWORD ignored = 0;
        VirtualProtect(region, size, PAGE_READWRITE, &ignored);
    }

    SecureZeroMemory(region, size);
    VirtualFree(region, 0, MEM_RELEASE);

    poc_emit(poc, 4, "MemoryRelease", "MEMORY_PROTECTION_LIFECYCLE",
             "{\"released\":true,\"execution_never_performed\":true}");
    return 0;
}
