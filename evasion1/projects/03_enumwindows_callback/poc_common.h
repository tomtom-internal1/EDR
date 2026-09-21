#ifndef EVASION1_ADVANCED_COMMON_H
#define EVASION1_ADVANCED_COMMON_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

static unsigned long long adv_now_ms(void)
{
    FILETIME ft;
    ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return (unsigned long long)(u.QuadPart / 10000ULL);
}

static void adv_emit(const char *id, unsigned long seq,
                     const char *type, const char *technique,
                     const char *details)
{
    printf("{"poc_id":"%s","sequence":%lu,"timestamp_ms":%" PRIu64
           ","pid":%lu,"tid":%lu,"event_type":"%s","
           ""technique":"%s","details":%s}
",
           id, seq, (uint64_t)adv_now_ms(),
           (unsigned long)GetCurrentProcessId(),
           (unsigned long)GetCurrentThreadId(),
           type, technique, details ? details : "{}");
}

static void adv_error(const char *id, unsigned long seq,
                      const char *technique, const char *stage)
{
    DWORD e = GetLastError();
    char d[256];
    snprintf(d, sizeof(d), "{"stage":"%s","win32_error":%lu}",
             stage, (unsigned long)e);
    adv_emit(id, seq, "Error", technique, d);
}

#endif
