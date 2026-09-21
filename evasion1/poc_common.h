#ifndef EVASION1_POC_COMMON_H
#define EVASION1_POC_COMMON_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

static unsigned long long poc_now_ms(void)
{
    FILETIME ft;
    ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return (unsigned long long)(u.QuadPart / 10000ULL);
}

static DWORD poc_pid(void)
{
    return GetCurrentProcessId();
}

static DWORD poc_tid(void)
{
    return GetCurrentThreadId();
}

static void poc_emit(const char *poc_id,
                     unsigned long sequence,
                     const char *event_type,
                     const char *technique,
                     const char *details_json)
{
    printf("{\"poc_id\":\"%s\",\"sequence\":%lu,\"timestamp_ms\":%" PRIu64
           ",\"pid\":%lu,\"tid\":%lu,\"event_type\":\"%s\",\"technique\":\"%s\",\"details\":%s}\n",
           poc_id,
           sequence,
           (uint64_t)poc_now_ms(),
           (unsigned long)poc_pid(),
           (unsigned long)poc_tid(),
           event_type,
           technique,
           details_json ? details_json : "{}");
}

static void poc_emit_error(const char *poc_id,
                           unsigned long sequence,
                           const char *technique,
                           const char *stage)
{
    DWORD err = GetLastError();
    char details[256];
    snprintf(details, sizeof(details),
             "{\"stage\":\"%s\",\"win32_error\":%lu}",
             stage, (unsigned long)err);
    poc_emit(poc_id, sequence, "Error", technique, details);
}

#endif
