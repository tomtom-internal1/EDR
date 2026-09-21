#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "poc_common.h"

static HANDLE g_ready;
static HANDLE g_go;
static HANDLE g_hit;
static volatile LONG g_hits;

__declspec(noinline) static void breakpoint_target(void)
{
    volatile unsigned long sink = 0x12345678UL;
    sink ^= 0x55AA55AAUL;
    (void)sink;
}

static LONG CALLBACK veh(PEXCEPTION_POINTERS ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    InterlockedIncrement(&g_hits);

#ifdef _WIN64
    ep->ContextRecord->Dr0 = 0;
    ep->ContextRecord->Dr7 &= ~1ULL;
#else
    ep->ContextRecord->Dr0 = 0;
    ep->ContextRecord->Dr7 &= ~1UL;
#endif

    adv_emit("A04_HW_BREAKPOINT_VEH", 2, "HardwareBreakpointHit",
             "PATCHLESS_SELF_INSTRUMENTATION",
             "{\"target\":\"breakpoint_target\",\"memory_patch\":false,"
             "\"return_value_modified\":false}");

    SetEvent(g_hit);
    return EXCEPTION_CONTINUE_EXECUTION;
}

static DWORD WINAPI worker(LPVOID p)
{
    UNREFERENCED_PARAMETER(p);
    SetEvent(g_ready);
    WaitForSingleObject(g_go, INFINITE);
    breakpoint_target();

    adv_emit("A04_HW_BREAKPOINT_VEH", 3, "TargetReturned",
             "PATCHLESS_SELF_INSTRUMENTATION",
             "{\"target_returned\":true,\"execution\":\"benign\"}");
    return 0;
}

int main(void)
{
    const char *id = "A04_HW_BREAKPOINT_VEH";
    g_ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_go = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_hit = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_ready || !g_go || !g_hit) {
        adv_error(id, 1, "PATCHLESS_SELF_INSTRUMENTATION", "CreateEvent");
        return 1;
    }

    PVOID handler = AddVectoredExceptionHandler(1, veh);
    if (!handler) {
        adv_error(id, 1, "PATCHLESS_SELF_INSTRUMENTATION", "AddVectoredExceptionHandler");
        return 1;
    }

    HANDLE t = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    if (!t) {
        adv_error(id, 1, "PATCHLESS_SELF_INSTRUMENTATION", "CreateThread");
        RemoveVectoredExceptionHandler(handler);
        return 1;
    }

    WaitForSingleObject(g_ready, INFINITE);

    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SuspendThread(t);

    if (!GetThreadContext(t, &ctx)) {
        adv_error(id, 1, "PATCHLESS_SELF_INSTRUMENTATION", "GetThreadContext");
        ResumeThread(t);
        CloseHandle(t);
        RemoveVectoredExceptionHandler(handler);
        return 1;
    }

#ifdef _WIN64
    ctx.Dr0 = (DWORD64)(ULONG_PTR)breakpoint_target;
    ctx.Dr7 |= 1ULL;
#else
    ctx.Dr0 = (DWORD)(ULONG_PTR)breakpoint_target;
    ctx.Dr7 |= 1UL;
#endif

    if (!SetThreadContext(t, &ctx)) {
        adv_error(id, 1, "PATCHLESS_SELF_INSTRUMENTATION", "SetThreadContext");
        ResumeThread(t);
        CloseHandle(t);
        RemoveVectoredExceptionHandler(handler);
        return 1;
    }

    adv_emit(id, 1, "HardwareBreakpointArmed",
             "PATCHLESS_SELF_INSTRUMENTATION",
             "{\"scope\":\"same_process\",\"target\":\"breakpoint_target\","
             "\"code_patch\":false}");

    ResumeThread(t);
    SetEvent(g_go);

    WaitForSingleObject(g_hit, 3000);
    WaitForSingleObject(t, 3000);

    char d[256];
    snprintf(d, sizeof(d),
             "{\"hits\":%ld,\"same_process\":true,\"code_modified\":false}",
             (long)g_hits);
    adv_emit(id, 4, "DetectionOracle", "PATCHLESS_SELF_INSTRUMENTATION", d);

    CloseHandle(t);
    RemoveVectoredExceptionHandler(handler);
    CloseHandle(g_ready);
    CloseHandle(g_go);
    CloseHandle(g_hit);
    return g_hits > 0 ? 0 : 2;
}
