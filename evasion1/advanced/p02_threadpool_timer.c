#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "poc_common.h"

typedef struct {
    HANDLE done;
    DWORD callback_tid;
} TIMER_CTX;

static VOID CALLBACK callback(PTP_CALLBACK_INSTANCE instance, PVOID context, PTP_TIMER timer)
{
    UNREFERENCED_PARAMETER(instance);
    UNREFERENCED_PARAMETER(timer);
    TIMER_CTX *ctx = (TIMER_CTX *)context;
    ctx->callback_tid = GetCurrentThreadId();

    char d[256];
    snprintf(d, sizeof(d),
             "{\"callback_tid\":%lu,\"worker_model\":\"Windows_threadpool\","
             "\"application_created_thread\":false,\"payload\":\"none\"}",
             (unsigned long)ctx->callback_tid);
    adv_emit("A02_THREADPOOL_TIMER", 2, "ThreadpoolCallback",
             "THREADPOOL_TIMER_EXECUTION", d);
    SetEvent(ctx->done);
}

int main(void)
{
    const char *id = "A02_THREADPOOL_TIMER";
    TIMER_CTX ctx = {0};
    ctx.done = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ctx.done) {
        adv_error(id, 1, "THREADPOOL_TIMER_EXECUTION", "CreateEvent");
        return 1;
    }

    PTP_TIMER timer = CreateThreadpoolTimer(callback, &ctx, NULL);
    if (!timer) {
        adv_error(id, 1, "THREADPOOL_TIMER_EXECUTION", "CreateThreadpoolTimer");
        CloseHandle(ctx.done);
        return 1;
    }

    adv_emit(id, 1, "ThreadpoolTimerRegister", "THREADPOOL_TIMER_EXECUTION",
             "{\"api\":\"CreateThreadpoolTimer\",\"due_ms\":100,"
             "\"period_ms\":0,\"callback_kind\":\"benign_function\"}");

    ULARGE_INTEGER now;
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    now.LowPart = ft.dwLowDateTime;
    now.HighPart = ft.dwHighDateTime;
    now.QuadPart -= 100ULL * 10000ULL;

    FILETIME when;
    when.dwLowDateTime = now.LowPart;
    when.dwHighDateTime = now.HighPart;

    SetThreadpoolTimer(timer, &when, 0, 0);
    WaitForSingleObject(ctx.done, 5000);

    SetThreadpoolTimer(timer, NULL, 0, 0);
    WaitForThreadpoolTimerCallbacks(timer, TRUE);
    CloseThreadpoolTimer(timer);

    adv_emit(id, 3, "DetectionOracle", "THREADPOOL_TIMER_EXECUTION",
             "{\"expected_detection\":\"callback_execution_without_application_thread_creation\","
             "\"correlate\":[\"ThreadpoolTimerRegister\",\"ThreadpoolCallback\"]}");

    CloseHandle(ctx.done);
    return 0;
}
