#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "poc_common.h"

typedef struct {
    HANDLE done;
    DWORD callback_tid;
} WAIT_CTX;

static VOID CALLBACK wait_callback(PVOID p, BOOLEAN timed_out)
{
    WAIT_CTX *ctx = (WAIT_CTX *)p;
    ctx->callback_tid = GetCurrentThreadId();

    char d[320];
    snprintf(d, sizeof(d),
             "{\"callback_tid\":%lu,\"timed_out\":%s,"
             "\"execution\":\"benign\",\"application_created_thread\":false}",
             (unsigned long)ctx->callback_tid,
             timed_out ? "true" : "false");
    adv_emit("A10_WAIT_CALLBACK", 2, "WaitCallback",
             "WAIT_CALLBACK_EXECUTION", d);
    SetEvent(ctx->done);
}

int main(void)
{
    const char *id = "A10_WAIT_CALLBACK";
    HANDLE signal = CreateEventW(NULL, TRUE, FALSE, NULL);
    WAIT_CTX ctx = {0};
    ctx.done = CreateEventW(NULL, TRUE, FALSE, NULL);

    if (!signal || !ctx.done) {
        adv_error(id, 1, "WAIT_CALLBACK_EXECUTION", "CreateEvent");
        if (signal) CloseHandle(signal);
        if (ctx.done) CloseHandle(ctx.done);
        return 1;
    }

    HANDLE registration = NULL;
    if (!RegisterWaitForSingleObject(&registration, signal, wait_callback,
                                     &ctx, 3000, WT_EXECUTEDEFAULT)) {
        adv_error(id, 1, "WAIT_CALLBACK_EXECUTION", "RegisterWaitForSingleObject");
        CloseHandle(signal);
        CloseHandle(ctx.done);
        return 1;
    }

    adv_emit(id, 1, "WaitRegistration", "WAIT_CALLBACK_EXECUTION",
             "{\"primitive\":\"RegisterWaitForSingleObject\","
             "\"worker_model\":\"threadpool\",\"explicit_thread_creation\":false}");

    SetEvent(signal);
    WaitForSingleObject(ctx.done, 5000);

    UnregisterWaitEx(registration, INVALID_HANDLE_VALUE);

    char d[256];
    snprintf(d, sizeof(d),
             "{\"callback_tid\":%lu,\"caller_tid\":%lu,"
             "\"threadpool_callback\":true}",
             (unsigned long)ctx.callback_tid,
             (unsigned long)GetCurrentThreadId());
    adv_emit(id, 3, "CallbackCorrelation", "WAIT_CALLBACK_EXECUTION", d);

    adv_emit(id, 4, "DetectionOracle", "WAIT_CALLBACK_EXECUTION",
             "{\"expected_detection\":\"deferred_callback_execution_without_application_thread_creation\","
             "\"correlate\":[\"WaitRegistration\",\"WaitCallback\"]}");

    CloseHandle(signal);
    CloseHandle(ctx.done);
    return 0;
}
