#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "poc_common.h"

typedef struct {
    HANDLE ready;
    HANDLE done;
    DWORD worker_tid;
    volatile LONG callback_count;
} APC_CONTEXT;

static VOID CALLBACK benign_apc_a(ULONG_PTR parameter)
{
    APC_CONTEXT *ctx = (APC_CONTEXT *)parameter;
    InterlockedIncrement(&ctx->callback_count);
    poc_emit("P03_APC_EXECUTION", 3, "ApcCallback", "APC_EXECUTION_CONTEXT",
             "{\"callback_id\":\"A\",\"payload\":\"none\",\"execution\":\"benign\"}");
}

static VOID CALLBACK benign_apc_b(ULONG_PTR parameter)
{
    APC_CONTEXT *ctx = (APC_CONTEXT *)parameter;
    InterlockedIncrement(&ctx->callback_count);
    poc_emit("P03_APC_EXECUTION", 4, "ApcCallback", "APC_EXECUTION_CONTEXT",
             "{\"callback_id\":\"B\",\"payload\":\"none\",\"execution\":\"benign\"}");
    SetEvent(ctx->done);
}

static DWORD WINAPI alertable_worker(LPVOID parameter)
{
    APC_CONTEXT *ctx = (APC_CONTEXT *)parameter;
    ctx->worker_tid = GetCurrentThreadId();

    poc_emit("P03_APC_EXECUTION", 1, "ThreadStart", "APC_EXECUTION_CONTEXT",
             "{\"thread_role\":\"alertable_worker\",\"alertable_wait\":true}");
    SetEvent(ctx->ready);

    while (WaitForSingleObject(ctx->done, 0) != WAIT_OBJECT_0) {
        DWORD r = SleepEx(5000, TRUE);
        if (r != WAIT_IO_COMPLETION)
            Sleep(25);
    }

    poc_emit("P03_APC_EXECUTION", 5, "ThreadStop", "APC_EXECUTION_CONTEXT",
             "{\"thread_role\":\"alertable_worker\",\"callback_count\":2}");
    return 0;
}

int main(void)
{
    const char *poc = "P03_APC_EXECUTION";
    APC_CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    ctx.done = CreateEventW(NULL, TRUE, FALSE, NULL);

    if (!ctx.ready || !ctx.done) {
        poc_emit_error(poc, 1, "APC_EXECUTION_CONTEXT", "CreateEvent");
        return 1;
    }

    HANDLE worker = CreateThread(NULL, 0, alertable_worker, &ctx, 0, NULL);
    if (!worker) {
        poc_emit_error(poc, 1, "APC_EXECUTION_CONTEXT", "CreateThread");
        return 1;
    }

    WaitForSingleObject(ctx.ready, INFINITE);

    char details[256];
    snprintf(details, sizeof(details),
             "{\"target_tid\":%lu,\"queue_api\":\"QueueUserAPC\","
             "\"target_process\":\"self\",\"callback_count_expected\":2}",
             (unsigned long)ctx.worker_tid);
    poc_emit(poc, 2, "ApcQueue", "APC_EXECUTION_CONTEXT", details);

    if (!QueueUserAPC(benign_apc_a, worker, (ULONG_PTR)&ctx) ||
        !QueueUserAPC(benign_apc_b, worker, (ULONG_PTR)&ctx)) {
        poc_emit_error(poc, 2, "APC_EXECUTION_CONTEXT", "QueueUserAPC");
        SetEvent(ctx.done);
        WaitForSingleObject(worker, 1000);
        CloseHandle(worker);
        CloseHandle(ctx.ready);
        CloseHandle(ctx.done);
        return 1;
    }

    WaitForSingleObject(ctx.done, 5000);
    WaitForSingleObject(worker, 5000);

    snprintf(details, sizeof(details),
             "{\"callbacks_observed\":%ld,\"thread_tid\":%lu,"
             "\"new_thread_after_queue\":false}",
             (long)ctx.callback_count, (unsigned long)ctx.worker_tid);
    poc_emit(poc, 6, "CorrelationResult", "APC_EXECUTION_CONTEXT", details);

    CloseHandle(worker);
    CloseHandle(ctx.ready);
    CloseHandle(ctx.done);
    return 0;
}
