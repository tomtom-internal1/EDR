#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "poc_common.h"

typedef struct {
    HANDLE ready;
    HANDLE done;
} APC_CONTEXT;

static VOID CALLBACK benign_apc(ULONG_PTR parameter)
{
    APC_CONTEXT *ctx = (APC_CONTEXT *)parameter;
    poc_emit("P03_APC_EXECUTION", 3, "ApcCallback", "APC_EXECUTION_CONTEXT",
             "{\"callback\":\"benign_apc\",\"payload\":\"none\",\"execution\":\"benign\"}");
    SetEvent(ctx->done);
}

static DWORD WINAPI alertable_worker(LPVOID parameter)
{
    APC_CONTEXT *ctx = (APC_CONTEXT *)parameter;

    poc_emit("P03_APC_EXECUTION", 1, "ThreadStart", "APC_EXECUTION_CONTEXT",
             "{\"thread_role\":\"alertable_worker\"}");
    SetEvent(ctx->ready);

    for (;;) {
        DWORD result = SleepEx(5000, TRUE);
        if (result == WAIT_OBJECT_0) break;
        if (WaitForSingleObject(ctx->done, 0) == WAIT_OBJECT_0) break;
    }

    poc_emit("P03_APC_EXECUTION", 4, "ThreadStop", "APC_EXECUTION_CONTEXT",
             "{\"thread_role\":\"alertable_worker\",\"status\":\"complete\"}");
    return 0;
}

int main(void)
{
    APC_CONTEXT ctx = {0};
    ctx.ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    ctx.done = CreateEventW(NULL, TRUE, FALSE, NULL);

    if (!ctx.ready || !ctx.done) {
        poc_emit_error("P03_APC_EXECUTION", 1, "APC_EXECUTION_CONTEXT", "CreateEvent");
        return 1;
    }

    HANDLE thread = CreateThread(NULL, 0, alertable_worker, &ctx, 0, NULL);
    if (!thread) {
        poc_emit_error("P03_APC_EXECUTION", 1, "APC_EXECUTION_CONTEXT", "CreateThread");
        return 1;
    }

    WaitForSingleObject(ctx.ready, INFINITE);

    DWORD target_tid = GetThreadId(thread);
    char details[256];
    snprintf(details, sizeof(details),
             "{\"target_tid\":%lu,\"queue_api\":\"QueueUserAPC\",\"payload_type\":\"benign_callback_pointer\"}",
             (unsigned long)target_tid);
    poc_emit("P03_APC_EXECUTION", 2, "ApcQueued", "APC_EXECUTION_CONTEXT", details);

    if (!QueueUserAPC(benign_apc, thread, (ULONG_PTR)&ctx)) {
        poc_emit_error("P03_APC_EXECUTION", 2, "APC_EXECUTION_CONTEXT", "QueueUserAPC");
        TerminateThread(thread, 1);
        CloseHandle(thread);
        CloseHandle(ctx.ready);
        CloseHandle(ctx.done);
        return 1;
    }

    WaitForSingleObject(ctx.done, 5000);
    WaitForSingleObject(thread, 5000);

    CloseHandle(thread);
    CloseHandle(ctx.ready);
    CloseHandle(ctx.done);
    return 0;
}
