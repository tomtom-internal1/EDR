#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "poc_common.h"

typedef struct {
    HANDLE done;
    DWORD callback_tid;
} TIMER_CONTEXT;

static VOID CALLBACK benign_timer(PVOID parameter, BOOLEAN fired)
{
    TIMER_CONTEXT *ctx = (TIMER_CONTEXT *)parameter;
    ctx->callback_tid = GetCurrentThreadId();

    char details[256];
    snprintf(details, sizeof(details),
             "{\"callback\":\"benign_timer\",\"callback_tid\":%lu,"
             "\"fired\":%s,\"payload\":\"none\"}",
             (unsigned long)ctx->callback_tid, fired ? "true" : "false");
    poc_emit("P04_TIMER_CALLBACK", 2, "TimerCallback", "TIMER_CALLBACK_EXECUTION", details);
    SetEvent(ctx->done);
}

int main(void)
{
    const char *poc = "P04_TIMER_CALLBACK";
    HANDLE queue = NULL;
    HANDLE timer = NULL;
    TIMER_CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.done = CreateEventW(NULL, TRUE, FALSE, NULL);

    if (!ctx.done || !CreateTimerQueue(&queue)) {
        poc_emit_error(poc, 1, "TIMER_CALLBACK_EXECUTION", "timer_initialization");
        if (ctx.done) CloseHandle(ctx.done);
        return 1;
    }

    poc_emit(poc, 1, "TimerRegistration", "TIMER_CALLBACK_EXECUTION",
             "{\"api\":\"CreateTimerQueueTimer\",\"due_ms\":50,"
             "\"period_ms\":0,\"callback_kind\":\"benign_function\","
             "\"execution_payload\":false}");

    if (!CreateTimerQueueTimer(&timer, queue, benign_timer, &ctx, 50, 0, WT_EXECUTEDEFAULT)) {
        poc_emit_error(poc, 1, "TIMER_CALLBACK_EXECUTION", "CreateTimerQueueTimer");
        DeleteTimerQueue(queue);
        CloseHandle(ctx.done);
        return 1;
    }

    WaitForSingleObject(ctx.done, 5000);

    BOOL deleted = DeleteTimerQueueTimer(queue, timer, INVALID_HANDLE_VALUE);
    DeleteTimerQueue(queue);

    char details[256];
    snprintf(details, sizeof(details),
             "{\"timer_deleted\":%s,\"callback_tid\":%lu,"
             "\"deferred_execution_observed\":%s}",
             deleted ? "true" : "false",
             (unsigned long)ctx.callback_tid,
             ctx.callback_tid ? "true" : "false");
    poc_emit(poc, 3, "TimerLifecycleEnd", "TIMER_CALLBACK_EXECUTION", details);

    CloseHandle(ctx.done);

    poc_emit(poc, 4, "DetectionOracle", "TIMER_CALLBACK_EXECUTION",
             "{\"expected_detection\":\"registration_to_callback_correlation\","
             "\"signals\":[\"TimerRegistration\",\"TimerCallback\",\"callback_tid\"]}");
    return 0;
}
