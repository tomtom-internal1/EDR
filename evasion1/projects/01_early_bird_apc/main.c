#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "poc_common.h"

typedef struct {
    HANDLE ready;
    HANDLE done;
    DWORD worker_tid;
} CTX;

static VOID CALLBACK benign_apc(ULONG_PTR p)
{
    CTX *ctx = (CTX *)p;
    adv_emit("A01_EARLY_BIRD_APC", 3, "ApcCallback",
             "EARLY_BIRD_APC_LIFECYCLE",
             "{\"execution\":\"benign\",\"payload\":\"none\",\"remote_process\":false}");
    SetEvent(ctx->done);
}

static DWORD WINAPI worker(LPVOID p)
{
    CTX *ctx = (CTX *)p;
    ctx->worker_tid = GetCurrentThreadId();

    adv_emit("A01_EARLY_BIRD_APC", 1, "WorkerStart",
             "EARLY_BIRD_APC_LIFECYCLE",
             "{\"thread_state\":\"resumed\",\"alertable_wait\":true}");
    SetEvent(ctx->ready);

    SleepEx(2000, TRUE);

    adv_emit("A01_EARLY_BIRD_APC", 4, "WorkerStop",
             "EARLY_BIRD_APC_LIFECYCLE",
             "{\"status\":\"complete\"}");
    return 0;
}

int main(void)
{
    const char *id = "A01_EARLY_BIRD_APC";
    CTX ctx = {0};
    ctx.ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    ctx.done = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ctx.ready || !ctx.done) {
        adv_error(id, 1, "EARLY_BIRD_APC_LIFECYCLE", "CreateEvent");
        return 1;
    }

    HANDLE t = CreateThread(NULL, 0, worker, &ctx, CREATE_SUSPENDED, NULL);
    if (!t) {
        adv_error(id, 1, "EARLY_BIRD_APC_LIFECYCLE", "CreateThread");
        return 1;
    }

    DWORD tid = GetThreadId(t);
    char d[256];
    snprintf(d, sizeof(d),
             "{\"target_tid\":%lu,\"thread_state\":\"suspended\","
             "\"queue_before_resume\":true,\"same_process\":true}",
             (unsigned long)tid);
    adv_emit(id, 2, "ApcQueuedBeforeResume", "EARLY_BIRD_APC_LIFECYCLE", d);

    if (!QueueUserAPC(benign_apc, t, (ULONG_PTR)&ctx)) {
        adv_error(id, 3, "EARLY_BIRD_APC_LIFECYCLE", "QueueUserAPC");
        TerminateThread(t, 1);
        CloseHandle(t);
        CloseHandle(ctx.ready);
        CloseHandle(ctx.done);
        return 1;
    }

    ResumeThread(t);
    WaitForSingleObject(ctx.done, 4000);
    WaitForSingleObject(t, 1000);

    snprintf(d, sizeof(d),
             "{\"target_tid\":%lu,\"callback_delivery\":\"alertable_wait\","
             "\"same_process\":true,\"new_remote_thread\":false}",
             (unsigned long)ctx.worker_tid);
    adv_emit(id, 5, "CorrelationResult", "EARLY_BIRD_APC_LIFECYCLE", d);

    adv_emit(id, 6, "DetectionOracle", "EARLY_BIRD_APC_LIFECYCLE",
             "{\"expected_detection\":\"APC_queued_before_resume_and_delivered_on_target_TID\","
             "\"correlate\":[\"ApcQueuedBeforeResume\",\"ApcCallback\",\"CorrelationResult\"]}");

    CloseHandle(t);
    CloseHandle(ctx.ready);
    CloseHandle(ctx.done);
    return 0;
}
