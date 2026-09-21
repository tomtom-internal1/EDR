#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "poc_common.h"

static HANDLE g_done;

static VOID CALLBACK benign_timer(PVOID parameter, BOOLEAN fired)
{
    UNREFERENCED_PARAMETER(parameter);
    UNREFERENCED_PARAMETER(fired);

    poc_emit("P04_TIMER_CALLBACK", 2, "TimerCallback", "TIMER_CALLBACK_EXECUTION",
             "{\"callback\":\"benign_timer\",\"payload\":\"none\",\"execution\":\"benign\"}");
    SetEvent(g_done);
}

int main(void)
{
    const char *poc = "P04_TIMER_CALLBACK";
    HANDLE queue = NULL;
    HANDLE timer = NULL;
    g_done = CreateEventW(NULL, TRUE, FALSE, NULL);

    if (!g_done) {
        poc_emit_error(poc, 1, "TIMER_CALLBACK_EXECUTION", "CreateEvent");
        return 1;
    }

    if (!CreateTimerQueue(&queue)) {
        poc_emit_error(poc, 1, "TIMER_CALLBACK_EXECUTION", "CreateTimerQueue");
        CloseHandle(g_done);
        return 1;
    }

    poc_emit(poc, 1, "TimerRegistered", "TIMER_CALLBACK_EXECUTION",
             "{\"api\":\"CreateTimerQueueTimer\",\"due_ms\":50,\"period_ms\":0,"
             "\"callback_type\":\"benign_function\",\"payload\":\"none\"}");

    if (!CreateTimerQueueTimer(&timer, queue, benign_timer, NULL, 50, 0, WT_EXECUTEDEFAULT)) {
        poc_emit_error(poc, 1, "TIMER_CALLBACK_EXECUTION", "CreateTimerQueueTimer");
        DeleteTimerQueue(queue);
        CloseHandle(g_done);
        return 1;
    }

    WaitForSingleObject(g_done, 5000);

    DeleteTimerQueueTimer(queue, timer, g_done);
    DeleteTimerQueue(queue);

    poc_emit(poc, 3, "TimerLifecycleEnd", "TIMER_CALLBACK_EXECUTION",
             "{\"callback_executed\":true,\"payload_execution\":false}");

    CloseHandle(g_done);
    return 0;
}
