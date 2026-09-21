#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "poc_common.h"

typedef struct {
    DWORD count;
    DWORD first_tid;
} ENUM_CTX;

static BOOL CALLBACK window_cb(HWND hwnd, LPARAM p)
{
    ENUM_CTX *ctx = (ENUM_CTX *)p;
    if (ctx->count == 0)
        ctx->first_tid = GetCurrentThreadId();

    ++ctx->count;

    if (ctx->count == 1) {
        char d[320];
        snprintf(d, sizeof(d),
                 "{\"hwnd\":\"0x%p\",\"callback_tid\":%lu,"
                 "\"execution\":\"benign_callback\",\"payload\":\"none\"}",
                 (void *)hwnd, (unsigned long)GetCurrentThreadId());
        adv_emit("A03_ENUMWINDOWS_CALLBACK", 2,
                 "EnumerationCallback", "CALLBACK_BASED_EXECUTION", d);
    }

    return ctx->count < 8;
}

int main(void)
{
    const char *id = "A03_ENUMWINDOWS_CALLBACK";
    ENUM_CTX ctx = {0};

    adv_emit(id, 1, "EnumerationStart", "CALLBACK_BASED_EXECUTION",
             "{\"api\":\"EnumWindows\",\"application_created_thread\":false}");

    BOOL ok = EnumWindows(window_cb, (LPARAM)&ctx);

    char d[320];
    snprintf(d, sizeof(d),
             "{\"enumwindows_result\":%s,\"callbacks_seen\":%lu,"
             "\"first_callback_tid\":%lu,\"current_tid\":%lu}",
             ok ? "true" : "false",
             (unsigned long)ctx.count,
             (unsigned long)ctx.first_tid,
             (unsigned long)GetCurrentThreadId());
    adv_emit(id, 3, "EnumerationResult", "CALLBACK_BASED_EXECUTION", d);

    adv_emit(id, 4, "DetectionOracle", "CALLBACK_BASED_EXECUTION",
             "{\"expected_detection\":\"execution_through_callback_surface\","
             "\"do_not_require\":\"new_thread_creation\"}");
    return 0;
}
