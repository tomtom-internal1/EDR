#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "poc_common.h"

typedef struct {
    DWORD count;
    DWORD callback_tid;
    DWORD target_pid;
    BOOL saw_target;
} ENUM_CTX;

static const wchar_t *CLASS_NAME = L"Evasion1A03HiddenClass";

static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(wp);
    UNREFERENCED_PARAMETER(lp);
    if (msg == WM_CLOSE) DestroyWindow(hwnd);
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static BOOL CALLBACK enum_windows_cb(HWND hwnd, LPARAM parameter)
{
    ENUM_CTX *ctx = (ENUM_CTX *)parameter;
    DWORD owner_pid = 0;
    DWORD owner_tid = GetWindowThreadProcessId(hwnd, &owner_pid);
    (void)owner_tid;

    ++ctx->count;
    if (ctx->callback_tid == 0)
        ctx->callback_tid = GetCurrentThreadId();

    if (owner_pid == ctx->target_pid) {
        ctx->saw_target = TRUE;

        char d[384];
        snprintf(d, sizeof(d),
                 "{\"hwnd\":\"0x%p\",\"callback_tid\":%lu,"
                 "\"owner_pid\":%lu,\"target_pid\":%lu,"
                 "\"target_window_seen\":true}",
                 (void *)hwnd,
                 (unsigned long)GetCurrentThreadId(),
                 (unsigned long)owner_pid,
                 (unsigned long)ctx->target_pid);
        adv_emit("A03_ENUMWINDOWS_CALLBACK", 2,
                 "EnumerationCallback", "CALLBACK_BASED_EXECUTION", d);

        return FALSE;
    }

    return TRUE;
}

int main(void)
{
    const char *id = "A03_ENUMWINDOWS_CALLBACK";

    HINSTANCE instance = GetModuleHandleW(NULL);
    WNDCLASSW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = instance;
    wc.lpszClassName = CLASS_NAME;

    if (!RegisterClassW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        adv_error(id, 1, "CALLBACK_BASED_EXECUTION", "RegisterClassW");
        return 1;
    }

    HWND target = CreateWindowExW(
        0, CLASS_NAME, L"EDDRR Evasion1 A03 Target",
        WS_OVERLAPPEDWINDOW,
        0, 0, 100, 100,
        NULL, NULL, instance, NULL);

    if (!target) {
        adv_error(id, 1, "CALLBACK_BASED_EXECUTION", "CreateWindowExW");
        return 1;
    }

    ShowWindow(target, SW_HIDE);
    UpdateWindow(target);

    ENUM_CTX ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.target_pid = GetCurrentProcessId();

    char d[384];
    snprintf(d, sizeof(d),
             "{\"api\":\"EnumWindows\",\"target_hwnd\":\"0x%p\","
             "\"target_pid\":%lu,\"application_created_thread\":false}",
             (void *)target, (unsigned long)ctx.target_pid);
    adv_emit(id, 1, "EnumerationStart", "CALLBACK_BASED_EXECUTION", d);

    BOOL ok = EnumWindows(enum_windows_cb, (LPARAM)&ctx);

    snprintf(d, sizeof(d),
             "{\"enumwindows_result\":%s,\"callbacks_seen\":%lu,"
             "\"callback_tid\":%lu,\"target_window_seen\":%s,"
             "\"caller_tid\":%lu}",
             ok ? "true" : "false",
             (unsigned long)ctx.count,
             (unsigned long)ctx.callback_tid,
             ctx.saw_target ? "true" : "false",
             (unsigned long)GetCurrentThreadId());
    adv_emit(id, 3, "EnumerationResult", "CALLBACK_BASED_EXECUTION", d);

    DestroyWindow(target);
    UnregisterClassW(CLASS_NAME, instance);

    adv_emit(id, 4, "DetectionOracle", "CALLBACK_BASED_EXECUTION",
             "{\"expected_detection\":\"execution_through_callback_surface\","
             "\"correlate\":[\"EnumerationStart\",\"EnumerationCallback\",\"EnumerationResult\"],"
             "\"do_not_require\":\"new_thread_creation\"}");
    return 0;
}
