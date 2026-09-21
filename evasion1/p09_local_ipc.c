#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include "poc_common.h"

static const wchar_t *PIPE_NAME = L"\\.\pipe\EDDRR-Evasion1-P09";

int main(void)
{
    const char *poc = "P09_LOCAL_IPC";

    HANDLE pipe = CreateNamedPipeW(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 512, 512, 0, NULL);

    if (pipe == INVALID_HANDLE_VALUE) {
        poc_emit_error(poc, 1, "LOCAL_IPC", "CreateNamedPipeW");
        return 1;
    }

    poc_emit(poc, 1, "NamedPipeCreate", "LOCAL_IPC",
             "{\"object\":\"\\\\.\\pipe\\EDDRR-Evasion1-P09\",\"scope\":\"local\",\"network_event_expected\":false}");

    HANDLE client = CreateFileW(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (client == INVALID_HANDLE_VALUE) {
        poc_emit_error(poc, 2, "LOCAL_IPC", "CreateFileW(pipe)");
        CloseHandle(pipe);
        return 1;
    }

    const char message[] = "EDDRR-P09-LOCAL-IPC";
    DWORD written = 0;
    WriteFile(client, message, (DWORD)sizeof(message), &written, NULL);

    BOOL connected = ConnectNamedPipe(pipe, NULL);
    DWORD connect_error = connected ? ERROR_SUCCESS : GetLastError();
    UNREFERENCED_PARAMETER(connect_error);

    char received[64] = {0};
    DWORD read = 0;
    ReadFile(pipe, received, sizeof(received) - 1, &read, NULL);

    poc_emit(poc, 2, "NamedPipeTransfer", "LOCAL_IPC",
             "{\"transport\":\"named_pipe\",\"scope\":\"same_host\",\"payload\":\"benign_marker\"}");

    CloseHandle(client);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);

    HKEY key = NULL;
    LONG rc = RegCreateKeyExW(HKEY_CURRENT_USER,
                              L"Software\\EDDRR\\Evasion1\\P09",
                              0, NULL, 0, KEY_READ | KEY_WRITE, NULL,
                              &key, NULL);
    if (rc != ERROR_SUCCESS) {
        poc_emit_error(poc, 3, "LOCAL_IPC", "RegCreateKeyExW");
        return 1;
    }

    const wchar_t value[] = L"EDDRR-P09-REGISTRY-IPC";
    RegSetValueExW(key, L"Message", 0, REG_SZ,
                   (const BYTE *)value, (DWORD)((wcslen(value) + 1) * sizeof(wchar_t)));

    wchar_t read_value[64] = {0};
    DWORD type = 0;
    DWORD cb = sizeof(read_value);
    RegQueryValueExW(key, L"Message", NULL, &type, (BYTE *)read_value, &cb);
    RegCloseKey(key);

    HKEY cleanup = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\EDDRR\\Evasion1\\P09",
                      0, KEY_WRITE, &cleanup) == ERROR_SUCCESS) {
        RegDeleteValueW(cleanup, L"Message");
        RegCloseKey(cleanup);
    }

    HKEY parent = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\EDDRR\\Evasion1",
                      0, KEY_WRITE, &parent) == ERROR_SUCCESS) {
        RegDeleteKeyW(parent, L"P09");
        RegCloseKey(parent);
    }

    poc_emit(poc, 3, "RegistryIpc", "LOCAL_IPC",
             "{\"operation\":\"HKCU_value_roundtrip\",\"scope\":\"same_host\",\"cleanup\":true}");

    return 0;
}
