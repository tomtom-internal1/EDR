#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <amsi.h>
#include <stdio.h>
#include <string.h>
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Amsi.lib")
#include "poc_common.h"

static int sha256(const BYTE *data, ULONG len, BYTE out[32])
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    PUCHAR object = NULL;
    ULONG object_len = 0, cb = 0;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (st < 0) return 0;

    st = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                           (PUCHAR)&object_len, sizeof(object_len), &cb, 0);
    if (st < 0) goto fail;

    object = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, object_len);
    if (!object) goto fail;

    st = BCryptCreateHash(alg, &hash, object, object_len, NULL, 0, 0);
    if (st < 0) goto fail;

    st = BCryptHashData(hash, (PUCHAR)data, len, 0);
    if (st < 0) goto fail;

    st = BCryptFinishHash(hash, out, 32, 0);
    if (st < 0) goto fail;

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    HeapFree(GetProcessHeap(), 0, object);
    return 1;

fail:
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    if (object) HeapFree(GetProcessHeap(), 0, object);
    return 0;
}

static void hex32(const BYTE h[32], char out[65])
{
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        out[i * 2] = hex[h[i] >> 4];
        out[i * 2 + 1] = hex[h[i] & 0x0f];
    }
    out[64] = '\0';
}

int main(void)
{
    const char *id = "A11_AMSI_INTEGRITY";
    HMODULE live = GetModuleHandleW(L"amsi.dll");
    if (!live)
        live = LoadLibraryW(L"amsi.dll");

    if (!live) {
        adv_error(id, 1, "AMSI_CODE_INTEGRITY", "LoadLibraryW");
        return 1;
    }

    FARPROC live_scan = GetProcAddress(live, "AmsiScanBuffer");
    if (!live_scan) {
        adv_error(id, 1, "AMSI_CODE_INTEGRITY", "GetProcAddress-live");
        return 1;
    }

    WCHAR system_dir[MAX_PATH];
    UINT n = GetSystemDirectoryW(system_dir, MAX_PATH);
    if (!n || n >= MAX_PATH) {
        adv_error(id, 1, "AMSI_CODE_INTEGRITY", "GetSystemDirectoryW");
        return 1;
    }

    WCHAR amsi_path[MAX_PATH];
    _snwprintf_s(amsi_path, MAX_PATH, _TRUNCATE,
                 L"%s\\amsi.dll", system_dir);

    HMODULE disk_image = LoadLibraryExW(
        amsi_path, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!disk_image) {
        adv_error(id, 2, "AMSI_CODE_INTEGRITY", "LoadLibraryExW-DONT_RESOLVE");
        return 1;
    }

    FARPROC disk_scan = GetProcAddress(disk_image, "AmsiScanBuffer");
    if (!disk_scan) {
        adv_error(id, 2, "AMSI_CODE_INTEGRITY", "GetProcAddress-disk-image");
        FreeLibrary(disk_image);
        return 1;
    }

    MEMORY_BASIC_INFORMATION live_mbi;
    ZeroMemory(&live_mbi, sizeof(live_mbi));
    VirtualQuery((const void *)live_scan, &live_mbi, sizeof(live_mbi));

    const SIZE_T compare_len = 64;
    BYTE live_bytes[64];
    BYTE disk_bytes[64];
    memcpy(live_bytes, (const void *)live_scan, compare_len);
    memcpy(disk_bytes, (const void *)disk_scan, compare_len);

    BYTE live_hash[32], disk_hash[32];
    if (!sha256(live_bytes, (ULONG)compare_len, live_hash) ||
        !sha256(disk_bytes, (ULONG)compare_len, disk_hash)) {
        adv_error(id, 3, "AMSI_CODE_INTEGRITY", "BCrypt-SHA256");
        FreeLibrary(disk_image);
        return 1;
    }

    char live_hex[65], disk_hex[65];
    hex32(live_hash, live_hex);
    hex32(disk_hash, disk_hex);

    char d[768];
    snprintf(d, sizeof(d),
             "{\"function\":\"AmsiScanBuffer\",\"bytes_compared\":%llu,"
             "\"live_address\":\"%p\",\"disk_image_address\":\"%p\","
             "\"live_sha256\":\"%s\",\"disk_image_sha256\":\"%s\","
             "\"equal\":%s}",
             (unsigned long long)compare_len,
             (void *)live_scan, (void *)disk_scan,
             live_hex, disk_hex,
             memcmp(live_bytes, disk_bytes, compare_len) == 0 ? "true" : "false");

    adv_emit(id, 1, "AmsiCodeIntegrity", "AMSI_CODE_INTEGRITY", d);\n\n    snprintf(d, sizeof(d),\n             "{\\"live_page_base\\":\\"%p\\",\\"live_region_state\\":%lu,\\"live_page_protect\\":%lu,"\n             "\\"page_is_writable\\":%s,\"page_is_executable\\":%s}",\n             live_mbi.BaseAddress, (unsigned long)live_mbi.State,\n             (unsigned long)live_mbi.Protect,\n             (live_mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) ? "true" : "false",\n             (live_mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) ? "true" : "false");\n    adv_emit(id, 2, "AmsiCodePageState", "AMSI_CODE_INTEGRITY", d);

    BOOL signature_bytes_same =
        memcmp(live_bytes, disk_bytes, compare_len) == 0;

    adv_emit(id, 3, "DetectionOracle", "AMSI_CODE_INTEGRITY",
             signature_bytes_same ?
             "{\"state\":\"LIVE_BYTES_MATCH_DISK_IMAGE\","
             "\"interpretation\":\"no_code_difference_detected\","
             "\"confidence\":\"baseline_only\"}" :
             "{\"state\":\"LIVE_BYTES_DIFFER_FROM_DISK_IMAGE\","
             "\"interpretation\":\"integrity_anomaly\","
             "\"action\":\"investigate_AMSI_tamper_or_instrumentation\","
             "\"not_proof_of_specific_bypass\":true}");

    FreeLibrary(disk_image);
    return 0;
}
