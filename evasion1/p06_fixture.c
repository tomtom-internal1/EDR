#include <windows.h>

__declspec(dllexport) const char *Evasion1FixtureMarker(void)
{
    return "EDDRR-EVASION1-BENIGN-FIXTURE";
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)hinst;
    (void)reason;
    (void)reserved;
    return TRUE;
}
