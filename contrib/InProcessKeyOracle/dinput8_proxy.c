/*
 * dinput8.dll proxy / side-loader -- gets kexport.dll into the client with no injector.
 *
 * Ascension.exe statically imports DINPUT8.dll!DirectInput8Create by name from its own
 * folder, and dinput8.dll is NOT a KnownDLL, so a copy dropped next to the exe loads
 * before the real System32 one. This proxy:
 *   1. forwards all 6 real dinput8 exports to "dinput8_orig.dll" (the user's own renamed
 *      copy of %WINDIR%\SysWOW64\dinput8.dll -- no Microsoft binary is shipped);
 *   2. on load, LoadLibrary()s kexport.dll from its OWN directory. kexport then serves the
 *      in-process login-K oracle on 127.0.0.1:37281 (see kexport.c). If kexport.dll is not
 *      present, this is a silent no-op and DirectInput still works.
 *
 * Pure file-drop. No process injection, no memory patching, never touches Extensions.dll or
 * Ascension.exe on disk. 32-bit, static CRT (/MT); imports kernel32 only.
 *
 * LOCAL PRESERVATION USE ONLY. Deploy only in a WRITABLE client copy.
 */
#include <windows.h>

#pragma comment(linker, "/export:DirectInput8Create=dinput8_orig.DirectInput8Create,@1")
#pragma comment(linker, "/export:DllCanUnloadNow=dinput8_orig.DllCanUnloadNow,@2,PRIVATE")
#pragma comment(linker, "/export:DllGetClassObject=dinput8_orig.DllGetClassObject,@3,PRIVATE")
#pragma comment(linker, "/export:DllRegisterServer=dinput8_orig.DllRegisterServer,@4,PRIVATE")
#pragma comment(linker, "/export:DllUnregisterServer=dinput8_orig.DllUnregisterServer,@5,PRIVATE")
#pragma comment(linker, "/export:GetdfDIJoystick=dinput8_orig.GetdfDIJoystick,@6")

#define ORACLE_NAME "kexport.dll"

static DWORD WINAPI loader_thread(LPVOID param)
{
    HMODULE self = (HMODULE)param;
    char path[MAX_PATH];
    DWORD n = GetModuleFileNameA(self, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return 0;
    /* strip our own filename, keep trailing separator -> directory of this DLL */
    while (n > 0 && path[n - 1] != '\\' && path[n - 1] != '/')
        n--;
    if (n + sizeof(ORACLE_NAME) <= MAX_PATH) {
        lstrcpynA(path + n, ORACLE_NAME, (int)(MAX_PATH - n));
        LoadLibraryA(path); /* kexport acts on its DllMain; nothing to call afterwards */
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE h;
        DisableThreadLibraryCalls(hInst);
        h = CreateThread(NULL, 0, loader_thread, (LPVOID)hInst, 0, NULL);
        if (h)
            CloseHandle(h);
    }
    return TRUE;
}
