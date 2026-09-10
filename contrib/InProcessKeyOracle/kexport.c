/*
 * kexport.dll  --  in-process login-K oracle for shim3799.
 *
 * WHY: shim3799 needs the client's per-session login key K (M2 = HMAC-SHA256(K,"OK"))
 * to answer Ascension's custom auth. Today it reads K with cross-process
 * ReadProcessMemory (rpm_readk.py), which requires the shim to run at the SAME
 * integrity level as the client -- the "launch the shim yourself / elevation dance"
 * friction. FirstOni's AscensionAuthGate showed the clean alternative: read K from
 * INSIDE the client, where no OpenProcess/RPM and no integrity match is needed.
 *
 * This DLL is the minimal lift of just that idea. It does NOT touch auth, does NOT
 * patch anything, does NOT replace Extensions.dll. On load it starts a loopback TCP
 * server; on each connection it does one live pointer-chain read and returns the
 * 32-byte K (or 32 zero bytes if the client has not computed it yet). shim3799
 * connects to it right when it needs K, and falls back to RPM, then variant-guess,
 * if the oracle is not present -- so the shim remains a complete fallback.
 *
 * Pointer chain (identical in rpm_readk.py and AscensionAuthGate; same client build):
 *     objptr = *(u32*)(Extensions base + 0x00bdbc04)      // static .data slot
 *     K      = *(u8[32])(objptr + 0x120)                   // X25519 login key
 * The real DLL is named "Extensions.dll" normally, or "Extensions_orig.dll" when a
 * chain-loading proxy (AuthGate) renamed it; try both.
 *
 * Loaded via the existing dinput8 proxy (file-drop, no injector). Only usable in a
 * WRITABLE client copy -- never client-ascension (a junction into the live install).
 *
 * LOCAL PRESERVATION USE ONLY. 32-bit, static CRT (/MT); imports kernel32 + ws2_32.
 */
#include <winsock2.h>
#include <windows.h>

#define KX_PORT           37281          /* loopback oracle port (unused on this box) */
#define STATIC_OBJ_SLOT   0x00bdbc04u    /* Extensions base + this = &heapObjectPtr   */
#define OFF_LOGIN_K       0x120u         /* heapObject + this = 32-byte K              */

/* Read K in-process via the pointer chain. Returns 1 and fills K on success (K set,
 * non-zero); 0 if the module/object is not ready yet. Never writes client memory. */
static int read_login_k(unsigned char K[32])
{
    HMODULE eo;
    unsigned int slot, obj;
    int i, allzero;

    eo = GetModuleHandleA("Extensions.dll");
    if (!eo) eo = GetModuleHandleA("Extensions_orig.dll");
    if (!eo) return 0;

    /* Guard every dereference: the object is null until the client computes K. The
     * addresses are in-process and readable, but be defensive about the null slot. */
    slot = *(volatile unsigned int *)((BYTE *)eo + STATIC_OBJ_SLOT);
    if (!slot) return 0;
    obj = slot;

    for (i = 0; i < 32; i++) K[i] = *(volatile unsigned char *)((BYTE *)(obj + OFF_LOGIN_K) + i);

    allzero = 1;
    for (i = 0; i < 32; i++) if (K[i]) { allzero = 0; break; }
    return allzero ? 0 : 1;
}

static DWORD WINAPI oracle_thread(LPVOID unused)
{
    WSADATA wsa;
    SOCKET srv;
    struct sockaddr_in sa;
    int yes = 1;
    (void)unused;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0;
    srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv == INVALID_SOCKET) return 0;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));

    ZeroMemory(&sa, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(KX_PORT);
    sa.sin_addr.s_addr = htonl(0x7F000001);   /* 127.0.0.1 only */
    if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) != 0) { closesocket(srv); return 0; }
    if (listen(srv, 4) != 0) { closesocket(srv); return 0; }

    for (;;) {
        SOCKET c = accept(srv, NULL, NULL);
        unsigned char reply[33];
        if (c == INVALID_SOCKET) continue;
        /* reply[0] = status (1 = K present, 0 = not ready); reply[1:33] = K (zeros if not ready) */
        ZeroMemory(reply, sizeof(reply));
        reply[0] = (unsigned char)read_login_k(reply + 1);
        send(c, (const char *)reply, (int)sizeof(reply), 0);
        closesocket(c);
    }
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE h;
        DisableThreadLibraryCalls(hInst);
        h = CreateThread(NULL, 0, oracle_thread, NULL, 0, NULL);
        if (h) CloseHandle(h);
    }
    return TRUE;
}
