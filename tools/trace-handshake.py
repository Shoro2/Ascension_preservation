"""Dynamic trace of the Ascension login handshake - recover the M2/KDF formula.

Static analysis mapped every native libsodium primitive in Extensions.dll but
the orchestration that folds the shared secret K and the two ephemeral publics
into M1/M2 lives in the .vm_sec code virtualizer and cannot be read from the
file.  The only way to see the exact bytes that go into M2 is to watch the
running client compute it.  This does that with the Windows debug API and
hardware breakpoints (DR0-DR3): no code is patched, so a self-checksumming
protector sees an unmodified image, and we set exactly four execute breakpoints
on the SHA-256 / key-agreement leaf functions.

Why this is safe to run:
  * We trace against the LOCAL replay server (replay-auth.py), not the real
    Ascension auth server.  The client still reaches the M2-verify step - it was
    already proven to compute the expected M2 and only then reject the stale one
    - so the formula is fully observable with no live server and no ban risk.
  * We trace only the LOGIN-SCREEN handshake and never enter the world, so the
    world-side anti-tamper (the layer that crashed zone-in) never activates.
  * Hardware execute breakpoints modify no memory; first-chance exceptions that
    are not ours pass straight back to the app (DBG_EXCEPTION_NOT_HANDLED) so we
    never alter the client control flow.

Key insight: HMAC-SHA256 is built ON sha256_init/update/final, so breakpointing
the SHA-256 primitive layer captures HMAC inner and outer hashes too - they show
up as a 64-byte first block equal to key XOR 0x36 (ipad) / 0x5c (opad).  Thus
four breakpoints see the entire M1/M2 construction, HMAC or not.

Targets (RVA from imagebase 0x10000000; resolved to the live base at attach):
  KEYAGREE  0x00ADAFB0  crypto_box_beforenm(k_out, peer_pub, my_sec) -> K
  SHA_INIT  0x00ADBFC0  sha256_init(ctx)                 - delimits each hash
  SHA_W1    0x00ADC820  sha256 wrapper (update or oneshot) - the hashed bytes
  SHA_W2    0x00ADC940  sha256 wrapper (final or oneshot)  - the digest

Usage:
    # 1. start the offline replay server:  python replay-auth.py
    # 2. launch client, realmList 127.0.0.1:3799, sit at login, do NOT click yet
    python trace-handshake.py            # auto-find Ascension.exe and attach
    python trace-handshake.py --pid 1234 # attach by pid
    python trace-handshake.py --selftest # struct/size/address check, no attach
"""
import ctypes, ctypes.wintypes as wt, sys, os, time, struct

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
LOG_PATH   = os.path.join(BASE_DIR, "trace-handshake.log")
IMAGEBASE  = 0x10000000
MODULE     = "Extensions.dll"
PROC_NAME  = "Ascension.exe"

TARGETS = {
    0x00ADAFB0: "KEYAGREE",
    0x00ADBFC0: "SHA_INIT",
    0x00ADC820: "SHA_W1",
    0x00ADC940: "SHA_W2",
}

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

DWORD, HANDLE, BOOL, LPVOID = wt.DWORD, wt.HANDLE, wt.BOOL, wt.LPVOID
SIZE_T = ctypes.c_size_t

DBG_CONTINUE              = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

EXCEPTION_DEBUG_EVENT      = 1
CREATE_THREAD_DEBUG_EVENT  = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT    = 4
EXIT_PROCESS_DEBUG_EVENT   = 5
LOAD_DLL_DEBUG_EVENT       = 6

EXCEPTION_BREAKPOINT  = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004

CONTEXT_i386 = 0x00010000
CONTEXT_CONTROL = CONTEXT_i386 | 0x1
CONTEXT_INTEGER = CONTEXT_i386 | 0x2
CONTEXT_SEGMENTS = CONTEXT_i386 | 0x4
CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10
CONTEXT_FULLDBG = (CONTEXT_CONTROL | CONTEXT_INTEGER |
                   CONTEXT_SEGMENTS | CONTEXT_DEBUG_REGISTERS)

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
TH32CS_SNAPMODULE   = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
TH32CS_SNAPTHREAD   = 0x00000004
THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010


class FLOATING_SAVE_AREA(ctypes.Structure):
    _fields_ = [("ControlWord", DWORD), ("StatusWord", DWORD),
                ("TagWord", DWORD), ("ErrorOffset", DWORD),
                ("ErrorSelector", DWORD), ("DataOffset", DWORD),
                ("DataSelector", DWORD), ("RegisterArea", ctypes.c_byte * 80),
                ("Cr0NpxState", DWORD)]


class WOW64_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", DWORD),
        ("Dr0", DWORD), ("Dr1", DWORD), ("Dr2", DWORD), ("Dr3", DWORD),
        ("Dr6", DWORD), ("Dr7", DWORD),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", DWORD), ("SegFs", DWORD), ("SegEs", DWORD), ("SegDs", DWORD),
        ("Edi", DWORD), ("Esi", DWORD), ("Ebx", DWORD), ("Edx", DWORD),
        ("Ecx", DWORD), ("Eax", DWORD),
        ("Ebp", DWORD), ("Eip", DWORD), ("SegCs", DWORD), ("EFlags", DWORD),
        ("Esp", DWORD), ("SegSs", DWORD),
        ("ExtendedRegisters", ctypes.c_byte * 512),
    ]


class _EVUNION(ctypes.Union):
    _fields_ = [("raw", ctypes.c_byte * 168), ("_align", ctypes.c_void_p)]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [("dwDebugEventCode", DWORD),
                ("dwProcessId", DWORD),
                ("dwThreadId", DWORD),
                ("u", _EVUNION)]


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", DWORD), ("th32ModuleID", DWORD),
                ("th32ProcessID", DWORD), ("GlblcntUsage", DWORD),
                ("ProccntUsage", DWORD), ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", DWORD), ("hModule", ctypes.c_void_p),
                ("szModule", ctypes.c_char * 256),
                ("szExePath", ctypes.c_char * 260)]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", DWORD), ("cntUsage", DWORD),
                ("th32ThreadID", DWORD), ("th32OwnerProcessID", DWORD),
                ("tpBasePri", ctypes.c_long), ("tpDeltaPri", ctypes.c_long),
                ("dwFlags", DWORD)]


for fn, argt, rest in [
    ("DebugActiveProcess", [DWORD], BOOL),
    ("DebugActiveProcessStop", [DWORD], BOOL),
    ("DebugSetProcessKillOnExit", [BOOL], BOOL),
    ("WaitForDebugEvent", [ctypes.POINTER(DEBUG_EVENT), DWORD], BOOL),
    ("ContinueDebugEvent", [DWORD, DWORD, DWORD], BOOL),
    ("Wow64GetThreadContext", [HANDLE, ctypes.POINTER(WOW64_CONTEXT)], BOOL),
    ("Wow64SetThreadContext", [HANDLE, ctypes.POINTER(WOW64_CONTEXT)], BOOL),
    ("OpenProcess", [DWORD, BOOL, DWORD], HANDLE),
    ("OpenThread", [DWORD, BOOL, DWORD], HANDLE),
    ("CloseHandle", [HANDLE], BOOL),
    ("ReadProcessMemory",
     [HANDLE, LPVOID, LPVOID, SIZE_T, ctypes.POINTER(SIZE_T)], BOOL),
    ("CreateToolhelp32Snapshot", [DWORD, DWORD], HANDLE),
    ("Module32First", [HANDLE, ctypes.POINTER(MODULEENTRY32)], BOOL),
    ("Module32Next", [HANDLE, ctypes.POINTER(MODULEENTRY32)], BOOL),
    ("Thread32First", [HANDLE, ctypes.POINTER(THREADENTRY32)], BOOL),
    ("Thread32Next", [HANDLE, ctypes.POINTER(THREADENTRY32)], BOOL),
]:
    f = getattr(k32, fn); f.argtypes = argt; f.restype = rest


_logf = None
def log(msg):
    global _logf
    line = "%s  %s" % (time.strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    if _logf is None:
        _logf = open(LOG_PATH, "a", encoding="utf8")
    _logf.write(line + "\n"); _logf.flush()


def hexs(b):
    return " ".join("%02X" % x for x in b)


def find_pid(name):
    TH32CS_SNAPPROCESS = 0x2
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [("dwSize", DWORD), ("cntUsage", DWORD),
                    ("th32ProcessID", DWORD), ("th32DefaultHeapID", ctypes.c_void_p),
                    ("th32ModuleID", DWORD), ("cntThreads", DWORD),
                    ("th32ParentProcessID", DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", DWORD), ("szExeFile", ctypes.c_char * 260)]
    k32.Process32First.argtypes = [HANDLE, ctypes.POINTER(PROCESSENTRY32)]
    k32.Process32First.restype = BOOL
    k32.Process32Next.argtypes = [HANDLE, ctypes.POINTER(PROCESSENTRY32)]
    k32.Process32Next.restype = BOOL
    pe = PROCESSENTRY32(); pe.dwSize = ctypes.sizeof(pe)
    hits = []
    ok = k32.Process32First(snap, ctypes.byref(pe))
    while ok:
        if pe.szExeFile.decode(errors="replace").lower() == name.lower():
            hits.append(pe.th32ProcessID)
        ok = k32.Process32Next(snap, ctypes.byref(pe))
    k32.CloseHandle(snap)
    return hits


def module_base(pid, modname):
    snap = k32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    me = MODULEENTRY32(); me.dwSize = ctypes.sizeof(me)
    base = None
    ok = k32.Module32First(snap, ctypes.byref(me))
    while ok:
        if me.szModule.decode(errors="replace").lower() == modname.lower():
            base = me.modBaseAddr; break
        ok = k32.Module32Next(snap, ctypes.byref(me))
    k32.CloseHandle(snap)
    return base


def enum_threads(pid):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    te = THREADENTRY32(); te.dwSize = ctypes.sizeof(te)
    out = []
    ok = k32.Thread32First(snap, ctypes.byref(te))
    while ok:
        if te.th32OwnerProcessID == pid:
            out.append(te.th32ThreadID)
        ok = k32.Thread32Next(snap, ctypes.byref(te))
    k32.CloseHandle(snap)
    return out


class Tracer:
    def __init__(self, pid):
        self.pid = pid
        self.hproc = k32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not self.hproc:
            raise OSError("OpenProcess failed: %d" % ctypes.get_last_error())
        self.base = None
        self.addrs = {}
        self.thread_h = {}
        self.k_out_ptrs = []
        self.hits = 0
        self.last_hit = None
        self.armed = False

    def read(self, addr, n):
        if not addr or n <= 0:
            return b""
        buf = (ctypes.c_char * n)()
        got = SIZE_T(0)
        ok = k32.ReadProcessMemory(self.hproc, ctypes.c_void_p(addr),
                                   buf, n, ctypes.byref(got))
        return bytes(buf[:got.value]) if ok else b""

    def u32(self, addr):
        b = self.read(addr, 4)
        return struct.unpack("<I", b)[0] if len(b) == 4 else 0

    def _thandle(self, tid):
        h = self.thread_h.get(tid)
        if h:
            return h
        h = k32.OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, False, tid)
        if h:
            self.thread_h[tid] = h
        return h

    def arm_thread(self, tid, hthread=None):
        h = hthread or self._thandle(tid)
        if not h:
            return False
        ctx = WOW64_CONTEXT(); ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
        if not k32.Wow64GetThreadContext(h, ctypes.byref(ctx)):
            return False
        slots = list(self.addrs.keys())
        for i in range(4):
            setattr(ctx, "Dr%d" % i, slots[i] if i < len(slots) else 0)
        dr7 = 0
        for i in range(min(4, len(slots))):
            dr7 |= (1 << (2 * i))
        ctx.Dr7 = dr7; ctx.Dr6 = 0
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
        return bool(k32.Wow64SetThreadContext(h, ctypes.byref(ctx)))

    def disarm_thread(self, tid):
        h = self._thandle(tid)
        if not h:
            return
        ctx = WOW64_CONTEXT(); ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
        if k32.Wow64GetThreadContext(h, ctypes.byref(ctx)):
            ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0
            ctx.Dr7 = 0; ctx.Dr6 = 0
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
            k32.Wow64SetThreadContext(h, ctypes.byref(ctx))

    def arm_all(self):
        n = 0
        for tid in enum_threads(self.pid):
            if self.arm_thread(tid):
                n += 1
        return n

    def dump_call(self, name, ctx):
        esp = ctx.Esp
        a = [self.u32(esp + 4 + 4 * i) for i in range(4)]
        ret = self.u32(esp)
        log("  HIT %-8s eip=%08X ret=%08X args=[%08X %08X %08X %08X]"
            % (name, ctx.Eip, ret, a[0], a[1], a[2], a[3]))
        if name == "KEYAGREE":
            log("      peer_pub = %s" % hexs(self.read(a[1], 32)))
            log("      my_sec   = %s" % hexs(self.read(a[2], 32)))
            self.k_out_ptrs.append(("K@%08X" % ret, a[0]))
        elif name == "SHA_INIT":
            log("      ctx=%08X  (hash start)" % a[0])
        else:
            for idx, v in enumerate(a):
                if 0x10000 <= v <= 0x7FFFFFFF:
                    blob = self.read(v, 96)
                    if blob:
                        log("      arg%d=%08X -> %s%s" %
                            (idx, v, hexs(blob[:64]),
                             " ..." if len(blob) > 64 else ""))
                else:
                    log("      arg%d=%08X (int? maybe len)" % (idx, v))
            for lp, dp in ((a[2], a[1]), (a[3], a[2]), (a[1], a[0])):
                if 1 <= lp <= 4096:
                    log("      len=%d -> data=%s" % (lp, hexs(self.read(dp, lp))))
                    break

    def run(self, quiet_secs=8.0, max_secs=180.0):
        if not k32.DebugActiveProcess(self.pid):
            raise OSError("DebugActiveProcess failed: %d (run as admin?)"
                          % ctypes.get_last_error())
        k32.DebugSetProcessKillOnExit(False)
        log("attached to pid %d" % self.pid)
        start = time.time()
        ev = DEBUG_EVENT()
        try:
            while True:
                if not k32.WaitForDebugEvent(ctypes.byref(ev), 200):
                    if self.armed and self.last_hit and \
                            time.time() - self.last_hit > quiet_secs:
                        log("quiet for %.0fs after %d hits - finishing"
                            % (quiet_secs, self.hits)); break
                    if time.time() - start > max_secs:
                        log("max %.0fs elapsed - finishing" % max_secs); break
                    continue
                code = ev.dwDebugEventCode
                tid = ev.dwThreadId
                status = DBG_CONTINUE
                uaddr = ctypes.addressof(ev) + DEBUG_EVENT.u.offset

                if code == CREATE_PROCESS_DEBUG_EVENT:
                    hthread = ctypes.c_void_p.from_address(uaddr + 16).value
                    if self.base is None:
                        self.base = module_base(self.pid, MODULE)
                        if self.base:
                            self.addrs = {self.base + rva: nm
                                          for rva, nm in TARGETS.items()}
                            log("%s base = %08X" % (MODULE, self.base))
                            for ad, nm in sorted(self.addrs.items()):
                                log("   BP %-8s @ %08X" % (nm, ad))
                    if hthread:
                        self.thread_h[tid] = hthread
                        self.arm_thread(tid, hthread)
                elif code == CREATE_THREAD_DEBUG_EVENT:
                    hthread = ctypes.c_void_p.from_address(uaddr + 0).value
                    if hthread:
                        self.thread_h[tid] = hthread
                    if self.addrs:
                        self.arm_thread(tid, hthread)
                elif code == EXIT_THREAD_DEBUG_EVENT:
                    self.thread_h.pop(tid, None)
                elif code == EXCEPTION_DEBUG_EVENT:
                    ecode = ctypes.c_uint32.from_address(uaddr + 0).value
                    if ecode == EXCEPTION_BREAKPOINT and not self.armed:
                        if self.base is None:
                            self.base = module_base(self.pid, MODULE)
                            self.addrs = {self.base + rva: nm
                                          for rva, nm in TARGETS.items()}
                            log("%s base = %08X" % (MODULE, self.base))
                        n = self.arm_all(); self.armed = True
                        log("ARMED %d threads on %d breakpoints" % (n, len(self.addrs)))
                        log(">>> now click Login in the client <<<")
                    elif ecode == EXCEPTION_SINGLE_STEP:
                        h = self._thandle(tid)
                        ctx = WOW64_CONTEXT(); ctx.ContextFlags = CONTEXT_FULLDBG
                        if h and k32.Wow64GetThreadContext(h, ctypes.byref(ctx)):
                            name = self.addrs.get(ctx.Eip)
                            if name:
                                self.hits += 1; self.last_hit = time.time()
                                self.dump_call(name, ctx)
                                ctx.EFlags |= 0x10000; ctx.Dr6 = 0
                                ctx.ContextFlags = CONTEXT_FULLDBG
                                k32.Wow64SetThreadContext(h, ctypes.byref(ctx))
                            else:
                                status = DBG_EXCEPTION_NOT_HANDLED
                        else:
                            status = DBG_EXCEPTION_NOT_HANDLED
                    else:
                        status = DBG_EXCEPTION_NOT_HANDLED
                elif code == EXIT_PROCESS_DEBUG_EVENT:
                    log("target exited"); break

                k32.ContinueDebugEvent(ev.dwProcessId, tid, status)
        finally:
            self.finish()

    def finish(self):
        for label, ptr in self.k_out_ptrs:
            log("  %s -> K = %s" % (label, hexs(self.read(ptr, 32))))
        for tid in list(self.thread_h):
            self.disarm_thread(tid)
        try:
            k32.DebugActiveProcessStop(self.pid)
            log("detached from pid %d (client left running)" % self.pid)
        except Exception:
            pass
        log("=== %d breakpoint hits captured -> %s ===" % (self.hits, LOG_PATH))


def selftest():
    assert ctypes.sizeof(WOW64_CONTEXT) == 716, ctypes.sizeof(WOW64_CONTEXT)
    assert DEBUG_EVENT.u.offset == 16, DEBUG_EVENT.u.offset
    assert hasattr(k32, "Wow64GetThreadContext")
    print("WOW64_CONTEXT size :", ctypes.sizeof(WOW64_CONTEXT), "(ok)")
    print("DEBUG_EVENT union  : offset", DEBUG_EVENT.u.offset, "(ok)")
    print("MODULEENTRY32 size :", ctypes.sizeof(MODULEENTRY32))
    fake = 0x6E480000
    print("if base=%08X the breakpoints would be:" % fake)
    for rva, nm in sorted(TARGETS.items()):
        print("   %-8s rva %08X -> %08X" % (nm, rva, fake + rva))
    pids = find_pid(PROC_NAME)
    print("running %s pids:" % PROC_NAME, pids or "(none)")
    if pids:
        b = module_base(pids[0], MODULE)
        print("live %s base:" % MODULE, ("%08X" % b) if b else "(not found)")
    print("selftest OK")


def main():
    args = sys.argv[1:]
    if "--selftest" in args:
        selftest(); return
    pid = None
    if "--pid" in args:
        pid = int(args[args.index("--pid") + 1])
    if pid is None:
        pids = find_pid(PROC_NAME)
        if not pids:
            print("no %s process found - launch the client to the login screen first"
                  % PROC_NAME); return
        if len(pids) > 1:
            print("multiple %s pids %s - pass --pid" % (PROC_NAME, pids)); return
        pid = pids[0]
    log("=== trace-handshake start, target pid %d ===" % pid)
    Tracer(pid).run()


if __name__ == "__main__":
    main()
