"""Passive diagnostic: did the client actually decrypt+parse our SMSG_AUTH_RESPONSE?

READ-ONLY (OpenProcess VM_READ + ReadProcessMemory + VirtualQueryEx only). No writes,
no patching, no debugger, no watchdog interaction.

The world-net object's constructor (Ascension.exe VA 0x4650e0) stamps its vtable pointer:
    mov dword ptr [esi], 0x9e8258
and the SMSG_AUTH_RESPONSE handler (VA 0x464640) sets, on AUTH_OK (0x0C):
    mov byte ptr [esi+0x2f18], 1
    ... then reads the stock billing block into:
      +0x2f24 u32 billingTimeRemaining
      +0x2f2c u8  billingPlanFlags
      +0x2f28 u32 billingTimeRested
      +0x2f2d u8  expansion
    queue path (AUTH_WAIT_QUEUE 0x1B) sets +0x2f1c u32 queuePos, +0x2f20 u8 hasFreeChar.

So: find every committed dword == 0x009e8258, treat each as an object base, and read the
state fields. If +0x2f18 == 1 the client DECRYPTED and PARSED our AUTH_OK (crypt is fine,
handler ran) and the block is downstream. If no object has the flag set, the client never
processed the packet (framing/crypt out of sync).
"""
import ctypes, os, sys, time
from ctypes import wintypes as w

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
import rpm_readk as R

LOG = os.path.join(BASE, "scan_world_obj_log.txt")
VTABLE = 0x009e8258
VTABLE_LE = VTABLE.to_bytes(4, "little")

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", w.DWORD), ("RegionSize", ctypes.c_size_t),
                ("State", w.DWORD), ("Protect", w.DWORD), ("Type", w.DWORD)]


def log(msg):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def regions(h):
    addr = 0
    mbi = MBI()
    while addr < 0x7fff0000:
        r = k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi),
                               ctypes.sizeof(mbi))
        if not r:
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize or 0
        if (mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_GUARD)
                and not (mbi.Protect & PAGE_NOACCESS)):
            yield base, size, mbi.Type, mbi.Protect
        addr = base + size
        if size == 0:
            break


def rd(h, addr, n):
    return R._read(h, addr, n)


def u32(h, addr):
    b = rd(h, addr, 4)
    return int.from_bytes(b, "little") if b else None


def u8(h, addr):
    b = rd(h, addr, 1)
    return b[0] if b else None


def main():
    open(LOG, "w").close()
    log("=" * 70)
    log("world-object state scan (vtable 0x%08x, flag +0x2f18)" % VTABLE)
    pids = R.find_pids()
    log("Ascension.exe PIDs: %s" % pids)
    if not pids:
        log("no client running"); return
    pid = pids[0]
    h = R._open(pid)
    if not h:
        log("OpenProcess failed (need elevation?)"); return
    try:
        # --- self-check: is enumeration sound? ---------------------------------
        rk = R.read_k_for_pid(pid)
        login_obj = rk[1] if rk else 0
        log("self-check: login-auth objptr = 0x%x (Extensions.dll+0xbdbc04)" % login_obj)
        reg = list(regions(h))
        lo = min((b for b, s, t, p in reg), default=0)
        hi = max((b + s for b, s, t, p in reg), default=0)
        covered = any(b <= login_obj < b + s for b, s, t, p in reg)
        log("self-check: %d committed regions, span 0x%x..0x%x, login-obj covered=%s"
            % (len(reg), lo, hi, covered))
        # sanity: the vtable value MUST appear at least once in the image (.rdata/.data)
        img_hits = 0
        for b, s, t, p in reg:
            if t != MEM_IMAGE:
                continue
            blk = rd(h, b, min(s, 0x400000))
            if blk:
                img_hits += blk.count(VTABLE_LE)
        log("self-check: vtable 0x%08x appears %d time(s) in IMAGE regions (want >=1)"
            % (VTABLE, img_hits))

        cands = []
        scanned = 0
        CHUNK = 0x100000  # 1 MB; read tolerantly so one guard page can't skip a whole region
        for base, size, typ, prot in regions(h):
            # heap objects live in PRIVATE (or sometimes mapped) regions
            if typ == MEM_IMAGE:
                continue
            off = 0
            while off < size:
                n = min(CHUNK, size - off)
                blk = rd(h, base + off, n)
                if blk is None:
                    # shrink: try page-sized reads so guard pages don't nuke the chunk
                    p = 0
                    while p < n:
                        pg = rd(h, base + off + p, min(0x1000, n - p))
                        if pg:
                            scanned += len(pg)
                            s = 0
                            while True:
                                i = pg.find(VTABLE_LE, s)
                                if i == -1:
                                    break
                                a = base + off + p + i
                                if a % 4 == 0:
                                    cands.append(a)
                                s = i + 4
                        p += 0x1000
                    off += n
                    continue
                scanned += len(blk)
                s = 0
                while True:
                    i = blk.find(VTABLE_LE, s)
                    if i == -1:
                        break
                    a = base + off + i
                    if a % 4 == 0:
                        cands.append(a)
                    s = i + 4
                off += n
        log("scanned %.1f MB of private/mapped memory; %d aligned vtable-ptr candidates"
            % (scanned / 1e6, len(cands)))
        real = []
        for obj in cands:
            parent = u32(h, obj + 0x2ee0)
            flag = u8(h, obj + 0x2f18)
            if parent is None or flag is None:
                continue
            # a real object: parent is a plausible heap/data pointer
            plausible = parent is not None and 0x00010000 < parent < 0x7fff0000
            log("  obj=0x%08x  parent=0x%08x %s  +2f18(authok)=%s"
                % (obj, parent, "(plausible)" if plausible else "", flag))
            if plausible:
                real.append(obj)
        log("-" * 70)
        for obj in real:
            f2f0c = u32(h, obj + 0x2f0c)
            f2f10 = u32(h, obj + 0x2f10)
            f2f14 = u32(h, obj + 0x2f14)
            authok = u8(h, obj + 0x2f18)
            qpos = u32(h, obj + 0x2f1c)
            hasfree = u8(h, obj + 0x2f20)
            billrem = u32(h, obj + 0x2f24)
            billrest = u32(h, obj + 0x2f28)
            billflags = u8(h, obj + 0x2f2c)
            expa = u8(h, obj + 0x2f2d)
            log("OBJ 0x%08x state:" % obj)
            log("   +2f0c=%08x  +2f10=%08x  +2f14=%08x" % (f2f0c, f2f10, f2f14))
            log("   AUTH_OK flag(+2f18)=%d   queuePos(+2f1c)=%d hasFreeChar(+2f20)=%d"
                % (authok, qpos, hasfree))
            log("   billing: rem(+2f24)=%d rested(+2f28)=%d planFlags(+2f2c)=%d expansion(+2f2d)=%d"
                % (billrem, billrest, billflags, expa))
        if not real:
            log("no plausible world-net object found (client may not have created it yet)")
        # verdict
        got = [o for o in real if u8(h, o + 0x2f18) == 1]
        log("=" * 70)
        if got:
            log("VERDICT: client PARSED our AUTH_OK (flag set on %d object(s)). "
                "Crypt+handler WORK. Block is downstream of AUTH_RESPONSE." % len(got))
        elif real:
            log("VERDICT: world-net object exists but AUTH_OK flag is 0. "
                "Client did NOT parse our AUTH_RESPONSE -> header crypt/framing out of sync.")
        else:
            log("VERDICT: no world-net object -- client hasn't reached world dispatch, "
                "or object base not in scanned regions.")
    finally:
        k32.CloseHandle(h)


if __name__ == "__main__":
    main()
