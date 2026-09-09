"""Read-only walk of the Ascension client's PARSED realm list (ground truth).

Same permission surface as rpm_readk.py (OpenProcess VM_READ + ReadProcessMemory only;
no writes/patches/debugger). Walks the client's own realm structures so we can see whether
OUR '[Ascension-Local]' realm was accepted by the native parser, and dump its fields
(category placement, gamemode/page metadata, connect string) to learn why it will not display.

Layout recovered by static RE of Ascension.exe (preferred ImageBase 0x400000):
  g_numCategories  = u32 @ VA 0xb6b0c8      (RVA 0x76b0c8)
  g_categoryArray  = u32 @ VA 0xb6b0cc  -> array of category* (numCategories entries)
  category struct:  +0x0c = realm** (array of realm*),  +0x14 = realm count
  realm struct:     +0x05 = flags byte,  +0x06 = name/connect string (asciiz),
                    +0x12c = numCharacters byte

The glue loop rebuilds every category struct each frame, so pointers are transient; we
re-read the whole chain from the globals on every attempt and keep the first live snapshot
of each realm slot.

MUST run ELEVATED (client is Administrator). Usage:  python rpm_realms.py
"""
import ctypes, os
from rpm_readk import find_pids, module_base, _open, _read

_LOG = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "realms_walk.txt"),
            "w", encoding="utf-8")
_real_print = print
def print(*a, **k):
    _real_print(*a, **k)
    try:
        _LOG.write(" ".join(str(x) for x in a) + "\n"); _LOG.flush()
    except Exception:
        pass

PREF_BASE = 0x400000
G_NUMCAT_RVA = 0xb6b0c8 - PREF_BASE
G_CATARR_RVA = 0xb6b0cc - PREF_BASE

def u32(h, a):
    b = _read(h, a, 4)
    return int.from_bytes(b, "little") if b else None

def u8(h, a):
    b = _read(h, a, 1)
    return b[0] if b else None

def cstr(h, a, maxlen=300):
    b = _read(h, a, maxlen)
    if not b: return None
    z = b.find(b"\x00")
    return b[:z if z >= 0 else maxlen]

def hexdump(b, base=0):
    out = []
    for off in range(0, len(b), 16):
        chunk = b[off:off+16]
        hexs = " ".join("%02x" % c for c in chunk)
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        out.append("      +0x%03x  %-47s  %s" % (base+off, hexs, asc))
    return "\n".join(out)

def walk(pid):
    base = module_base(pid, b"Ascension.exe")
    if not base:
        print("  no Ascension.exe module base"); return
    h = _open(pid)
    if not h:
        print("  OpenProcess failed (run ELEVATED)"); return
    try:
        numcat = u32(h, base + G_NUMCAT_RVA)
        catarr = u32(h, base + G_CATARR_RVA)
        print("  base=0x%x  numCategories=%s  catArray=0x%x" % (base, numcat, catarr or 0))
        if not numcat or not catarr or numcat > 128:
            print("  (no realm list parsed right now)"); return

        # 1) summary of counts (one snapshot) + remember which categories are non-empty
        expected = {}   # ci -> rcount
        for ci in range(numcat):
            catptr = u32(h, catarr + ci*4)
            if not catptr:
                continue
            rcount = u32(h, catptr + 0x14)
            if rcount and rcount < 200:
                expected[ci] = rcount
        print("  non-empty categories: %s  (total realms expected=%d)"
              % ({k: v for k, v in expected.items()}, sum(expected.values())))

        # dump the category structs of the non-empty ones
        for ci in list(expected):
            catptr = u32(h, catarr + ci*4)
            cblk = _read(h, catptr, 0x18) if catptr else None
            if cblk:
                print("  --- category[%d] struct @0x%x ---" % (ci, catptr))
                print(hexdump(cblk))

        # 2) capture each realm slot: re-read full chain from globals until a live ptr appears
        captured = {}   # (ci,ri) -> realm struct bytes
        want = sum(expected.values())
        for _ in range(200000):
            if len(captured) >= want:
                break
            ca = u32(h, base + G_CATARR_RVA)
            if not ca:
                continue
            for ci, rc in expected.items():
                cp = u32(h, ca + ci*4)
                if not cp:
                    continue
                ra = u32(h, cp + 0x0c)
                if not ra:
                    continue
                for ri in range(rc):
                    if (ci, ri) in captured:
                        continue
                    rp = u32(h, ra + ri*4)
                    if not rp:
                        continue
                    blk = _read(h, rp, 0x180)
                    if blk and len(blk) == 0x180:
                        captured[(ci, ri)] = (rp, blk)

        print("  captured %d/%d realm slots" % (len(captured), want))
        for (ci, ri), (rp, blk) in sorted(captured.items()):
            flags = blk[5]
            z = blk.find(b"\x00", 6)
            name = blk[6:z if z >= 0 else 6].decode("latin1", "replace")
            nchar = blk[0x12c]
            print("\n    realm[cat%d idx%d] ptr=0x%x flags=0x%02x numChars=%d"
                  % (ci, ri, rp, flags, nchar))
            print("       name/connect@+6: %r" % name)
            print(hexdump(blk))

        # raw dump of category[0]'s realm-pointer array + what cat+0 points at
        cp = u32(h, catarr + 0*4)
        if cp:
            head = _read(h, cp + 0x00, 4)
            namep = int.from_bytes(head, "little") if head else 0
            ns = cstr(h, namep, 64) if namep else None
            print("\n  category[0] cat+0 -> 0x%x  string=%r" % (namep, ns))
            ra = u32(h, cp + 0x0c)
            print("  category[0] realmArr @0x%x raw:" % (ra or 0))
            rab = _read(h, ra, 0x40) if ra else None
            if rab: print(hexdump(rab))

        # ---- full committed-memory scan for realm strings (finds structs off-chain) ----
        scan_memory(h)
    finally:
        ctypes.windll.kernel32.CloseHandle(h)


MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
READABLE = {0x02, 0x04, 0x20, 0x40, 0x80}
class MBI64(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_ulonglong), ("AllocationBase", ctypes.c_ulonglong),
                ("AllocationProtect", ctypes.c_uint32), ("__a", ctypes.c_uint32),
                ("RegionSize", ctypes.c_ulonglong), ("State", ctypes.c_uint32),
                ("Protect", ctypes.c_uint32), ("Type", ctypes.c_uint32), ("__b", ctypes.c_uint32)]

def scan_memory(h):
    k32 = ctypes.windll.kernel32
    k32.VirtualQueryEx.restype = ctypes.c_size_t
    targets = [b"[Ascension-Local]", b"127.0.0.1:8085", b"127.0.0.1:3799",
               b"Ascension Archive", b"Ascension"]
    hits = {t: [] for t in targets}
    addr = 0x10000; limit = 0x7FFF0000; mbi = MBI64(); scanned = 0
    print("\n  === memory scan for realm strings ===")
    while addr < limit:
        if k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            addr += 0x1000; continue
        b = mbi.BaseAddress; sz = int(mbi.RegionSize); nxt = b + sz
        if (mbi.State == MEM_COMMIT and (mbi.Protect & 0xFF) in READABLE
                and not (mbi.Protect & PAGE_GUARD) and sz and sz <= 0x4000000):
            data = _read(h, b, sz)
            if data:
                scanned += len(data)
                for t in targets:
                    s = 0
                    while len(hits[t]) < 30:
                        j = data.find(t, s)
                        if j < 0: break
                        hits[t].append(b + j); s = j + 1
        addr = nxt if nxt > addr else addr + 0x1000
    print("  scanned ~%.0f MB" % (scanned/1e6))
    for t in targets:
        hl = hits[t]
        print("  [%s] %d hit(s): %s" % (t.decode(), len(hl),
              " ".join("0x%x" % a for a in hl[:12])))
    # for the distinctive ones, dump the struct assuming name sits at struct+6
    for t in (b"[Ascension-Local]", b"Ascension Archive"):
        for a in hits[t][:3]:
            blk = _read(h, a - 6, 0x140)
            if blk:
                print("  --- struct around %s @0x%x (name assumed at +6) ---" % (t.decode(), a-6))
                print(hexdump(blk))

if __name__ == "__main__":
    pids = find_pids()
    print("Ascension.exe PIDs:", pids or "NONE")
    for pid in pids:
        print("\n=== pid %d ===" % pid)
        walk(pid)
