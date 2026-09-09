"""Passive, offset-independent test: did the client derive the STOCK world RC4 keys?

READ-ONLY (VirtualQueryEx + ReadProcessMemory of the client's OWN memory -- the same
class of read as the already-approved K40 read; no writes/patches/secrets-from-Ascension).

The client's crypt-init (Ascension.exe 0x466bf0) computes, per direction,
    rc4key = HMAC_SHA1( 16-byte-seed-half , K40 )
and stores the 20-byte digest at cryptobj+0x34c / +0x360. The default seed halves are
the STOCK constants at 0x9e8a9c:
    half0 = CC98AE04E897EACA12DDC09342915357   (ServerEncryptionKey, S->C)
    half1 = C2B3723CC6AED9B5343C53EE2F4367CE   (ServerDecryptionKey, C->S)

So if the client used the stock world crypt (Path 1), the two 20-byte digests below MUST
appear verbatim somewhere in its memory. If NEITHER appears, the client keyed its world
crypt from a different seed (custom Path 2) -> our stock RC4 desyncs and the client silently
drops SMSG_AUTH_RESPONSE. We also scan for K40 itself as a scanner sanity check (>=1 hit).
"""
import ctypes, os, sys, time, hashlib, hmac
from ctypes import wintypes as w

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
import rpm_readk as R

LOG = os.path.join(BASE, "scan_crypt_keys_log.txt")
HALF0 = bytes.fromhex("cc98ae04e897eaca12ddc09342915357")   # ServerEncryptionKey (S->C)
HALF1 = bytes.fromhex("c2b3723cc6aed9b5343c53ee2f4367ce")   # ServerDecryptionKey (C->S)

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
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
        r = k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not r:
            addr += 0x1000
            continue
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize or 0
        if (mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_GUARD)
                and not (mbi.Protect & PAGE_NOACCESS)):
            yield base, size, mbi.Type
        addr = base + size
        if size == 0:
            break


def scan_for(h, needles):
    """needles: dict label->bytes. Return dict label->[addresses]."""
    hits = {k: [] for k in needles}
    CHUNK = 0x100000
    for base, size, typ in regions(h):
        off = 0
        while off < size:
            n = min(CHUNK, size - off)
            blk = R._read(h, base + off, n)
            if blk is None:
                # page-granular fallback
                p = 0
                while p < n:
                    pg = R._read(h, base + off + p, min(0x1000, n - p))
                    if pg:
                        for label, needle in needles.items():
                            s = 0
                            while True:
                                i = pg.find(needle, s)
                                if i == -1:
                                    break
                                hits[label].append(base + off + p + i)
                                s = i + 1
                    p += 0x1000
                off += n
                continue
            for label, needle in needles.items():
                s = 0
                while True:
                    i = blk.find(needle, s)
                    if i == -1:
                        break
                    hits[label].append(base + off + i)
                    s = i + 1
            # carry overlap so a needle straddling a chunk boundary isn't missed
            off += n
    return hits


def main():
    open(LOG, "w").close()
    log("=" * 70)
    log("stock-world-crypt-key presence scan")
    pids = R.find_pids()
    if not pids:
        log("no client running"); return
    pid = pids[0]
    rk = R.read_k_for_pid(pid)
    if not rk:
        log("RPM read failed (elevation?)"); return
    base, objptr, k32b = rk
    h = R._open(pid)
    if not h:
        log("OpenProcess failed"); return
    try:
        key40 = R._read(h, objptr + 0x140, 40)
        key32 = R._read(h, objptr + 0x120, 32)
        if not key40:
            log("could not read K40 at objptr+0x140"); return
        log("pid=%d objptr=0x%x" % (pid, objptr))
        log("K40 = %s" % key40.hex())
        stockA = hmac.new(HALF1, key40, hashlib.sha1).digest()   # C->S (dirA, flag=1)
        stockB = hmac.new(HALF0, key40, hashlib.sha1).digest()   # S->C (dirB, flag=0)
        # also compute the K32-keyed variants, in case world crypt keys on the 32-byte K
        stockA32 = hmac.new(HALF1, key32, hashlib.sha1).digest() if key32 else b""
        stockB32 = hmac.new(HALF0, key32, hashlib.sha1).digest() if key32 else b""
        log("stock RC4 keys (want present if client uses STOCK world crypt):")
        log("   S->C  HMAC(CC98,K40) = %s" % stockB.hex())
        log("   C->S  HMAC(C2B3,K40) = %s" % stockA.hex())
        needles = {
            "K40": key40,
            "S->C key HMAC(CC98,K40)": stockB,
            "C->S key HMAC(C2B3,K40)": stockA,
        }
        if key32:
            needles["S->C key HMAC(CC98,K32)"] = stockB32
            needles["C->S key HMAC(C2B3,K32)"] = stockA32
        t0 = time.time()
        hits = scan_for(h, needles)
        log("scan done in %.1fs" % (time.time() - t0))
        for label, addrs in hits.items():
            shown = ", ".join("0x%x" % a for a in addrs[:6])
            log("   %-28s : %d hit(s)  %s" % (label, len(addrs), shown))
        log("=" * 70)
        stock_found = hits["S->C key HMAC(CC98,K40)"] or hits["C->S key HMAC(C2B3,K40)"] \
            or hits.get("S->C key HMAC(CC98,K32)") or hits.get("C->S key HMAC(C2B3,K32)")
        k40_found = bool(hits["K40"])
        if not k40_found:
            log("SANITY WARNING: K40 not found anywhere -- scanner or key stale; result inconclusive.")
        if stock_found:
            log("VERDICT: STOCK world-crypt keys ARE present in client memory.")
            log("  => client's world crypt == our server's. Crypt is NOT the block; the client")
            log("     stalls AFTER decrypting AUTH_RESPONSE (downstream flow issue).")
        elif k40_found:
            log("VERDICT: stock world-crypt keys are ABSENT while K40 is present.")
            log("  => client did NOT derive stock RC4 keys -> it uses a CUSTOM world crypt seed")
            log("     (Ascension Path 2). Our stock RC4 desyncs; the client drops AUTH_RESPONSE.")
            log("     (If no world connection is currently live, the crypt object may simply not")
            log("      exist yet -- re-run this WHILE connected to be conclusive.)")
        else:
            log("VERDICT: inconclusive (no K40, no stock keys) -- ensure client is live/elevated.")
    finally:
        k32.CloseHandle(h)


if __name__ == "__main__":
    main()
