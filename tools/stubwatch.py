# -*- coding: utf-8 -*-
"""Read-only: find and dump the hook-trampoline block that the ERROR #132
signature-B fault jumps out of.

Chain, established from the on-disk disassembly plus the crash registers:

  0047DBF5  mov eax,[ebp+8] / fld [ebp+0xC] / lea ecx,[ebp-8] / fstp [ebp-8]
  0047DC01  push ecx          ; &localfloat  -> EAX at crash = 0434FF10
  0047DC02  push 6            ; event id 6 (per-frame tick)
  0047DC04  push esi
  0047DC08  call 0x480AD0     ; the event dispatcher
      0480B45  mov eax,[esi]              ; walk the handler list
      0480B6C  mov edx,[ebx+0x0C]         ; handler userdata
      0480B6F  mov eax,[ebp+0x10]         ; = &localfloat
      0480B72  mov ecx,[ebx+0x08]         ; = the callback
      0480B77  call ecx                   ; ecx = 0x00403340 at crash

EIP at the fault is CD0CA1xx, NOT ECX, so `call ecx` itself did not fault: it
entered 0x00403340, which Extensions.dll has hot-patched to `E9 3B 33 EF 6D`
(jmp Extensions+0x276680).  ECX is still 0x00403340 at the fault, so we die
only a few instructions into the hook chain, before anything reloads ECX.

Where CD0CA1xx comes from.  If the faulting transfer is a rel32 whose
displacement was left as the 0xCC filler:

    target = next_instruction + 0xCCCCCCCC   (mod 2**32)
    next   = target + 0x33333334

    0xCD0CA136 -> 0x003FD46A
    0xCD0CA176 -> 0x003FD4AA

Both sit just BELOW Ascension.exe's image base (0x00400000) -- not in any
section of the exe -- and are exactly 0x40 apart.  That is where a hook engine
allocates trampolines: scanning down from the patched function so a 5-byte
rel32 still reaches.  This tool checks whether such a block really exists and
what is in it.

Nothing here writes.  OpenProcess asks for VM_READ|QUERY_INFORMATION only and
there is no WriteProcessMemory import (handoff s8).

  python tools\stubwatch.py <pid> [seconds=240] [interval=1.0]
"""
import ctypes
import ctypes.wintypes as w
import sys
import time

import capstone

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

SCAN_LO, SCAN_HI = 0x00010000, 0x00400000   # everything under the image base
HOT = (0x003FD46A, 0x003FD4AA)              # derived next-instruction addresses

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = w.HANDLE
k32.ReadProcessMemory.argtypes = [w.HANDLE, w.LPCVOID, w.LPVOID,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", w.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", w.DWORD),
                ("Protect", w.DWORD),
                ("Type", w.DWORD)]


STATE = {0x1000: "COMMIT", 0x2000: "RESERVE", 0x10000: "FREE"}
TYPE = {0x20000: "PRIVATE", 0x40000: "MAPPED", 0x1000000: "IMAGE"}
PROT = {0x00: "-", 0x01: "NOACCESS", 0x02: "R", 0x04: "RW", 0x08: "WC",
        0x10: "X", 0x20: "RX", 0x40: "RWX", 0x80: "XWC"}
EXEC = (0x10, 0x20, 0x40, 0x80)


def read(h, addr, n):
    buf = (ctypes.c_char * n)()
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n,
                                 ctypes.byref(got)):
        return b""
    return bytes(buf[:got.value])


def scan(h):
    """Every committed region below the image base."""
    out = []
    a = SCAN_LO
    m = MBI()
    while a < SCAN_HI:
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(a), ctypes.byref(m),
                                  ctypes.sizeof(m)):
            break
        if m.State == 0x1000:
            out.append((m.BaseAddress or 0, m.RegionSize, m.Protect, m.Type))
        nxt = (m.BaseAddress or 0) + m.RegionSize
        if nxt <= a:
            break
        a = nxt
    return out


def stride_report(data, base, md):
    """Look for a fixed-stride stub table and flag CC-filled rel32 fields."""
    lines = []
    hits = 0
    for off in range(0, len(data) - 5):
        b = data[off]
        if b in (0xE8, 0xE9) and data[off + 1:off + 5] == b"\xcc\xcc\xcc\xcc":
            va = base + off
            tgt = (va + 5 + 0xCCCCCCCC) & 0xFFFFFFFF
            mark = "  <<<< MATCHES CRASH EIP" if tgt in (0xCD0CA136, 0xCD0CA176) else ""
            lines.append("  %08X  %s CCCCCCCC -> %08X%s" %
                         (va, "call" if b == 0xE8 else "jmp ", tgt, mark))
            hits += 1
            if hits > 40:
                lines.append("  ... (truncated)")
                break
    return lines


def dump_hot(h, md):
    """Disassemble 0x100 around the derived hot slots, if mapped."""
    lo = 0x003FD400
    data = read(h, lo, 0x100)
    if not data:
        return ["  (0x003FD400 is not readable)"]
    out = []
    for i in md.disasm(data, lo):
        end = i.address + i.size
        mark = ""
        if end in HOT:
            mark = "   <<<< ENDS AT A DERIVED SLOT (%08X)" % end
        out.append("  %08X  %-20s %s %s%s" %
                   (i.address, i.bytes.hex(), i.mnemonic, i.op_str, mark))
    return out


def main():
    pid = int(sys.argv[1])
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 240.0
    iv = float(sys.argv[3]) if len(sys.argv) > 3 else 1.0

    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        print("OpenProcess failed: %d" % ctypes.get_last_error())
        return 1
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    print("pid %d: scanning %08X..%08X for the trampoline block" %
          (pid, SCAN_LO, SCAN_HI))
    print("derived slots: %s" % " ".join("%08X" % a for a in HOT))
    sys.stdout.flush()

    t0 = time.time()
    last_map = None
    last_hot = None
    while time.time() - t0 < secs:
        rc = w.DWORD(0)
        if not k32.GetExitCodeProcess(h, ctypes.byref(rc)) or rc.value != 259:
            print("\n[%7.3f] PROCESS EXITED (code %d)" % (time.time() - t0, rc.value))
            break
        regs = scan(h)
        sig = tuple((b, s, p, t) for b, s, p, t in regs)
        if sig != last_map:
            print("\n[%7.3f] %d committed region(s) below the image base:" %
                  (time.time() - t0, len(regs)))
            for b, s, p, t in regs:
                x = " EXEC" if p in EXEC else ""
                hot = " <<<< CONTAINS THE DERIVED SLOTS" if b <= HOT[0] < b + s else ""
                print("   %08X..%08X  %7d B  %-4s %-8s%s%s" %
                      (b, b + s, s, PROT.get(p, hex(p)),
                       TYPE.get(t, hex(t)), x, hot))
            for b, s, p, t in regs:
                if p in EXEC and s <= 0x100000:
                    d = read(h, b, s)
                    if d:
                        sr = stride_report(d, b, md)
                        if sr:
                            print("  CC-filled rel32 fields in %08X:" % b)
                            for line in sr:
                                print(line)
            last_map = sig
            sys.stdout.flush()
        hot = read(h, 0x003FD400, 0x100)
        if hot and hot != last_hot:
            print("\n[%7.3f] 003FD400 window:" % (time.time() - t0))
            for line in dump_hot(h, md):
                print(line)
            last_hot = hot
            sys.stdout.flush()
        time.sleep(iv)

    if last_hot is None:
        print("\n=== 0x003FD400 was NEVER mapped while we watched ===")
        print("=== so the CC-rel32-trampoline reading is REFUTED ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
