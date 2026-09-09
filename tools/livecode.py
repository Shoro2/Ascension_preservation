# -*- coding: utf-8 -*-
"""Read-only: dump live code bytes out of Ascension.exe and diff them against the
file on disk, so runtime hot-patches (Extensions.dll installs several) are visible.

Nothing here writes: OpenProcess asks for VM_READ|QUERY_INFORMATION only, and
there is no WriteProcessMemory import.  Handoff s8 forbids writing to the client.

  python tools\livecode.py [pid] [va:len ...]
"""
import ctypes, ctypes.wintypes as w, sys
import capstone, pefile

EXE = r"C:\AzerothRealm\client-ascension\Ascension.exe"
PROCESS_VM_READ, PROCESS_QUERY_INFORMATION = 0x0010, 0x0400
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = w.HANDLE
k32.ReadProcessMemory.argtypes = [w.HANDLE, w.LPCVOID, w.LPVOID,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]


def find_pid():
    import subprocess, json
    out = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command",
         "Get-Process Ascension -ErrorAction SilentlyContinue | "
         "Select-Object -First 1 -ExpandProperty Id"],
        capture_output=True, text=True).stdout.strip()
    return int(out) if out else 0


def main():
    args = sys.argv[1:]
    pid = int(args.pop(0)) if args and args[0].isdigit() else find_pid()
    if not pid:
        sys.exit("no Ascension.exe running")
    spans = []
    for a in args:
        va, _, n = a.partition(":")
        spans.append((int(va, 16), int(n or "32")))
    if not spans:
        spans = [(0x00403340, 0x28), (0x00480B40, 0x44), (0x0047DBC0, 0x54),
                 (0x004E5CB0, 0x30), (0x0047F150, 0x20)]

    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        sys.exit("OpenProcess(%d) failed: %d (try elevated)"
                 % (pid, ctypes.get_last_error()))

    pe = pefile.PE(EXE, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    secs = [(base + s.VirtualAddress, s.get_data()) for s in pe.sections]

    def on_disk(va, n):
        for sva, sd in secs:
            if sva <= va < sva + len(sd):
                return sd[va - sva: va - sva + n]
        return None

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    print("pid %d" % pid)
    for va, n in spans:
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(h, w.LPCVOID(va), buf, n, ctypes.byref(got)):
            print("\n%08X  READ FAILED (%d)" % (va, ctypes.get_last_error()))
            continue
        live, disk = buf.raw[:got.value], on_disk(va, got.value)
        same = (live == disk)
        print("\n=== %08X (%d bytes)  %s ==="
              % (va, got.value, "unchanged" if same else "*** PATCHED ***"))
        if not same and disk:
            for i in range(0, len(live), 16):
                lh = " ".join("%02X" % b for b in live[i:i + 16])
                dh = " ".join("%02X" % b for b in disk[i:i + 16])
                mark = "   <<<" if live[i:i + 16] != disk[i:i + 16] else ""
                print("  %08X live %s%s" % (va + i, lh, mark))
                if mark:
                    print("  %08X disk %s" % (va + i, dh))
        print("  -- live disassembly --")
        for ins in md.disasm(live, va):
            print("  %08X  %-16s %s %s"
                  % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
    k32.CloseHandle(h)


main()
