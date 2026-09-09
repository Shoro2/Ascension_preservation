"""Is the OpenProcess denial specific to Ascension (anti-tamper) or a privilege
problem on our side?  Compare against a benign same-user process and try each
access tier.  Read-only, no attach."""
import ctypes, ctypes.wintypes as wt, sys
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = wt.HANDLE

TIERS = [
    ("QUERY_LIMITED_INFORMATION", 0x1000),
    ("QUERY_INFORMATION",         0x0400),
    ("VM_READ",                   0x0010),
    ("VM_READ|QUERY",             0x0410),
    ("SYNCHRONIZE",               0x00100000),
    ("ALL_ACCESS",                0x1F0FFF),
]

def probe(pid, label):
    print("=== %s pid %d ===" % (label, pid))
    for nm, mask in TIERS:
        h = k32.OpenProcess(mask, False, pid)
        if h:
            print("  %-28s OK (h=0x%X)" % (nm, h)); k32.CloseHandle(h)
        else:
            print("  %-28s DENIED err=%d" % (nm, ctypes.get_last_error()))

targets = [(int(sys.argv[i]), sys.argv[i+1]) for i in range(1, len(sys.argv)-1, 2)]
for pid, label in targets:
    probe(pid, label)
