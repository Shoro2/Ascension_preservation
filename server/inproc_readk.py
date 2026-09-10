"""In-process login-K source for shim3799 -- the clean alternative to cross-process RPM.

Background: shim3799 needs the client's per-session login key K to answer the custom auth
(M2 = HMAC-SHA256(K,"OK")). By default it reads K with rpm_readk.py using OpenProcess +
ReadProcessMemory, which requires the shim to run at the SAME integrity level as the client
-- the "run the shim elevated" step documented in docs/HOW-THE-REDIRECT-WORKS.md sec.3/5.

This module removes that requirement. kexport.dll, loaded INSIDE the client by the dinput8
proxy (see contrib/InProcessKeyOracle/), reads K in-process via the same pointer chain
rpm_readk.py uses (Extensions base + 0xbdbc04 -> obj -> +0x120) and serves it on a loopback
oracle at 127.0.0.1:37281. Reading from inside the process needs no OpenProcess/RPM and no
integrity match. shim3799 asks the oracle right when it needs K, and falls back to rpm_readk
(then variant-guess) if the oracle is absent -- so the shim remains a complete standalone
fallback and this module is never required.

The idea is lifted from FirstOni's AscensionAuthGate; see docs/AUTH-APPROACHES-EVALUATED.md.

Wire format (kexport.c): server -> 33 bytes = status(1) || K(32). status 1 = K present.
The oracle only helps when kexport.dll is deployed, which needs a WRITABLE client copy (do
not modify the live client install if it is a junction / read-only link).
"""
import socket

ORACLE_HOST = "127.0.0.1"
ORACLE_PORT = 37281
_TIMEOUT_S = 0.7


def read_k(host=ORACLE_HOST, port=ORACLE_PORT):
    """Return the 32-byte login K from the in-process oracle, or None if the oracle is
    not present / not answering / K not computed yet. Never raises."""
    try:
        with socket.create_connection((host, port), timeout=_TIMEOUT_S) as s:
            s.settimeout(_TIMEOUT_S)
            buf = b""
            while len(buf) < 33:
                chunk = s.recv(33 - len(buf))
                if not chunk:
                    break
                buf += chunk
    except OSError:
        return None
    if len(buf) != 33 or buf[0] != 1:
        return None
    k = buf[1:33]
    return None if set(k) == {0} else k


def available(host=ORACLE_HOST, port=ORACLE_PORT):
    """True if the oracle port accepts a connection (kexport.dll is loaded)."""
    try:
        with socket.create_connection((host, port), timeout=_TIMEOUT_S):
            return True
    except OSError:
        return False


if __name__ == "__main__":
    k = read_k()
    print("oracle at %s:%d -> %s" % (
        ORACLE_HOST, ORACLE_PORT,
        ("K=" + k.hex()) if k else ("reachable, K not ready" if available() else "not reachable")))
