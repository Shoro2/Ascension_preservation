r"""
Frida probe: where does the Ascension client build its auth packet?

Hooks ws2_32 send/sendto/WSASend, filters for the auth hello (first byte 0x00,
100 < len < 4096), and backtraces the caller chain -- specifically to answer
"is the packet-building code inside Extensions.dll's VMProtect .vm_sec section,
or is it normal compiled code I could read?"

Changes from the original:
  * probe.js is loaded from next to THIS file instead of a hard-coded D:\ path.
  * the target process is looked up by name and reported clearly if missing.
  * --script lets you point at a different .js without editing the source.

Run as Administrator, with the client sitting at the login screen.

    python probe.py
    python probe.py --process Ascension.exe --script probe.js
"""

import argparse
import os
import sys

try:
    import frida
except ImportError:
    print("frida not installed. Run:  python -m pip install frida")
    sys.exit(1)

HERE = os.path.dirname(os.path.abspath(__file__))


def on_message(m, data):
    if m.get('type') == 'send':
        p = m['payload']
        ev = p.get('event')
        if ev == 'auth_send':
            print("\n" + "=" * 70)
            print("AUTH SEND via %s   len=%d   extFrames=%d   inVM=%s"
                  % (p['tag'], p['len'], p.get('extFrames', 0), p['inVM']))
            print("first16:", p['first16'])
            print("backtrace (caller chain):")
            for f in p['frames']:
                print("   ", f)
            print("=" * 70)
            if p['inVM']:
                print(">>> Encryption/build path runs through .vm_sec (VIRTUALIZED) -> client patch is HARD")
            elif p.get('extFrames', 0) > 0:
                print(">>> Path runs through normal Extensions.dll code -> client patch is PLAUSIBLE")
            else:
                print(">>> Path is in the client core (Ascension.exe) -> inspect further")
        elif ev == 'info':
            print("[info]", p['msg'])
        else:
            print(p)
    elif m.get('type') == 'error':
        print("[frida-error]", m.get('stack') or m.get('description'))


def main():
    ap = argparse.ArgumentParser(description="Backtrace the Ascension auth-packet send.")
    ap.add_argument("--process", default="Ascension.exe",
                    help="process to attach to (default: %(default)s)")
    ap.add_argument("--script", default=os.path.join(HERE, "probe.js"),
                    help="agent script (default: probe.js beside this file)")
    a = ap.parse_args()

    if not os.path.isfile(a.script):
        print("agent script not found:", a.script)
        sys.exit(1)

    try:
        session = frida.attach(a.process)
    except frida.ProcessNotFoundError:
        print("process not found:", a.process)
        print("-> Start the game and leave it at the login screen first.")
        sys.exit(1)
    except Exception as e:
        print("attach failed:", e)
        print("-> Run this as Administrator; the client runs elevated, and Frida needs")
        print("   at least equal integrity to attach.")
        sys.exit(1)

    print("Attached to", a.process)
    with open(a.script, "r", encoding="utf-8") as fh:
        script = session.create_script(fh.read())
    script.on('message', on_message)
    script.load()
    print("\nHooks installed. Now type any username/password in the game and click LOGIN.")
    print("The auth packet's backtrace will print below. Press Enter here to stop.\n")
    try:
        sys.stdin.readline()
    except KeyboardInterrupt:
        pass
    session.detach()


if __name__ == "__main__":
    main()
