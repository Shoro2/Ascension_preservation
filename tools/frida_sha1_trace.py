"""Runtime SHA1 tracer for the Ascension client (Ascension.exe, 32-bit, ASLR off).

Why: three black-box M2 rounds failed, so we stop guessing the derivation and READ it.
All SHA1 in the client routes through two shared primitives we located by disassembly:
    SHA1_Update = 0x42b150   thiscall(ctx=ecx, data=[esp+4], len=[esp+8])
    SHA1_Final  = 0x42b280   thiscall(ctx=ecx, out=[esp+4])  -> writes 20-byte digest
We hook both, key Update payloads by ctx, and at Final print the exact input pieces and the
resulting digest. The login SHA1 chain then reveals x, S, K=interleave(S), M1 and — the prize —
M2 = SHA1(<pieces>): the true A/M1/K layout the client expects.

Read-only instrumentation: no disk patch, no secret. Observes the client hashing the user's own
local test creds + public wire values.

The client's protector hides it from process ENUMERATION and blocks path queries, but Frida still
ATTACHES by explicit PID. So we get PIDs from `tasklist` and hook every Ascension.exe instance
(there are two: the game + a watchdog twin); whichever computes M2 will reveal it.

USAGE (shim already running `python shim3799.py test test`, client at the login screen):
    python frida_sha1_trace.py [seconds]
then in the client type test/test and click Login ONCE.
"""
import sys, os, time, subprocess, frida

IMAGE_BASE = 0x400000
UPDATE_VA  = 0x42b150
FINAL_VA   = 0x42b280
LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frida-sha1-trace.log")

JS = r"""
var IMAGE_BASE = ptr('0x%x');
var UPDATE_VA  = ptr('0x%x');
var FINAL_VA   = ptr('0x%x');

var mod = null;
Process.enumerateModules().forEach(function (m) {
  if (m.name.toLowerCase() === 'ascension.exe') mod = m;
});
if (!mod) mod = Process.enumerateModules()[0];
var slide  = mod.base.sub(IMAGE_BASE);
var UPDATE = UPDATE_VA.add(slide);
var FINAL  = FINAL_VA.add(slide);
send({tag:'info', pid: Process.id, msg:'main=' + mod.name + ' base=' + mod.base});

var ctxData = {};
var finalizing = {};

function toHex(p, len) {
  try {
    var b = new Uint8Array(p.readByteArray(len));
    var s = '';
    for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
    return s;
  } catch (e) { return '<unreadable len=' + len + '>'; }
}

Interceptor.attach(UPDATE, {
  onEnter: function () {
    if (finalizing[this.threadId]) return;
    var ctx  = this.context.ecx.toString();
    var data = this.context.esp.add(4).readPointer();
    var len  = this.context.esp.add(8).readU32();
    if (!ctxData[ctx]) ctxData[ctx] = [];
    ctxData[ctx].push(toHex(data, len));
  }
});

Interceptor.attach(FINAL, {
  onEnter: function () {
    this.tid = this.threadId;
    this.ctx = this.context.ecx.toString();
    this.out = this.context.esp.add(4).readPointer();
    finalizing[this.tid] = true;
  },
  onLeave: function () {
    var pieces = ctxData[this.ctx] || [];
    var digest = toHex(this.out, 20);
    delete ctxData[this.ctx];
    delete finalizing[this.tid];
    if (pieces.length) send({tag:'sha1', pid: Process.id, pieces: pieces, digest: digest});
  }
});
"""

def ascension_pids():
    try:
        out = subprocess.check_output(
            ["tasklist", "/FI", "IMAGENAME eq Ascension.exe", "/FO", "CSV", "/NH"],
            stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return []
    pids = []
    for line in out.splitlines():
        line = line.strip()
        if not line or not line.startswith('"'):
            continue
        cols = [c.strip('"') for c in line.split('","')]
        if len(cols) >= 2 and cols[1].isdigit():
            pids.append(int(cols[1]))
    return pids

def main():
    log = open(LOG, "w", encoding="utf-8")
    def out(line):
        print(line, flush=True)
        log.write(line + "\n"); log.flush()

    dur = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    dev = frida.get_local_device()

    out("waiting for Ascension.exe (via tasklist) ...")
    pids = []
    for _ in range(240):
        pids = ascension_pids()
        if pids:
            break
        time.sleep(0.5)
    if not pids:
        out("!! no Ascension.exe running. Open the client to the login screen and re-run.")
        return
    out("Ascension.exe PIDs: %s" % pids)

    n = [0]
    def on_message(msg, data):
        if msg.get("type") == "error":
            out("[frida error] %s" % msg.get("description")); return
        p = msg.get("payload", {})
        if p.get("tag") == "info":
            out("[hook pid=%s] %s" % (p.get("pid"), p.get("msg"))); return
        if p.get("tag") != "sha1":
            return
        pieces, digest = p["pieces"], p["digest"]
        total = sum(len(x)//2 for x in pieces if not x.startswith("<"))
        n[0] += 1
        out("")
        out("SHA1 #%d  pid=%s  (%d in-bytes, %d piece(s)) -> %s"
            % (n[0], p.get("pid"), total, len(pieces), digest))
        for i, pc in enumerate(pieces):
            blen = len(pc)//2 if not pc.startswith("<") else "?"
            out("    piece[%d] len=%s : %s" % (i, blen, pc))

    sessions, scripts = [], []
    for pid in pids:
        try:
            s = dev.attach(pid)
            sc = s.create_script(JS % (IMAGE_BASE, UPDATE_VA, FINAL_VA))
            sc.on("message", on_message)
            sc.load()
            sessions.append(s); scripts.append(sc)
            out("attached + hooked pid=%d" % pid)
        except Exception as e:
            out("!! attach/hook failed for pid=%d: %r" % (pid, e))
    if not scripts:
        out("!! could not hook any client process."); return

    out("hooks live in %d process(es). In the client: type test / test and click Login ONCE." % len(scripts))
    out("watching for %ds ... (trace also saved to %s)" % (dur, LOG))
    t0 = time.time()
    try:
        while time.time() - t0 < dur:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    out("stopped after %d hash(es)." % n[0])

if __name__ == "__main__":
    main()
