'use strict';
//
// Frida agent: backtrace the Ascension client's auth-hello send.
//
// Changes from the original:
//   * .vm_sec bounds are read from Extensions.dll's PE section table at runtime
//     instead of being hard-coded to 0xc46000 / 0x8200. Those constants are
//     correct for one build; a client update moves them, and a stale constant
//     makes every frame silently report "not virtualized", which is the worst
//     possible failure mode for this tool. The old values remain as a fallback.
//   * each frame is labelled with the section it lands in, so a frame in .text
//     is distinguishable from one in .vm_sec at a glance.
//   * the hello-size filter is a named constant and is reported, because the
//     hello is a 631-645 byte 0x00 message (vanilla is 35) and that size is
//     itself the quickest confirmation you hooked the right send.
//
// Expected: hello sizes of 631 / 632 / 641 body bytes (645 total incl. header).

var HELLO_MIN = 100;
var HELLO_MAX = 4096;

// Fallback if the section table cannot be walked (one specific build).
var VM_FALLBACK_RVA = 0xc46000;
var VM_FALLBACK_SIZE = 0x8200;

function toHex(u8) {
  var s = '';
  for (var i = 0; i < u8.length; i++) s += ('0' + u8[i].toString(16)).slice(-2) + ' ';
  return s;
}

function ext() { return Process.findModuleByName('Extensions.dll'); }

// --- read the PE section table so section bounds survive a client update ----
function readSections(mod) {
  var out = [];
  try {
    var base = mod.base;
    var e_lfanew = base.add(0x3c).readU32();
    var nt = base.add(e_lfanew);
    if (nt.readU32() !== 0x00004550) return out;              // 'PE\0\0'
    var numSections = nt.add(0x06).readU16();
    var optSize = nt.add(0x14).readU16();
    var sec = nt.add(0x18).add(optSize);
    for (var i = 0; i < numSections; i++) {
      var h = sec.add(i * 40);
      var name = h.readCString(8) || '';
      var vsize = h.add(0x08).readU32();
      var vaddr = h.add(0x0c).readU32();
      out.push({ name: name, start: base.add(vaddr), end: base.add(vaddr + vsize) });
    }
  } catch (e) { /* fall through to the fallback below */ }
  return out;
}

var SECTIONS = [];
var VM_START = null, VM_END = null;

function initSections() {
  var e = ext();
  if (!e) return false;
  SECTIONS = readSections(e);
  for (var i = 0; i < SECTIONS.length; i++) {
    if (SECTIONS[i].name === '.vm_sec') {
      VM_START = SECTIONS[i].start;
      VM_END = SECTIONS[i].end;
    }
  }
  if (!VM_START) {
    VM_START = e.base.add(VM_FALLBACK_RVA);
    VM_END = e.base.add(VM_FALLBACK_RVA + VM_FALLBACK_SIZE);
    send({ event: 'info', msg: '.vm_sec not in section table -- using hard-coded fallback ' +
           VM_START + '..' + VM_END + ' (verify this against your build!)' });
  } else {
    send({ event: 'info', msg: '.vm_sec resolved from PE headers: ' + VM_START + '..' + VM_END });
  }
  return true;
}

function sectionOf(addr) {
  for (var i = 0; i < SECTIONS.length; i++) {
    if (addr.compare(SECTIONS[i].start) >= 0 && addr.compare(SECTIONS[i].end) < 0) {
      return SECTIONS[i].name;
    }
  }
  return null;
}

function report(context, tag, buf, len) {
  var first16 = '';
  try { first16 = toHex(new Uint8Array(buf.readByteArray(Math.min(len, 16)))); } catch (e) {}
  if (!VM_START) initSections();   // Extensions.dll may have loaded after attach
  var frames = [];
  var inVM = false;
  var extFrames = 0;
  try {
    var bt = Thread.backtrace(context, Backtracer.FUZZY);
    for (var i = 0; i < bt.length; i++) {
      var a = bt[i];
      var m = Process.findModuleByAddress(a);
      var line = a.toString();
      if (m) {
        line += '  ' + m.name + '+0x' + a.sub(m.base).toString(16);
        if (m.name.toLowerCase() === 'extensions.dll') {
          extFrames++;
          var sn = sectionOf(a);
          if (sn) line += ' [' + sn + ']';
        }
      } else {
        line += '  <unknown>';
      }
      if (VM_START && a.compare(VM_START) >= 0 && a.compare(VM_END) < 0) {
        line += '   <<< INSIDE .vm_sec (VIRTUALIZED)';
        inVM = true;
      }
      var sym = DebugSymbol.fromAddress(a);
      if (sym && sym.name && sym.name.indexOf('0x') !== 0) line += '  ' + sym.name;
      frames.push(line);
    }
  } catch (e2) { frames.push('backtrace error: ' + e2); }
  send({ event: 'auth_send', tag: tag, len: len, first16: first16,
         inVM: inVM, extFrames: extFrames, frames: frames });
}

function findExport(modName, expName) {
  // Frida 17 removed static Module.findExportByName(dll, name); use module instance + globals
  try {
    var m = Process.findModuleByName(modName);
    if (m) {
      var a = m.findExportByName ? m.findExportByName(expName) : null;
      if (a) return a;
    }
  } catch (e) {}
  try { if (Module.findGlobalExportByName) { var b = Module.findGlobalExportByName(expName); if (b) return b; } } catch (e) {}
  try { if (Module.getGlobalExportByName) { var c = Module.getGlobalExportByName(expName); if (c) return c; } } catch (e) {}
  return null;
}

function hook(name, getBuf) {
  var addr = findExport('ws2_32.dll', name);
  if (!addr) { send({ event: 'info', msg: 'no export ' + name }); return; }
  Interceptor.attach(addr, {
    onEnter: function (args) {
      try {
        var bl = getBuf(args);
        if (!bl || bl.len <= HELLO_MIN || bl.len >= HELLO_MAX) return;
        var fb = new Uint8Array(bl.buf.readByteArray(1))[0];
        if (fb === 0x00) report(this.context, name, bl.buf, bl.len);
      } catch (e) {}
    }
  });
  send({ event: 'info', msg: 'hooked ws2_32.dll!' + name });
}

hook('send', function (a) { return { len: a[2].toInt32(), buf: a[1] }; });
hook('sendto', function (a) { return { len: a[2].toInt32(), buf: a[1] }; });
hook('WSASend', function (a) {
  var wb = a[1];
  return { len: wb.readU32(), buf: wb.add(Process.pointerSize).readPointer() };
});

var e0 = ext();
if (e0) {
  send({ event: 'info', msg: 'Extensions.dll base=' + e0.base + ' size=0x' + e0.size.toString(16) });
  initSections();
} else {
  send({ event: 'info', msg: 'Extensions.dll NOT loaded yet -- section bounds unresolved' });
}
send({ event: 'info', msg: 'READY -> now type creds and click Login in the game window' });
