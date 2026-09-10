"""Inspect our rebuilt proxy; never loads it or copies client assets."""
from pathlib import Path
import hashlib,json
import pefile
root=Path(__file__).resolve().parent
path=root/"build"/"Extensions.dll"
data=path.read_bytes();pe=pefile.PE(data=data)
exports=[s.name.decode() for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name]
imports=sorted({s.name.decode() for d in pe.DIRECTORY_ENTRY_IMPORT for s in d.imports if s.name})
forbidden={"AddVectoredExceptionHandler","SetThreadContext","GetThreadContext","ReadProcessMemory","WriteProcessMemory","CreateRemoteThread","CreateProcessA","CreateProcessW","ShellExecuteA","ShellExecuteW","RegSetValueExA","WinHttpConnect","InternetOpenA"}
markers=[b"worldkey.bin",b"proxy_key.log",b"proxy_keyread.log",b"proxy_net.log",b"proxy_files.log",b"mysql.exe"]
assert pe.FILE_HEADER.Machine==0x14c and pe.OPTIONAL_HEADER.Magic==0x10b
assert exports==["ClientExtensionsDummy"]
assert not forbidden.intersection(imports)
assert not any(m in data for m in markers)
report={"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),"machine":"x86 PE32","exports":exports,"imports":imports,"debug_artifact_scan":"PASS","unneeded_debug_import_scan":"PASS","sourceSha256":{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((root/"src").iterdir()) if p.is_file()}}
(root/"build"/"binary-verification.json").write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps({k:v for k,v in report.items() if k not in ("imports","sourceSha256")}))
