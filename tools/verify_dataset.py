"""Verify the pinned dataset manifest and every listed file; no writes or downloads."""
import argparse, hashlib, json
from pathlib import Path

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("root",type=Path,help="ascension-data checkout")
    ap.add_argument("--pin",type=Path,default=Path(__file__).resolve().parents[1]/"manifests/dataset.json")
    args=ap.parse_args();root=args.root.resolve();pin=json.loads(args.pin.read_text(encoding="utf8"))
    def safe(rel):
        result=(root/rel).resolve()
        if root not in result.parents:raise ValueError("Manifest path escapes dataset root")
        return result
    manifest=safe(pin["manifest"]);raw=manifest.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=pin["manifest_sha256"]:raise ValueError("Pinned manifest hash mismatch")
    data=json.loads(raw)
    for item in data["files"]:
        file=safe(item["path"])
        if file.stat().st_size!=item["bytes"] or hashlib.sha256(file.read_bytes()).hexdigest()!=item["sha256"]:
            raise ValueError("Dataset mismatch: "+item["path"])
    print("Verified",data["snapshot"],len(data["files"]),"files")
if __name__=="__main__":main()
