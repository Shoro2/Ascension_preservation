"""Find the source of the per-connection password keystream.

Confirmed: account field = name XOR K, K=28a668efc006e2b5ab81c32acb0842b237219774.
Password tail = password XOR ks(per-connection). We have exact ks for two connections
(known plaintext). ks is per-connection, so it must derive from on-wire per-connection
material (V1@0x08/16, V3@0x235/60) that the server also receives — else the server
couldn't decrypt. Hunt for the function.
"""
import os, hashlib
BASE=os.path.dirname(os.path.abspath(__file__)); CAP=os.path.join(BASE,"e0-captures")
def H(t): return open(os.path.join(CAP,"%s_c00_hello.bin"%t),"rb").read()
def xb(a,b): return bytes(x^y for x,y in zip(a,b))
K=bytes.fromhex("28a668efc006e2b5ab81c32acb0842b237219774")
CH=open(os.path.join(BASE,"live-server-challenge-response.bin"),"rb").read()

def rc4(key,n):
    S=list(range(256)); j=0
    for i in range(256):
        j=(j+S[i]+key[i%len(key)])&0xff; S[i],S[j]=S[j],S[i]
    out=bytearray(); i=j=0
    while len(out)<n:
        i=(i+1)&0xff; j=(j+S[i])&0xff; S[i],S[j]=S[j],S[i]; out.append(S[(S[i]+S[j])&0xff])
    return bytes(out)

def fields(t):
    h=H(t)
    return {"V1":h[0x08:0x18],"V3":h[0x235:0x271],"ACC":h[0x135:0x149],
            "b271":bytes([h[0x271]]),"whole":h}

cases={"s009":"REDACTED_PW_A","s010":"REDACTED_PW_B"}
for s,pw in cases.items():
    h=H(s); tail=h[0x275:]; ks=xb(tail,pw.encode()); n=len(ks)
    f=fields(s)
    print("="*66); print("%s pw=%s  ks=%s (%dB)"%(s,pw,ks.hex(),n))
    # 1) literal substring search in the whole packet & challenge
    for nm,blob in (("hello",h),("challenge",CH)):
        idx=blob.find(ks)
        if idx!=-1: print("   ks found literally in %s @0x%x"%(nm,idx))
    # 2) ks vs first-n of many derivations
    cand={}
    for nm,src in f.items():
        if nm=="whole": continue
        cand["%s[:n]"%nm]=src[:n]
        cand["sha1(%s)"%nm]=hashlib.sha1(src).digest()[:n]
        cand["md5(%s)"%nm]=hashlib.md5(src).digest()[:n]
        cand["rc4(%s)"%nm]=rc4(src,n)
    cand["sha1(V1|V3)"]=hashlib.sha1(f["V1"]+f["V3"]).digest()[:n]
    cand["sha1(V3|V1)"]=hashlib.sha1(f["V3"]+f["V1"]).digest()[:n]
    cand["rc4(V1|V3)"]=rc4(f["V1"]+f["V3"],n)
    cand["sha1(chal)"]=hashlib.sha1(CH).digest()[:n]
    cand["sha1(K)"]=hashlib.sha1(K).digest()[:n]
    cand["rc4(K)"]=rc4(K,n)
    hit=False
    for nm,cv in cand.items():
        if cv==ks: print("   ks == %s   <== MATCH"%nm); hit=True
    if not hit: print("   (no direct source matched; showing XOR residues)")
    # 3) residues: ks XOR candidate -> is it a recognizable constant/pattern?
    for nm in ("V1","V3","ACC"):
        r=xb(ks,f[nm][:n])
        # recognizable if constant, or equals K prefix, or ascii
        const = len(set(r))==1
        note = " CONST" if const else (" =K[:n]" if r==K[:n] else "")
        print("   ks ^ %s[:n] = %s%s"%(nm,r.hex(),note))

# cross-connection: is ks the SAME between s009 and s010 anywhere? (per-process check)
k9=xb(H("s009")[0x275:],b"REDACTED_PW_A"); k10=xb(H("s010")[0x275:],b"REDACTED_PW_B")
print("="*66)
print("s009 ks:",k9.hex()); print("s010 ks:",k10.hex())
print("shared prefix bytes:",sum(1 for i in range(min(len(k9),len(k10))) if k9[i]==k10[i]))
