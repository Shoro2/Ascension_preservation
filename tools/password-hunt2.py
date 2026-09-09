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
def hashstream(algo,seed,n):
    out=bytearray(); ctr=0
    while len(out)<n:
        out+=hashlib.new(algo,seed+bytes([ctr])).digest(); ctr+=1
    return bytes(out[:n])

cases={"s009":"REDACTED_PW_A","s010":"REDACTED_PW_B"}
for s,pw in cases.items():
    h=H(s); tail=h[0x275:]
    V1=h[0x08:0x18]; V3=h[0x235:0x271]; ACC=h[0x135:0x149]; b271=bytes([h[0x271]])
    print("="*66)
    for lbl,p in ((pw,pw.encode()),(pw.upper(),pw.upper().encode())):
        ks_x=xb(tail,p); n=len(ks_x)
        ks_a=bytes((tail[i]-p[i])&0xff for i in range(n))
        for mdl,ks in (("XOR",ks_x),("ADD",ks_a)):
            # build a big candidate dict
            seeds={"V1":V1,"V3":V3,"ACC":ACC,"V1|V3":V1+V3,"V3|V1":V3+V1,
                   "K|V1":K+V1,"V1|K":V1+K,"K|V3":K+V3,"V1|CH":V1+CH,"CH|V1":CH+V1,
                   "V1|ACC":V1+ACC,"b271|V1":b271+V1,"V1|b271":V1+b271}
            cand={}
            for nm,sd in seeds.items():
                cand["sha1s(%s)"%nm]=hashstream("sha1",sd,n)
                cand["md5s(%s)"%nm]=hashstream("md5",sd,n)
                cand["rc4(%s)"%nm]=rc4(sd,n)
            for nm,cv in cand.items():
                if cv==ks:
                    print("   %-8s %-6s ks == %s   <===== MATCH"%(lbl,mdl,nm))
    print("   %s done (no match above => not these)"%s)

# period / structure of the XOR keystream
for s,pw in cases.items():
    ks=xb(H(s)[0x275:],pw.encode())
    print("%s ks=%s  bytes:%s"%(s,ks.hex()," ".join("%d"%b for b in ks)))
