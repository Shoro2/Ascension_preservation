/* Tests the real handler on loopback sockets with a synthetic auth object.
 * Does not load a game DLL, call DllMain, patch a process, or touch game data. */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <bcrypt.h>
static int rng_fail;
static NTSTATUS WINAPI test_rng(BCRYPT_ALG_HANDLE a,PUCHAR b,ULONG n,ULONG f) {
    if(rng_fail)return (NTSTATUS)0xC0000001L;return BCryptGenRandom(a,b,n,f);
}
#define BCryptGenRandom test_rng
static BYTE *fake_module;
static HMODULE WINAPI fixture_module(LPCSTR name);
#define GetModuleHandleA fixture_module
#include "../src/proxy.c"
#undef GetModuleHandleA
#undef BCryptGenRandom
static HMODULE WINAPI fixture_module(LPCSTR name) {
    if (name && !lstrcmpA(name, "Extensions_orig.dll")) return (HMODULE)fake_module;
    return GetModuleHandleA(name);
}
static int checks, failures;
static void check(int ok, const char *label) {
    ++checks; if (!ok) ++failures;
    printf("%s %s\n", ok ? "PASS" : "FAIL", label);
}
static DWORD WINAPI serve_one(LPVOID p) {
    SOCKET s = (SOCKET)p; as_handle(s); closesocket(s); return 0;
}
typedef struct { SOCKET c; HANDLE thread; } fixture;
static fixture open_fixture(void) {
    SOCKET ls, ss; struct sockaddr_in sa; int n=sizeof(sa), one=1; DWORD ms=1500;
    fixture f; ls=socket(AF_INET,SOCK_STREAM,0);
    setsockopt(ls,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,(const char*)&one,sizeof(one));
    ZeroMemory(&sa,sizeof(sa));sa.sin_family=AF_INET;sa.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(bind(ls,(struct sockaddr*)&sa,sizeof(sa)) || listen(ls,1)) exit(90);
    getsockname(ls,(struct sockaddr*)&sa,&n);f.c=socket(AF_INET,SOCK_STREAM,0);
    if(connect(f.c,(struct sockaddr*)&sa,n)) exit(91);
    ss=accept(ls,NULL,NULL);closesocket(ls);
    setsockopt(ss,SOL_SOCKET,SO_RCVTIMEO,(const char*)&ms,sizeof(ms));
    setsockopt(f.c,SOL_SOCKET,SO_RCVTIMEO,(const char*)&ms,sizeof(ms));
    f.thread=CreateThread(NULL,0,serve_one,(LPVOID)ss,0,NULL);
    if(!f.thread)exit(92);
    return f;
}
static void finish(fixture f) {
    shutdown(f.c,SD_BOTH);closesocket(f.c);
    check(WaitForSingleObject(f.thread,3000)==WAIT_OBJECT_0,"handler exits when client closes");
    CloseHandle(f.thread);
}
static int hello(fixture f) {
    unsigned char h[636]={0},challenge[119];int i;
    h[1]=8;h[2]=0x78;h[3]=2;
    for(i=0;i<4;i++)send(f.c,(const char*)h+i,1,0);
    send(f.c,(const char*)h+4,632,0);
    if(as_recvn(f.c,challenge,119)!=119)return 0;
    return challenge[0]==0 && challenge[1]==0 && challenge[2]==0 &&
           challenge[35]==1 && challenge[36]==7 && challenge[37]==32 &&
           !memcmp(challenge+38,N_LE,32) && challenge[118]==0;
}
static int ready(SOCKET s) {
    fd_set rd;struct timeval t={0,50000};FD_ZERO(&rd);FD_SET(s,&rd);
    return select(0,&rd,NULL,NULL,&t)>0;
}
static DWORD log_size(void) {
    WIN32_FILE_ATTRIBUTE_DATA a;
    return GetFileAttributesExA(g_aslog,GetFileExInfoStandard,&a)?a.nFileSizeLow:0;
}
static int realm(fixture f) {
    unsigned char req[5]={0x10},head[3],body[600];int n,p,i;
    send(f.c,(const char*)req,2,0);send(f.c,(const char*)req+2,3,0);
    if(as_recvn(f.c,head,3)!=3 || head[0]!=0x10)return 0;
    n=head[1]|head[2]<<8;if(n>600 || n<12 || as_recvn(f.c,body,n)!=n)return 0;
    if(body[4]!=2 || body[5]!=0)return 0;
    p=6;
    for(i=0;i<2;i++) {
        char *name,*addr;int category;
        if(p+3>=n || body[p] || body[p+1] || body[p+2])return 0;p+=3;
        name=(char*)body+p;while(p<n&&body[p])p++;if(p>=n)return 0;p++;
        addr=(char*)body+p;while(p<n&&body[p])p++;if(p+8>=n)return 0;p++;
        category=body[p+5];p+=7;
        if(i==0 && (strcmp(addr,"127.0.0.1:8088") || category!=1))return 0;
        if(i==1 && (addr[0] || category!=27 || !strstr(name,g_coa?"!0!11!":"!1!0!")))return 0;
    }
    return p+2==n && body[p]==0x10 && body[p+1]==0;
}
static void flow(int deny,int fragmented) {
    fixture f=open_fixture();unsigned char proof[75]={1},response[44];int n;DWORD bytes;
    InterlockedExchange(&g_gate_deny,deny);
    check(hello(f),"fragmented hello receives valid 119-byte challenge");
    if(fragmented) {
        send(f.c,(const char*)proof,1,0);
        check(!ready(f.c),"no response until the entire 75-byte proof arrives");
        send(f.c,(const char*)proof+1,17,0);send(f.c,(const char*)proof+18,57,0);
    } else send(f.c,(const char*)proof,75,0);
    n=as_recvn(f.c,response,44);
    check(n==44 && response[0]==1 && response[1]==(deny?4:0),deny?"denied gate returns AUTH_FAILED":"approved gate returns success");
    if(!deny && n==44) {
        static const unsigned char want[32]={0xeb, 0xff, 0x2f, 0x39, 0xec, 0xba, 0xdc, 0x1f, 0x72, 0x2b, 0xea, 0x27, 0x20, 0x28, 0x14, 0x94, 0x5d, 0x2e, 0xe8, 0x5a, 0xda, 0x31, 0x98, 0x9a, 0xa5, 0x35, 0x3e, 0x29, 0x55, 0xbe, 0xfa, 0x70};
        check(!memcmp(response+2,want,32),"response HMAC matches independent Python hashlib vector");
        check(!memcmp(response+34,M2_TAIL,10),"response preserves Ascension tail bytes");
        check(realm(f),"connectable realm and CoA metadata twin decode correctly");
        bytes=log_size();
        check(realm(f),"repeat realm polling remains functional");
        check(log_size()==bytes,"repeat realm polling does not write status logs");
    }
    if(deny)check(g_gate_deny==1,"denial is not consumed by a failed connection");
    finish(f);
}
static void malformed(int oversized) {
    fixture f=open_fixture();unsigned char h[14]={0},out[119];int n;
    h[1]=8;h[2]=oversized?0:0x78;h[3]=oversized?8:2;
    send(f.c,(const char*)h,oversized?4:14,0);shutdown(f.c,SD_SEND);
    n=recv(f.c,(char*)out,sizeof(out),0);
    check(n<=0,oversized?"oversized hello is refused":"truncated hello is refused");finish(f);
}
static void proof_vector(void) {
    static const unsigned char B[32]={0x57,0x1b,0x4a,0x3d,0xc2,0x67,0x5d,0x1e,0xb6,0x6e,0xce,0xce,0x73,0xd5,0x16,0xc8,0xc6,0xc0,0xac,0x63,0x2f,0x29,0x7f,0x49,0x62,0x3f,0x00,0x1c,0x01,0xa1,0x4f,0x6d};
    static const unsigned char salt[32]={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
    static const unsigned char a[32]={0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20};
    static const unsigned char wantA[32]={0xe6,0xd9,0x4d,0x77,0xf7,0x78,0x11,0xf8,0x7d,0x4f,0x75,0x1a,0x85,0xab,0xdd,0xbd,0x29,0x58,0xed,0x2f,0xae,0xd6,0x60,0x4d,0x5c,0xce,0x72,0x4e,0xe1,0x8d,0xf3,0x14};
    static const unsigned char wantM1[20]={0x6a,0xcc,0x1f,0x24,0xc8,0x67,0xa1,0x68,0xb5,0xe1,0x13,0x4e,0x23,0x3f,0xdb,0x9a,0x87,0xae,0x82,0xbf};
    static const unsigned char wantM2[20]={0x4c,0xc2,0x27,0x0a,0x20,0xb5,0xb1,0x24,0xae,0xc0,0xa5,0xb8,0x27,0x06,0xc5,0xce,0x8b,0xea,0x36,0x75};
    unsigned char A[32],M1[20],M2[20];
    check(srp6_proof("UNITTEST","PASSWORD",B,salt,a,A,M1,M2) && !memcmp(A,wantA,32) && !memcmp(M1,wantM1,20) && !memcmp(M2,wantM2,20),"SRP A, client proof and server proof match independent Python vector");
}

typedef struct {SOCKET socket;int mode;} peer_context;
static DWORD WINAPI fake_auth_peer(LPVOID arg) {
    peer_context *p=(peer_context*)arg;unsigned char request[100],reply[119]={0},proof[75];int n;
    if(as_recvn(p->socket,request,4)!=4)goto done;
    n=request[2]|request[3]<<8;if(n>96 || as_recvn(p->socket,request+4,n)!=n)goto done;
    if(p->mode==2){reply[2]=4;as_sendn(p->socket,reply,3);goto done;}
    reply[3]=1;reply[35]=1;reply[36]=7;reply[37]=32;memcpy(reply+38,N_LE,32);
    if(p->mode==3)reply[36]=3;
    if(p->mode==4)ZeroMemory(reply+3,32);
    as_sendn(p->socket,reply,119);
    if(as_recvn(p->socket,proof,75)!=75)goto done;
    ZeroMemory(reply,sizeof(reply));reply[0]=1;
    as_sendn(p->socket,reply,p->mode==0?2:32);
done:
    shutdown(p->socket,SD_BOTH);closesocket(p->socket);return 0;
}
static int fake_exchange(int mode) {
    SOCKET ls,c;struct sockaddr_in sa;int n=sizeof(sa),result;peer_context context;HANDLE th;
    ls=socket(AF_INET,SOCK_STREAM,0);ZeroMemory(&sa,sizeof(sa));sa.sin_family=AF_INET;sa.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(bind(ls,(struct sockaddr*)&sa,n)||listen(ls,1))exit(95);
    getsockname(ls,(struct sockaddr*)&sa,&n);c=socket(AF_INET,SOCK_STREAM,0);if(connect(c,(struct sockaddr*)&sa,n))exit(96);
    context.socket=accept(ls,NULL,NULL);context.mode=mode;closesocket(ls);
    th=CreateThread(NULL,0,fake_auth_peer,&context,0,NULL);if(!th)exit(97);
    result=srp6_exchange(c,"UNITTEST","PASSWORD");shutdown(c,SD_BOTH);closesocket(c);
    if(WaitForSingleObject(th,6000)!=WAIT_OBJECT_0)exit(98);CloseHandle(th);return result;
}
static void hardening_checks(void) {
    unsigned char challenge[119];
    lstrcpyA(g_proxy_path,"C:\\AuthGateFixture\\Extensions.dll");
    lstrcpyW(g_proxy_path_w,L"C:\\AuthGateFixture\\Extensions.dll");
    check(own_proxy_a(g_proxy_path,GENERIC_READ,OPEN_EXISTING),"own DLL read is forwarded");
    check(own_proxy_w(g_proxy_path_w,GENERIC_READ,OPEN_EXISTING),"own wide-path DLL read is forwarded");
    check(!own_proxy_a("C:\\OtherClient\\Extensions.dll",GENERIC_READ,OPEN_EXISTING),"another client's DLL is never redirected");
    check(!own_proxy_a(g_proxy_path,GENERIC_WRITE,OPEN_EXISTING),"DLL write is never redirected to original");
    check(!own_proxy_a(g_proxy_path,GENERIC_READ,CREATE_ALWAYS),"DLL create/truncate is never redirected to original");
    check(!own_proxy_w(g_proxy_path_w,DELETE,OPEN_EXISTING),"DLL delete access is never redirected to original");
    check(!srp6_credentials("UNITTEST","PASSWORD-SUFFIX-TOO-LONG"),"overlong password is rejected without truncation");
    check(srp6_validate("UNITTEST","PASSWORD",htonl(0x08080808))==-1,"credential validation refuses non-loopback endpoints");
    proof_vector();
    check(fake_exchange(0)!=1,"two-byte success without server proof is rejected");
    check(fake_exchange(1)==0,"forged server M2 is rejected");
    check(fake_exchange(2)==0,"three-byte account rejection handled immediately");
    check(fake_exchange(3)==-1,"unexpected SRP group is rejected");
    check(fake_exchange(4)==-1,"zero SRP public value is rejected");
    rng_fail=1;
    check(!as_build_challenge(challenge),"custom auth fails closed when system RNG fails");
    check(fake_exchange(1)==-1,"credential gate fails closed when system RNG fails");
    rng_fail=0;
    g_coa=0;flow(0,0);g_coa=1;
}
static int stub_calls;
static int __cdecl stub_login(const char *u,const char *p) {(void)u;(void)p;stub_calls++;return 42;}
int main(int argc,char **argv) {
    WSADATA wsa;BYTE *obj;unsigned char sv[32],key[32];int i;
    WSAStartup(MAKEWORD(2,2),&wsa);InitializeCriticalSection(&g_ascs);
    lstrcpyA(g_aslog,"build\\test_protocol.log");DeleteFileA(g_aslog);g_ready=1;
    check(g_gate_deny==1,"gate starts denied until credentials validate");
    check(srp6_selftest(sv),"existing SRP6 modexp/verifier vectors");
    check(!as_read_login_K(key),"missing original module is handled safely");
    fake_module=(BYTE*)VirtualAlloc(NULL,RVA_AUTHOBJ_SLOT+sizeof(DWORD),MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    obj=(BYTE*)VirtualAlloc(NULL,0x200,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if(!fake_module||!obj)return 93;
    *(DWORD*)(fake_module+RVA_AUTHOBJ_SLOT)=(DWORD)obj;
    check(!as_read_login_K(key),"uninitialized key is rejected");
    for(i=0;i<32;i++)obj[OFF_LOGIN_K+i]=(BYTE)(i+1);
    check(as_read_login_K(key)&&key[0]==1&&key[31]==32,"guarded key read preserved without KEYREAD worker");
    flow(0,0);flow(0,1);flow(1,0);flow(1,0);malformed(0);malformed(1);
    hardening_checks();
    g_orig_login=stub_login;g_gate_deny=0;
    check(gate_my_login(NULL,NULL)==42 && g_gate_deny==1,"null credentials deny while preserving client state transition");
    if(argc>1 && !strcmp(argv[1],"--live-gate")) {
        char *user=getenv("AUTHGATE_TEST_USER"),*pass=getenv("AUTHGATE_TEST_PASSWORD");
        if(!user||!pass)return 94;
        check(gate_my_login(user,"WRONG_AUTH_GATE")==42 && g_gate_deny==1,"real local authserver rejects a wrong password");
        check(gate_my_login(user,pass)==42 && g_gate_deny==0,"real local authserver accepts the existing test account");
    }
    VirtualFree(obj,0,MEM_RELEASE);VirtualFree(fake_module,0,MEM_RELEASE);WSACleanup();
    printf("RESULT %d/%d checks passed\n",checks-failures,checks);return failures?1:0;
}
