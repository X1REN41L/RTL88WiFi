"""Exercise the WPA3 code the kext links: rtw88_crypto.c and hostap's SAE on
Mbed TLS, through the rtw88_sae.h interface the MLME calls.

Crypto is checked against published vectors (FIPS 180/197, RFC 2202/3394/4231/
4493, IEEE 802.11i) and, for the 802.11 KDF and PRF, against answers computed
here with Python's hmac. SAE runs a station against an access point, both ends
using this code, so it proves self-consistency, not interoperability.

Built for the host: the KERNEL branches of rtw88_hostap.c (allocator, RNG) are
not covered. ASan/UBSan check malformed input. Not a kernel or hardware test.
"""
from pathlib import Path
import hashlib, hmac, struct, subprocess, tempfile

root = Path(__file__).resolve().parents[1] / 'driver/RTL88WiFi'
wpa3 = root / 'src/compat/wpa3'
tp = root.parent / 'third_party'

def c_bytes(b):
    return ','.join(str(x) for x in b)

def kdf_sha256(key, label, ctx, bits):
    out = b''
    for i in range(1, (bits + 255) // 256 + 1):
        out += hmac.new(key, struct.pack('<H', i) + label + ctx + struct.pack('<H', bits), hashlib.sha256).digest()
    return out[:bits // 8]

def prf_sha1(key, label, data, n):
    out = b''
    i = 0
    while len(out) < n:
        out += hmac.new(key, label + b'\0' + data + bytes([i]), hashlib.sha1).digest()
        i += 1
    return out[:n]

K = bytes(range(32))
CTX = bytes(range(100, 176))
KDF_LABEL = b'Pairwise key expansion'
vectors = f'''
static const uint8_t PY_KEY[32]={{{c_bytes(K)}}};
static const uint8_t PY_CTX[76]={{{c_bytes(CTX)}}};
static const uint8_t PY_KDF48[48]={{{c_bytes(kdf_sha256(K, KDF_LABEL, CTX, 384))}}};
static const uint8_t PY_KDF16[16]={{{c_bytes(kdf_sha256(K, KDF_LABEL, CTX, 128))}}};
static const uint8_t PY_PRF64[64]={{{c_bytes(prf_sha1(K, KDF_LABEL, CTX, 64))}}};
'''

test = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rtw88_crypto.h"
#include "rtw88_sae.h"
static int failures;
#define CHECK(c) do{if(!(c)){failures++;printf("FAIL line %d: %s\n",__LINE__,#c);}}while(0)
static int unhex(const char*h,uint8_t*o){int n=0;for(;h[0]&&h[1];h+=2){unsigned v;sscanf(h,"%2x",&v);o[n++]=(uint8_t)v;}return n;}
#define EQ(buf,hex) do{uint8_t e_[128];int n_=unhex(hex,e_);CHECK(memcmp(buf,e_,(size_t)n_)==0);}while(0)
''' + vectors + r'''
static void crypto_vectors(void){
 uint8_t o[64],k[32],m[64];
 rtw88_sha1((const uint8_t*)"abc",3,o);EQ(o,"a9993e364706816aba3e25717850c26c9cd0d89d");
 rtw88_sha256((const uint8_t*)"abc",3,o);EQ(o,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
 rtw88_sha256((const uint8_t*)"",0,o);EQ(o,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
 memset(k,0x0b,20);
 rtw88_hmac_sha1(k,20,(const uint8_t*)"Hi There",8,o);EQ(o,"b617318655057264e28bc0b6fb378c8ef146be00");
 rtw88_hmac_sha256(k,20,(const uint8_t*)"Hi There",8,o);EQ(o,"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
 /* IEEE 802.11i-2004 annex H.4 passphrase vector */
 rtw88_pbkdf2_sha1((const uint8_t*)"password",8,(const uint8_t*)"IEEE",4,4096,o,32);
 EQ(o,"f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e");
 /* FIPS 197 appendix C.1, both directions */
 unhex("000102030405060708090a0b0c0d0e0f",k);unhex("00112233445566778899aabbccddeeff",m);
 rtw88_aes128_encrypt(k,m,o);EQ(o,"69c4e0d86a7b0430d8cdb78070b4c55a");
 rtw88_aes128_decrypt(k,o,o+16);CHECK(memcmp(o+16,m,16)==0);
 /* RFC 3394 4.1, both directions, and a corrupted wrap */
 rtw88_aes_wrap(k,m,16,o);EQ(o,"1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5");
 {uint8_t p[16];CHECK(rtw88_aes_unwrap(k,o,24,p));CHECK(memcmp(p,m,16)==0);o[3]^=1;CHECK(!rtw88_aes_unwrap(k,o,24,p));}
 /* RFC 4493 section 4: all four message lengths */
 unhex("2b7e151628aed2a6abf7158809cf4f3c",k);
 unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",m);
 rtw88_aes_cmac(k,m,0,o);EQ(o,"bb1d6929e95937287fa37d129b756746");
 rtw88_aes_cmac(k,m,16,o);EQ(o,"070a16b46b4d4144f79bdd9dd04a287c");
 rtw88_aes_cmac(k,m,40,o);EQ(o,"dfa66747de9ae63030ca32611497c827");
 rtw88_aes_cmac(k,m,64,o);EQ(o,"51f0bebf7e3b9d92fc49741779363cfe");
 /* IEEE 802.11-2020 annex J: CCMP data frame vector; then tampering and the management nonce */
 {uint8_t tk[16],hdr[24],d[20],mic[8];const uint64_t pn=0xB5039776E70CULL;
  unhex("c97c1f67ce371185514a8a19f2bdd52f",tk);unhex("0848c32c0fd2e128a57c5030f1844408abaea5b8fcba8033",hdr);
  unhex("f8ba1a55d02f85ae967bb62fb6cda8eb7e78a050",d);
  rtw88_ccmp_encrypt(tk,hdr,24,pn,d,20,mic);EQ(d,"f3d0a2fe9a3dbf2342a643e43246e80c3c04d019");EQ(mic,"7845ce0b16f97623");
  uint8_t c[20];memcpy(c,d,20);
  CHECK(rtw88_ccmp_decrypt(tk,hdr,24,pn,d,20,mic));EQ(d,"f8ba1a55d02f85ae967bb62fb6cda8eb7e78a050");
  memcpy(d,c,20);d[0]^=1;CHECK(!rtw88_ccmp_decrypt(tk,hdr,24,pn,d,20,mic));
  memcpy(d,c,20);CHECK(!rtw88_ccmp_decrypt(tk,hdr,24,pn+1,d,20,mic));
  /* The same bytes as a management frame (nonce flags 0x10) must not interchange with data */
  uint8_t mh[24],md[20];memcpy(mh,hdr,24);mh[0]=0xd0;mh[1]=0x40;unhex("f8ba1a55d02f85ae967bb62fb6cda8eb7e78a050",md);memcpy(d,md,20);
  rtw88_ccmp_encrypt(tk,mh,24,pn,md,20,mic);CHECK(memcmp(md,c,20)!=0);CHECK(rtw88_ccmp_decrypt(tk,mh,24,pn,md,20,mic));CHECK(memcmp(md,d,20)==0);}
 /* Computed independently by the Python half of this test */
 rtw88_kdf_sha256(PY_KEY,32,"Pairwise key expansion",PY_CTX,76,o,48);CHECK(memcmp(o,PY_KDF48,48)==0);
 rtw88_kdf_sha256(PY_KEY,32,"Pairwise key expansion",PY_CTX,76,o,16);CHECK(memcmp(o,PY_KDF16,16)==0);
 rtw88_sha1_prf(PY_KEY,32,"Pairwise key expansion",PY_CTX,76,o,64);CHECK(memcmp(o,PY_PRF64,64)==0);
}
static const uint8_t STA[6]={2,0,0,0,0,1},AP[6]={2,0,0,0,0,2};
static const uint8_t SSID[]="TestNet";
#define PW(s) (const uint8_t*)(s),strlen(s)
static struct rtw88_sae*mk(const uint8_t*own,const uint8_t*peer,const char*pw,bool h2e){
 return rtw88_sae_begin(own,peer,SSID,7,(const uint8_t*)pw,strlen(pw),h2e);}
/* A whole exchange. Returns 1 if each side accepted the other's confirm. */
static int run(const char*stapw,const char*appw,bool stah2e,bool aph2e,uint8_t*pmkOut){
 struct rtw88_sae*s=mk(STA,AP,stapw,stah2e),*a=mk(AP,STA,appw,aph2e);
 uint8_t sc[256],ac[256],sf[64],af[64];int ok=0;
 CHECK(s&&a);if(!s||!a){rtw88_sae_end(s);rtw88_sae_end(a);return 0;}
 int sl=rtw88_sae_write_commit(s,NULL,0,sc,sizeof sc),al=rtw88_sae_write_commit(a,NULL,0,ac,sizeof ac);
 CHECK(sl==98&&al==98);                       /* group 19, 32-byte scalar, 64-byte element */
 CHECK(sc[0]==19&&sc[1]==0);
 if(rtw88_sae_rx_commit(a,sc,(size_t)sl)==0&&rtw88_sae_rx_commit(s,ac,(size_t)al)==0){
  int sn=rtw88_sae_write_confirm(s,sf,sizeof sf),an=rtw88_sae_write_confirm(a,af,sizeof af);
  CHECK(sn==34&&an==34);                      /* send-confirm, 32-byte confirm */
  int r1=rtw88_sae_rx_confirm(a,sf,(size_t)sn)==0,r2=rtw88_sae_rx_confirm(s,af,(size_t)an)==0;
  CHECK(r1==r2);ok=r1&&r2;
  if(ok){uint8_t p1[32],p2[32],i1[16],i2[16],z[32]={0};rtw88_sae_keys(s,p1,i1);rtw88_sae_keys(a,p2,i2);
   CHECK(memcmp(p1,p2,32)==0&&memcmp(i1,i2,16)==0&&memcmp(p1,z,32)!=0&&memcmp(i1,z,16)!=0);
   if(pmkOut)memcpy(pmkOut,p1,32);}
 }
 rtw88_sae_end(s);rtw88_sae_end(a);return ok;
}
static void sae_exchanges(void){
 static const char*pw[]={"a","correct horse battery","0123456789012345678901234567890123456789012345678901234567890123",
  "p\xc3\xa4ssw\xc3\xb6rd with spaces and \xe2\x82\xac"};
 uint8_t p1[32],p2[32];
 for(int h2e=0;h2e<2;h2e++){
  for(unsigned i=0;i<4;i++)CHECK(run(pw[i],pw[i],h2e,h2e,NULL));
  /* Fresh secrets every run: same password, different PMK. */
  CHECK(run(pw[1],pw[1],h2e,h2e,p1));CHECK(run(pw[1],pw[1],h2e,h2e,p2));CHECK(memcmp(p1,p2,32)!=0);
  /* Wrong password must never reach a shared key. */
  CHECK(!run("correct horse battery","wrong horse battery",h2e,h2e,NULL));
 }
 /* The two password-element methods do not interoperate silently. */
 CHECK(!run(pw[1],pw[1],true,false,NULL));
 /* The password element binds both addresses. */
 {struct rtw88_sae*s=mk(STA,AP,pw[1],false),*a=mk(AP,(const uint8_t*)"\x02\0\0\0\0\x09",pw[1],false);
  uint8_t sc[256],ac[256],sf[64];int sl=rtw88_sae_write_commit(s,NULL,0,sc,256),al=rtw88_sae_write_commit(a,NULL,0,ac,256);
  if(rtw88_sae_rx_commit(a,sc,(size_t)sl)==0&&rtw88_sae_rx_commit(s,ac,(size_t)al)==0){
   int n=rtw88_sae_write_confirm(s,sf,64);CHECK(rtw88_sae_rx_confirm(a,sf,(size_t)n)!=0);}
  rtw88_sae_end(s);rtw88_sae_end(a);}
}
static void sae_commit_format(void){
 struct rtw88_sae*s=mk(STA,AP,"correct horse battery",false);uint8_t b[256],t[32],small[10];memset(t,0x5a,32);
 CHECK(rtw88_sae_write_commit(s,t,32,b,sizeof b)==98+32);
 CHECK(b[0]==19&&b[1]==0&&memcmp(b+2,t,32)==0);      /* anti-clogging token follows the group */
 CHECK(rtw88_sae_write_commit(s,NULL,0,small,sizeof small)<0);
 rtw88_sae_end(s);
}
/* A hostile AP: every truncation and many bit flips of a valid exchange. */
static void sae_hostile(void){
 for(int h2e=0;h2e<2;h2e++){
  struct rtw88_sae*a=mk(AP,STA,"correct horse battery",h2e);uint8_t ac[256];int al=rtw88_sae_write_commit(a,NULL,0,ac,256);
  /* Reflection: our own commit coming back. */
  {struct rtw88_sae*s=mk(STA,AP,"correct horse battery",h2e);uint8_t sc[256];int sl=rtw88_sae_write_commit(s,NULL,0,sc,256);
   CHECK(rtw88_sae_rx_commit(s,sc,(size_t)sl)!=0);rtw88_sae_end(s);}
  for(int n=0;n<al;n++){struct rtw88_sae*s=mk(STA,AP,"correct horse battery",h2e);
   CHECK(rtw88_sae_rx_commit(s,ac,(size_t)n)!=0);rtw88_sae_end(s);}
  /* A flipped commit is refused, or leads to a confirm that cannot verify. */
  uint32_t seed=19+(uint32_t)h2e;
  for(int t=0;t<150;t++){struct rtw88_sae*s=mk(STA,AP,"correct horse battery",h2e);uint8_t m[256];memcpy(m,ac,(size_t)al);
   seed=seed*1664525+1013904223;m[(seed>>8)%(unsigned)al]^=(uint8_t)(1u<<((seed>>4)&7));
   if(rtw88_sae_rx_commit(s,m,(size_t)al)==0){uint8_t c[64];memset(c,0,64);CHECK(rtw88_sae_rx_confirm(s,c,34)!=0);}
   rtw88_sae_end(s);}
  /* Confirm tampering, wrong length, and truncation. */
  {struct rtw88_sae*s=mk(STA,AP,"correct horse battery",h2e);uint8_t sc[256],sf[64],af[64];int sl=rtw88_sae_write_commit(s,NULL,0,sc,256);
   struct rtw88_sae*ap=mk(AP,STA,"correct horse battery",h2e);uint8_t pc[256];int pl=rtw88_sae_write_commit(ap,NULL,0,pc,256);
   CHECK(rtw88_sae_rx_commit(ap,sc,(size_t)sl)==0);CHECK(rtw88_sae_rx_commit(s,pc,(size_t)pl)==0);
   int fn=rtw88_sae_write_confirm(ap,af,64);(void)rtw88_sae_write_confirm(s,sf,64);
   for(int n=0;n<fn;n++)CHECK(rtw88_sae_rx_confirm(s,af,(size_t)n)!=0);
   for(int i=2;i<fn;i++){af[i]^=1;CHECK(rtw88_sae_rx_confirm(s,af,(size_t)fn)!=0);af[i]^=1;}
   CHECK(rtw88_sae_rx_confirm(s,af,(size_t)fn)==0);
   rtw88_sae_end(s);rtw88_sae_end(ap);}
  rtw88_sae_end(a);
 }
}
int main(void){
 crypto_vectors();sae_exchanges();sae_commit_format();sae_hostile();
 if(failures){printf("%d failure(s)\n",failures);return 1;}
 puts("PASS: SHA-1/SHA-256/HMAC/PBKDF2/AES/AES-wrap/AES-CMAC vectors, 802.11 KDF and PRF against Python; SAE hunting-and-pecking and hash-to-element: agreement, fresh keys, wrong password, address binding, method mismatch, token format, reflection, every truncation, flipped commits and confirms");
 return 0;
}
'''

inc = [f'-I{d}' for d in (wpa3 / 'hostap', tp / 'hostap', tp / 'hostap/src', tp / 'hostap/src/utils',
                          tp / 'hostap/src/common', tp / 'mbedtls/include', tp / 'mbedtls/library', wpa3)]
srcs = [tp / 'hostap/src/common/sae.c', tp / 'hostap/src/common/dragonfly.c', wpa3 / 'rtw88_wpabuf.c',
        tp / 'mbedtls/library/bignum.c', tp / 'mbedtls/library/bignum_core.c', tp / 'mbedtls/library/ecp.c',
        tp / 'mbedtls/library/ecp_curves.c', tp / 'mbedtls/library/constant_time.c',
        tp / 'mbedtls/library/platform_util.c', wpa3 / 'rtw88_hostap.c', wpa3 / 'rtw88_sae.c', wpa3 / 'rtw88_crypto.c']
with tempfile.TemporaryDirectory(prefix='rtw88-wpa3-') as td:
    p = Path(td)
    (p / 'test.c').write_text(test)
    subprocess.run(['xcrun', 'clang', '-std=gnu11', '-w', '-g', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-DMBEDTLS_CONFIG_FILE="rtw88_mbedtls_config.h"',
                    *inc, str(p / 'test.c'), *map(str, srcs), '-o', str(p / 'test')], check=True)
    subprocess.run([str(p / 'test')], check=True)
