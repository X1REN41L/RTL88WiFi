"""Exercise the actual join security, protected management frame, SAE frame,
link monitor, scan start, failed-join, key teardown and association wire code.

Functions are cut from the driver source. Host substitutes replace the radio,
timers, SAE crypto and macOS. ASan/UBSan check memory use. This is not a kernel
or hardware test, and threading is only exercised in sequence.
"""
from pathlib import Path
import subprocess, tempfile

root = Path(__file__).resolve().parents[1] / 'driver/RTL88WiFi/src/kext'
ieee = (root / 'RTW88IEEE80211.cpp').read_text()
sec = (root / 'RTW88Security.cpp').read_text()
wifi = (root / 'RTL88WiFi.cpp').read_text()

def fn(signature, src):
    start = src.index(signature); i = src.index('{', start) + 1; depth = 1
    while depth:
        depth += (src[i] == '{') - (src[i] == '}'); i += 1
    return src[start:i]

COMMON = r'''
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cassert>
#include <string>
#include <vector>
#define IOLog(...) ((void)0)
typedef int IOReturn;
enum {kIOReturnSuccess=0,kIOReturnBusy,kIOReturnNotReady,kIOReturnNoMemory,kIOReturnError,
      kIOReturnUnsupported,kIOReturnBadArgument,kIOReturnNotFound};
enum RTW88State{RTW88_STATE_IDLE,RTW88_STATE_SCANNING,RTW88_STATE_AUTHENTICATING,RTW88_STATE_ASSOCIATING,
      RTW88_STATE_HANDSHAKING,RTW88_STATE_CONNECTED,RTW88_STATE_DISCONNECTING};
static void bzero_(void*p,size_t n){memset(p,0,n);}
#define bzero bzero_
static uint64_t nowMs=100000;
static uint64_t rtw88NowMs(){return nowMs;}
'''

DRIVER = COMMON + r'''
typedef signed char s8;
enum {kAkm8021X=1,kAkmPsk=2,kAkmPskSha256=6,kAkmSae=8};
#define WLAN_CIPHER_SUITE_CCMP 0x000fac04
#define WLAN_CIPHER_SUITE_TKIP 0x000fac02
#define WLAN_EID_RSN 48
#define WLAN_EID_SUPP_RATES 1
#define WLAN_EID_EXT_SUPP_RATES 50
#define WLAN_REASON_DEAUTH_LEAVING 3
#define WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY 4
#define IEEE80211_FCTL_PROTECTED 0x4000
#define RX_FLAG_DECRYPTED 1
#define IEEE80211_KEY_FLAG_PAIRWISE 1
#define IEEE80211_CHAN_DISABLED 1
#define NL80211_NUM_BANDS 2
#define kIONetworkLinkValid 1
#define kMillisecondScale 1
#define DISABLE_KEY 0
#define SET_KEY 1
#define IEEE80211_FTYPE_MGMT 0
#define IEEE80211_STYPE_ACTION 0xd0
#define IEEE80211_STYPE_AUTH 0xb0
static long live=0;static bool failAlloc=false;
static void*IOMallocZero(size_t n){if(failAlloc)return nullptr;live++;return calloc(1,n);}
static void IOFree(void*p,size_t){live--;free(p);}
struct ieee80211_key_conf{uint32_t cipher;signed char keyidx;uint32_t flags;uint8_t keylen,iv_len,icv_len,hw_key_idx;uint8_t key[32];};
struct ieee80211_sta{int x;};
struct ieee80211_channel{uint32_t flags;uint16_t hw_value;int band;};
struct ieee80211_supported_band{int band;int n_channels;ieee80211_channel*channels;};
struct Wiphy{ieee80211_supported_band*bands[NL80211_NUM_BANDS];};
struct cfg80211_req{ieee80211_channel**channels;int n_channels;};
struct ieee80211_scan_request{cfg80211_req req;};
struct IOLock{int held;};
static void IOLockLock(IOLock*l){assert(!l->held);l->held=1;}
static void IOLockUnlock(IOLock*l){assert(l->held);l->held=0;}
struct Timer{int armed=0,cancels=0;void wakeAtTime(uint64_t){armed++;}void cancelTimeout(){cancels++;}void setTimeoutMS(int){armed++;}};
struct Ops{int(*hw_scan)(void*,void*,ieee80211_scan_request*);int(*set_key)(void*,int,void*,void*,ieee80211_key_conf*);};
struct HW{Ops*ops;Wiphy*wiphy;};
struct sk_buff{uint8_t*data;uint32_t len;uint32_t flag;};
struct rxinfo{uint32_t flag;};
static rxinfo*IEEE80211_SKB_RXCB(sk_buff*b){return (rxinfo*)&b->flag;}
static void skb_pull(sk_buff*b,uint32_t n){b->data+=n;b->len-=n;}
static void skb_trim(sk_buff*b,uint32_t n){if(b->len>n)b->len=n;}
static int bzeroCalls=0;
static void read_random(void*p,unsigned n){memset(p,0x5a,n);}
static bool decryptOk=true;static int decrypts=0;
static bool rtw88_ccmp_decrypt(const uint8_t*,const uint8_t*,uint32_t,uint64_t,uint8_t*,uint32_t,const uint8_t*){decrypts++;return decryptOk;}
static bool wpa3On=true,saeMixed=false;
static bool rtw88Wpa3Enabled(){return wpa3On;}
static bool preferSaeOnMixed(){return saeMixed;}
static int saeCommitRet=0,saeConfirmRet=0;
struct rtw88_sae{int x;};
static int rtw88_sae_rx_commit(rtw88_sae*,const uint8_t*,size_t){return saeCommitRet;}
static int rtw88_sae_rx_confirm(rtw88_sae*,const uint8_t*,size_t){return saeConfirmRet;}
static void rtw88_sae_keys(rtw88_sae*,uint8_t*pmk,uint8_t*id){memset(pmk,0x77,32);memset(id,1,16);}
static bool rtw88_hw_scan_supported(HW*){return true;}
static void clock_interval_to_deadline(uint32_t,uint32_t,uint64_t*d){*d=1;}
typedef int*thread_call_t;static int tcEnters=0;static void thread_call_enter(thread_call_t){tcEnters++;}
static const char*rtw88CipherName(uint32_t){return "x";}
enum Ev{kRTW88EventJoinFailed,kRTW88EventDisconnected};
static std::vector<std::string> reports;
struct Parent{void setLinkStatus(uint32_t){reports.push_back("link");}};
struct Delegate{void rtw88Event(int e,void*){reports.push_back(e==kRTW88EventJoinFailed?"failed":"disconnected");}};
struct RTW88BSS{RTW88BSS*next;uint32_t last_seen_scan;uint32_t akms;uint16_t rsn_caps;uint32_t cipher,group_cipher;uint8_t channel;uint8_t bssid[6];char ssid[33];uint32_t ssid_len;uint8_t ies[64];uint32_t ies_len;};
class RTW88IEEE80211{
public:
 static const uint32_t kSaeFrameMax=1024;
 static const uint8_t kCsaMinBeacons=2,kCsaQuietTicks=3;
 HW*_hw=nullptr;void*_vif=(void*)1;ieee80211_sta stay{};ieee80211_sta*_sta=&stay;Timer tm,monitor,failT;Timer*_timer=&tm,*_monitorTimer=&monitor,*_joinFailTimer=&failT;
 Parent parent;Parent*_parent=&parent;Delegate del;Delegate*_delegate=&del;
 RTW88State _state=RTW88_STATE_IDLE,_scanReturnState=RTW88_STATE_IDLE;
 bool _powered=true,_associatedVisible=false,_awdlOffChannel=false;
 uint8_t _awdlPreparedChannel=0;uint8_t _scanSsid[32]={},_scanSsidLen=0,_scanFilter[64]={};uint32_t _scanFilterCount=0,_scanSliceCursor=0;
 bool _scanWhileConnected=false,_scanSlice=false,_manualScanAbort=false,_manualScanOnHomeChannel=false,_manualScanFallbackLogged=false;
 IOLock lk{0};IOLock*_bssLock=&lk;RTW88BSS*_bssList=nullptr;uint32_t _scanGeneration=1;
 ieee80211_scan_request*_scanRequest=nullptr;ieee80211_channel*_scanRequestChannels[256]={};ieee80211_channel*_manualScanChannels[256]={};
 const char*_scanEngine="";uint32_t _lastScanChannelCount=0,_scanVisited2GHz=0,_scanVisited5GHz=0,_manualScanChannelCount=0,_rxFrameCount=0,_timeoutMs=0;thread_call_t _manualScanTC=nullptr;
 bool _mfp=false,_enterprise=false,_saeJoin=false,_saeFallbackAllowed=false,_mgmtRxPnValid=false,_saQueryPending=false,_assocRetryPending=false;
 uint8_t _keyVer=2,_ownRsnIE[32]={},_ownRsnLen=0,_ownRsnxe[3]={},_ownRsnxeLen=0,_assocComebacks=0;uint16_t _heldM1Len=0,_saQueryReason=0;uint64_t _mgmtRxPn=0,_saQueryStartMs=0;uint8_t _saQueryId[2]={};
 RTW88BSS _targetBSS{};uint8_t _macAddr[6]={2,0,0,0,0,1};
 ieee80211_key_conf*_ptkConf=nullptr,*_gtkConf=nullptr,*_retiredPtk=nullptr,*_retiredGtk=nullptr;
 uint8_t _pmk[32]={},_ptk[64]={},_gtk[32]={},_anonce[32]={},_snonce[32]={},_replayCtr[8]={},_installedM3ReplayCtr[8]={},_ccmpTxPn[6]={};char _password[65]={};
 bool _pmkProvided=false,_externalPTKInstalled=false,_externalGTKInstalled=false,_rxCcmpIvSkipLogged=false,_snonceValid=false,_m3KeysInstalled=false,_handshakePending=false;
 volatile uint64_t _lastApRxMs=0;uint64_t _lastProbeMs=0;volatile uint32_t _probeNoAcks=0;
 volatile uint8_t _csaChannel=0,_csaBeacons=0;uint8_t _csaQuietTicks=0;bool _csaLogged=false;
 volatile bool _joinFailPending=false,_connectCancelled=false;uint32_t _authAttempts=0;
 rtw88_sae sae{};rtw88_sae*_sae=&sae;bool _saeH2e=false,_saeConfirmSent=false;uint8_t _saeToken[128]={},_saeTokenLen=0;
 int saQueries=0,sends=0,associates=0,saeStarts=0,saeEnds=0,arms=0,nulls=0,txFrames=0;std::vector<std::string> lost;bool sendOk=true;
 void sendSaQuery(uint8_t,const uint8_t*){saQueries++;}
 void linkLost(uint16_t,const char*why){lost.push_back(why);_state=RTW88_STATE_IDLE;_associatedVisible=false;}
 void txNullFunc(bool,bool){nulls++;}
 bool saeSendAuth(){sends++;return sendOk;}bool saeStart(bool h){saeStarts++;_saeH2e=h;return true;}void saeEnd(){saeEnds++;_sae=nullptr;}void saeArmTimer(){arms++;}
 void doAssociate(){associates++;}bool buildAuthReq(uint8_t*,uint32_t*l){*l=30;return true;}bool txMgmtFrame(const uint8_t*,uint32_t){txFrames++;return true;}
 bool authenticationCancelled()const{return _connectCancelled;}
 void resetScanRequest();IOReturn cmdScan();IOReturn startScan();IOReturn cmdScanDirected(const uint8_t*,size_t,const uint8_t*,uint32_t,bool);
 void failJoin(const char*);void reportJoinFailure();
 void retireKey(ieee80211_key_conf**,ieee80211_key_conf**,ieee80211_sta*);void freeRetiredKey(ieee80211_key_conf**);void clearKeys();
 bool installKey(ieee80211_key_conf**,bool,uint8_t,uint32_t,const uint8_t*,uint8_t);
 void resetJoinSecurity();IOReturn prepareJoinSecurity(const char*,const uint8_t*,bool,bool);
 bool mgmtUnprotect(sk_buff*);bool mgmtFilterRx(sk_buff*);void noteApBeacon(const uint8_t*,uint32_t);void startLinkMonitor();void monitorTick();
 void saeRxFrame(const uint8_t*,uint32_t);bool saeFallBack(const char*);
};
''' + fn('enum {', sec) + ''';
static const uint16_t kRsnCapMfpr = 1u << 6, kRsnCapMfpc = 1u << 7;
''' + '\n'.join(fn(x, sec) for x in (
    'static uint16_t buildRsnIe(', 'static bool passphraseFitsWpa2(', 'void RTW88IEEE80211::resetJoinSecurity(',
    'IOReturn RTW88IEEE80211::prepareJoinSecurity(', 'static bool frameIsRobust(', 'bool RTW88IEEE80211::mgmtUnprotect(',
    'bool RTW88IEEE80211::mgmtFilterRx(', 'void RTW88IEEE80211::noteApBeacon(', 'void RTW88IEEE80211::startLinkMonitor(',
    'void RTW88IEEE80211::monitorTick(', 'void RTW88IEEE80211::saeRxFrame(', 'bool RTW88IEEE80211::saeFallBack(')
) + '\n' + '\n'.join(fn(x, ieee) for x in (
    'void RTW88IEEE80211::resetScanRequest(', 'IOReturn RTW88IEEE80211::cmdScan(', 'IOReturn RTW88IEEE80211::startScan(',
    'IOReturn RTW88IEEE80211::cmdScanDirected(', 'void RTW88IEEE80211::failJoin(', 'void RTW88IEEE80211::reportJoinFailure(',
    'void RTW88IEEE80211::retireKey(', 'void RTW88IEEE80211::freeRetiredKey(', 'void RTW88IEEE80211::clearKeys(',
    'bool RTW88IEEE80211::installKey(')
) + r'''
#include "RTW88AssocWire.hpp"
typedef RTW88IEEE80211 D;
static const uint8_t PMK[32]={9};
static int bwHits=0;
static int hwScanRet=0,hwScans=0,lastN=0;
static std::vector<uint16_t> lastChans;
static int hwScan(void*,void*,ieee80211_scan_request*r){hwScans++;lastN=r->req.n_channels;lastChans.clear();
 for(int i=0;i<lastN;i++)lastChans.push_back(r->req.channels[i]->hw_value);return hwScanRet;}
static int keySets=0,keyDisables=0;
static int setKey(void*,int cmd,void*,void*,ieee80211_key_conf*k){assert(k);(cmd==SET_KEY?keySets:keyDisables)++;return 0;}
static ieee80211_channel chans[39];static ieee80211_supported_band bandA{0,39,chans};static Wiphy wiphy{{&bandA,nullptr}};static Ops ops{hwScan,setKey};static HW hw{&ops,&wiphy};
static void radio(D&d){d._hw=&hw;for(int i=0;i<39;i++){chans[i].hw_value=i+1;chans[i].flags=0;}}
static void reqClean(D&d){assert(d._scanSsidLen==0&&d._scanFilterCount==0&&!d._scanWhileConnected&&!d._scanSlice);}
static void freeReq(D&d){if(d._scanRequest){IOFree(d._scanRequest,0);d._scanRequest=nullptr;}}
static void afterHwScan(D&d){d._state=RTW88_STATE_IDLE;d._scanReturnState=RTW88_STATE_IDLE;d.resetScanRequest();}

static void test_scan_failure_cleans(){
 const uint8_t only[2]={200,201},s[3]={'a','b','c'};
 auto again=[](D&d){hwScanRet=0;d._powered=true;ops.hw_scan=hwScan;lastN=0;assert(d.cmdScan()==kIOReturnSuccess);assert(lastN==39);afterHwScan(d);freeReq(d);};
 {D d;radio(d);assert(d.cmdScanDirected(s,3,only,2,false)==kIOReturnNotReady);reqClean(d);assert(d._state==RTW88_STATE_IDLE);again(d);} // n_chans==0
 {D d;radio(d);d._powered=false;assert(d.cmdScanDirected(s,3,only,2,false)==kIOReturnNotReady);reqClean(d);again(d);}     // not powered
 {D d;radio(d);failAlloc=true;assert(d.cmdScanDirected(s,3,only,1,false)==kIOReturnNoMemory);failAlloc=false;reqClean(d);again(d);}
 {D d;radio(d);hwScanRet=-5;const uint8_t one[1]={3};assert(d.cmdScanDirected(s,3,one,1,false)==kIOReturnError);reqClean(d);assert(d._state==RTW88_STATE_IDLE);again(d);}
 {D d;radio(d);Ops noScan{nullptr,setKey};HW h2{&noScan,&wiphy};d._hw=&h2;const uint8_t one[1]={3};assert(d.cmdScanDirected(s,3,one,1,false)==kIOReturnNotReady);reqClean(d);d._hw=&hw;again(d);} // no worker
 // Refused on a busy radio (joining): nothing kept.
 {D d;radio(d);d._state=RTW88_STATE_ASSOCIATING;assert(d.cmdScanDirected(s,3,only,2,false)==kIOReturnBusy);reqClean(d);}
 // A plain scan refused during a running directed one leaves that scan's request alone.
 {D d;radio(d);const uint8_t one[1]={3};assert(d.cmdScanDirected(s,3,one,1,false)==kIOReturnSuccess);d._state=RTW88_STATE_SCANNING;
  assert(d.cmdScan()==kIOReturnBusy);assert(d._scanSsidLen==3&&d._scanFilterCount==1);
  assert(d.cmdScanDirected(nullptr,0,nullptr,0,false)==kIOReturnBusy);assert(d._scanSsidLen==3);freeReq(d);}
}
static void test_scan_slices(){
 D d;radio(d);d._state=RTW88_STATE_CONNECTED;d._associatedVisible=true;
 // Connected: never more than eight, resuming where the last one stopped, also from a channel list.
 assert(d.cmdScanDirected(nullptr,0,nullptr,0,true)==kIOReturnSuccess);assert(lastN==8&&lastChans[0]==1&&lastChans[7]==8);
 afterHwScan(d);d._state=RTW88_STATE_CONNECTED;
 assert(d.cmdScanDirected(nullptr,0,nullptr,0,true)==kIOReturnSuccess);assert(lastN==8&&lastChans[0]==9);
 afterHwScan(d);d._state=RTW88_STATE_CONNECTED;
 uint8_t list[20];for(int i=0;i<20;i++)list[i]=(uint8_t)(i+1);
 assert(d.cmdScanDirected(nullptr,0,list,20,true)==kIOReturnSuccess);assert(lastN==8);
 afterHwScan(d);d._state=RTW88_STATE_CONNECTED;
 // Connected without cmdScanDirected: refused, as ever.
 assert(d.cmdScan()==kIOReturnBusy);reqClean(d);
 // Disconnected: the whole list, nothing cut.
 afterHwScan(d);uint8_t all[39];for(int i=0;i<39;i++)all[i]=(uint8_t)(i+1);
 assert(d.cmdScanDirected(nullptr,0,all,39,false)==kIOReturnSuccess);assert(lastN==39);
 afterHwScan(d);freeReq(d);
}
static void bss(D&d,uint32_t akms,uint16_t caps,uint32_t cipher=WLAN_CIPHER_SUITE_CCMP){d._targetBSS.akms=akms;d._targetBSS.rsn_caps=caps;d._targetBSS.cipher=cipher;d._targetBSS.group_cipher=WLAN_CIPHER_SUITE_CCMP;}
static void wpa2Unchanged(D&d){assert(d._ownRsnLen==0&&d._keyVer==2&&!d._mfp&&!d._saeJoin&&!d._enterprise);}
static void test_join_security(){
 const uint32_t P=1u<<kAkmPsk,S256=1u<<kAkmPskSha256,SAE=1u<<kAkmSae,X=1u<<kAkm8021X;const uint16_t C=kRsnCapMfpc,R=kRsnCapMfpr;
 std::string hex64(64,'a'),notHex64(64,'z');
 // The proven WPA2 path stays exactly as it was: PMK form and every valid passphrase.
 {D d;bss(d,P,0);assert(d.prepareJoinSecurity(nullptr,PMK,false,false)==0);wpa2Unchanged(d);
  for(const char*p:{"12345678","123456789012345678901234567890123456789012345678901234567890123"}){assert(d.prepareJoinSecurity(p,nullptr,false,false)==0);wpa2Unchanged(d);}
  assert(d.prepareJoinSecurity(hex64.c_str(),nullptr,false,false)==0);wpa2Unchanged(d);}
 // MFP capable but not required, on PSK: not used, nothing changes.
 {D d;bss(d,P,C);assert(d.prepareJoinSecurity(nullptr,PMK,false,false)==0);wpa2Unchanged(d);}
 // A mixed network with a good password stays on WPA2, as does one with a PMK.
 {D d;bss(d,P|SAE,C);assert(d.prepareJoinSecurity("goodpassword",nullptr,false,false)==0);wpa2Unchanged(d);assert(d.prepareJoinSecurity(nullptr,PMK,false,false)==0);wpa2Unchanged(d);}
 // Passwords WPA2 cannot use.
 {D d;bss(d,P,0);assert(d.prepareJoinSecurity("short",nullptr,false,false)==kIOReturnBadArgument);
  assert(d.prepareJoinSecurity(notHex64.c_str(),nullptr,false,false)==kIOReturnBadArgument);}
 // Short passwords: SAE, without a WPA2 fallback that could not work.
 {D d;bss(d,SAE,C|R);assert(d.prepareJoinSecurity("abc",nullptr,false,false)==0);assert(d._saeJoin&&!d._saeFallbackAllowed&&d._mfp&&d._keyVer==0&&d._ownRsnLen==22);}
 {D d;bss(d,P|SAE,C);assert(d.prepareJoinSecurity("abc",nullptr,false,false)==0);assert(d._saeJoin&&!d._saeFallbackAllowed);
  assert(d.prepareJoinSecurity("abc",nullptr,false,true)==kIOReturnBadArgument);}
 {D d;bss(d,P|SAE,C);wpa3On=false;assert(d.prepareJoinSecurity("abc",nullptr,false,false)==kIOReturnBadArgument);
  assert(d.prepareJoinSecurity("goodpassword",nullptr,false,false)==0);wpa2Unchanged(d);wpa3On=true;}
 {D d;bss(d,SAE,C|R);wpa3On=false;assert(d.prepareJoinSecurity("goodpassword",nullptr,false,false)==kIOReturnUnsupported);wpa3On=true;}
 // -rtl88saemixed: SAE with a fallback, which forcePsk then takes.
 {D d;bss(d,P|SAE,C);saeMixed=true;assert(d.prepareJoinSecurity("goodpassword",nullptr,false,false)==0);assert(d._saeJoin&&d._saeFallbackAllowed);
  assert(d.prepareJoinSecurity("goodpassword",nullptr,false,true)==0);wpa2Unchanged(d);saeMixed=false;}
 // PSK-SHA256.
 {D d;bss(d,S256,C);assert(d.prepareJoinSecurity(nullptr,PMK,false,false)==0);assert(d._keyVer==3&&d._mfp&&d._ownRsnLen==22&&d._ownRsnIE[19]==kAkmPskSha256);}
 {D d;bss(d,P|S256,C);assert(d.prepareJoinSecurity(nullptr,PMK,false,false)==0);wpa2Unchanged(d);}
 // PMF required with PSK: joined protected.
 {D d;bss(d,P,C|R);assert(d.prepareJoinSecurity(nullptr,PMK,false,false)==0);assert(d._mfp&&d._keyVer==2&&d._ownRsnLen==22);}
 // Required but not offered: refused.
 {D d;bss(d,P,R);assert(d.prepareJoinSecurity(nullptr,PMK,false,false)==kIOReturnUnsupported);}
 // 802.1X.
 {D d;bss(d,X,0);assert(d.prepareJoinSecurity(nullptr,nullptr,true,false)==0);assert(d._enterprise&&d._ownRsnLen==22&&d._ownRsnIE[19]==kAkm8021X&&!d._mfp);}
 {D d;bss(d,X,C|R);assert(d.prepareJoinSecurity(nullptr,nullptr,true,false)==kIOReturnUnsupported);}
 {D d;bss(d,P,0);assert(d.prepareJoinSecurity(nullptr,nullptr,true,false)==kIOReturnUnsupported);}
 // Nothing parsed, or no key: nothing changes for this join.
 {D d;bss(d,0,0,0);assert(d.prepareJoinSecurity(nullptr,nullptr,false,false)==0);wpa2Unchanged(d);}
 {D d;bss(d,P,0);assert(d.prepareJoinSecurity(nullptr,nullptr,false,false)==0);wpa2Unchanged(d);}
 // Only SAE offered and only a PMK given: no way to use it.
 {D d;bss(d,SAE,C|R);assert(d.prepareJoinSecurity(nullptr,PMK,false,false)==kIOReturnUnsupported);}
}
typedef std::vector<uint8_t> V;
static const uint8_t AP[6]={2,0,0,0,0,9},ME[6]={2,0,0,0,0,1};
static sk_buff*frame(uint8_t fc0,uint8_t fc1,const V&body,const uint8_t*a1=ME,const uint8_t*a2=AP,uint32_t flag=0){
 V f(24,0);f[0]=fc0;f[1]=fc1;memcpy(&f[4],a1,6);memcpy(&f[10],a2,6);memcpy(&f[16],AP,6);f.insert(f.end(),body.begin(),body.end());
 auto*b=new sk_buff;b->len=f.size();b->data=(uint8_t*)malloc(f.size());memcpy(b->data,f.data(),f.size());b->flag=flag;return b;}
struct Own{sk_buff*b;uint8_t*orig;Own(sk_buff*x):b(x),orig(x->data){}~Own(){free(orig);delete b;}};
static V ccmpBody(uint64_t pn,V plain,bool ext=true){V v{(uint8_t)pn,(uint8_t)(pn>>8),0,(uint8_t)(ext?0x20:0),(uint8_t)(pn>>16),(uint8_t)(pn>>24),(uint8_t)(pn>>32),(uint8_t)(pn>>40)};v.insert(v.end(),plain.begin(),plain.end());v.insert(v.end(),8,0xee);return v;}
static ieee80211_key_conf demoKey{};
static void mfp(D&d){d._mfp=true;d._ptkConf=&demoKey;memcpy(d._targetBSS.bssid,AP,6);}
static void test_mgmt(){
 const uint8_t DEAUTH=0xc0,DISASSOC=0xa0,ACTION=0xd0;
 // Without PMF everything goes through untouched.
 {D d;Own o(frame(DEAUTH,0,{3,0}));assert(d.mgmtFilterRx(o.b));}
 // Unprotected leave under PMF: not believed; the AP is asked, once; the reason is kept.
 {D d;mfp(d);nowMs=5000;Own o(frame(DEAUTH,0,{7,1}));assert(!d.mgmtFilterRx(o.b));assert(d._saQueryPending&&d.saQueries==1&&d._saQueryReason==0x107&&d._saQueryStartMs==5000);
  Own p(frame(DISASSOC,0,{3,0}));assert(!d.mgmtFilterRx(p.b));assert(d.saQueries==1);}
 // Not from our AP, or not to us (broadcast forged deauth): dropped without a query.
 {D d;mfp(d);const uint8_t other[6]={2,9,9,9,9,9},bc[6]={255,255,255,255,255,255};
  Own o(frame(DEAUTH,0,{3,0},ME,other));assert(!d.mgmtFilterRx(o.b));Own p(frame(DEAUTH,0,{3,0},bc));assert(!d.mgmtFilterRx(p.b));assert(d.saQueries==0&&!d._saQueryPending);}
 // Action categories: public and vendor pass; SA Query and protected vendor must be protected.
 {D d;mfp(d);for(uint8_t c:{4,7,11,15,20,21,127}){Own o(frame(ACTION,0,{c,0}));assert(d.mgmtFilterRx(o.b));}
  for(uint8_t c:{0,3,8,126}){Own o(frame(ACTION,0,{c,0}));assert(!d.mgmtFilterRx(o.b));}
  // Top bit set (an error return of the category): not robust, whatever the category.
  for(uint8_t c:{0x84,0x88}){Own e(frame(ACTION,0,{c,0}));assert(d.mgmtFilterRx(e.b));}}
 // Protected frames: header and MIC removed, frame plain, PN advances, replay refused.
 {D d;mfp(d);decryptOk=true;int d0=decrypts;Own o(frame(DEAUTH,0x40,ccmpBody(10,{3,0})));assert(d.mgmtFilterRx(o.b));
  assert(o.b->len==26&&o.b->data[24]==3&&!(o.b->data[1]&0x40)&&!memcmp(o.b->data+4,ME,6)&&d._mgmtRxPn==10&&d._mgmtRxPnValid&&decrypts==d0+1);
  Own r(frame(DEAUTH,0x40,ccmpBody(10,{3,0})));assert(!d.mgmtFilterRx(r.b));Own r2(frame(DEAUTH,0x40,ccmpBody(9,{3,0})));assert(!d.mgmtFilterRx(r2.b));assert(d._mgmtRxPn==10);
  // Hardware already decrypted: no second decrypt.
  d0=decrypts;Own hwd(frame(DEAUTH,0x40,ccmpBody(11,{3,0}),ME,AP,RX_FLAG_DECRYPTED));assert(d.mgmtFilterRx(hwd.b));assert(decrypts==d0&&d._mgmtRxPn==11);
  // Failed MIC does not advance the PN: a forgery cannot block the real frame.
  decryptOk=false;Own bad(frame(DEAUTH,0x40,ccmpBody(500,{3,0})));assert(!d.mgmtFilterRx(bad.b));assert(d._mgmtRxPn==11);decryptOk=true;
  // No Ext IV, and too short.
  Own noext(frame(DEAUTH,0x40,ccmpBody(600,{3,0},false)));assert(!d.mgmtFilterRx(noext.b));Own shortf(frame(DEAUTH,0x40,{1,2,3}));assert(!d.mgmtFilterRx(shortf.b));}
 // No key yet: passes through to the plain handling.
 {D d;d._mfp=true;Own o(frame(DEAUTH,0,{3,0}));assert(d.mgmtFilterRx(o.b));}
}
static V csa(uint8_t ch){return V{37,3,1,ch,5};}
static V plainIes(){return V{0,1,'x',3,1,36};}
static void connected(D&d){d._state=RTW88_STATE_CONNECTED;d._associatedVisible=true;d._targetBSS.channel=36;d.startLinkMonitor();}
static void beacon(D&d,const V&v){d.noteApBeacon(v.data(),(uint32_t)v.size());}
static void tick(D&d,int n=1){for(int i=0;i<n&&d.lost.empty();i++){nowMs+=1000;d.monitorTick();}}
static void test_link_monitor(){
 // One forged beacon, nothing heard afterwards: no leaving on it.
 {D d;connected(d);beacon(d,csa(44));tick(d,6);assert(d.lost.empty());}
 // Forged twice while the real AP goes on beaconing: a plain beacon ends it.
 {D d;connected(d);beacon(d,csa(44));beacon(d,csa(44));d._lastApRxMs=nowMs;beacon(d,plainIes());tick(d,6);assert(d.lost.empty()&&d._csaBeacons==0);}
 // Announcements repeated but frames still arriving: not gone.
 {D d;connected(d);for(int i=0;i<10;i++){beacon(d,csa(44));beacon(d,csa(44));d._lastApRxMs=nowMs+1000;tick(d);}assert(d.lost.empty());}
 // Two beacons naming different channels do not add up.
 {D d;connected(d);beacon(d,csa(44));beacon(d,csa(48));tick(d,6);assert(d.lost.empty());}
 // The current channel, channel 0 and a cut-off element are not announcements.
 {D d;connected(d);beacon(d,csa(36));beacon(d,csa(36));beacon(d,csa(0));beacon(d,csa(0));V cut{37,3,1};beacon(d,cut);beacon(d,cut);V sh{37,2,1,44};beacon(d,sh);beacon(d,sh);tick(d,6);assert(d.lost.empty());}
 // The real thing: repeated, then the AP is gone from this channel.
 {D d;connected(d);beacon(d,csa(44));beacon(d,csa(44));d._lastApRxMs=nowMs;tick(d,2);assert(d.lost.empty());tick(d,2);assert(d.lost.size()==1&&d.lost[0]=="AP changed channel");}
 // Only ticks at home count: scanning and AWDL windows add nothing.
 {D d;connected(d);beacon(d,csa(44));beacon(d,csa(44));d._state=RTW88_STATE_SCANNING;tick(d,10);assert(d.lost.empty());
  d._state=RTW88_STATE_CONNECTED;d._awdlOffChannel=true;tick(d,10);assert(d.lost.empty());d._awdlOffChannel=false;
  d._lastApRxMs=nowMs+1000;tick(d);assert(d._csaQuietTicks==0);}
 // A new link forgets all of it.
 {D d;connected(d);beacon(d,csa(44));beacon(d,csa(44));connected(d);assert(!d._csaBeacons&&!d._csaChannel);tick(d,6);assert(d.lost.empty());}
 // Other reasons to leave still work: SA Query unanswered; AP unanswering, which needs real non-ACKs.
 {D d;connected(d);d._saQueryPending=true;d._saQueryStartMs=nowMs;d._saQueryReason=7;tick(d,2);assert(d.lost.size()==1&&d.lost[0]=="no answer to the SA Query");}
 {D d;connected(d);tick(d,30);assert(d.lost.empty()&&d.nulls>0);d._probeNoAcks=3;tick(d);assert(d.lost.size()==1);}
 // Off or not associated: stops without re-arming.
 {D d;connected(d);d._powered=false;int a=d.monitor.armed;tick(d);assert(d.monitor.armed==a);}
}
static void test_join_failure_report(){
 // The worker reports nothing itself; the RX workloop does, once, ASSOC_DONE before LINK_CHANGED.
 {D d;reports.clear();d._state=RTW88_STATE_AUTHENTICATING;d._associatedVisible=true;d.failJoin("x");
  assert(d._state==RTW88_STATE_IDLE&&!d._associatedVisible&&d._connectCancelled&&d.tm.cancels==1&&d.failT.armed==1&&reports.empty());
  d.reportJoinFailure();assert((reports==std::vector<std::string>{"link","failed","disconnected"}));
  d.reportJoinFailure();assert(reports.size()==3);}
 // A newer join or a disconnect got there first (they clear the flag): silent.
 {D d;reports.clear();d.failJoin("x");d._joinFailPending=false;d.reportJoinFailure();assert(reports.empty());}
}
static void key(D&d,ieee80211_key_conf**slot,bool pair,uint8_t b){uint8_t k[16];memset(k,b,16);assert(d.installKey(slot,pair,pair?0:1,WLAN_CIPHER_SUITE_CCMP,k,16));}
static void test_keys(){
 long l0=live;keySets=keyDisables=0;
 D d;d._hw=&hw;key(d,&d._ptkConf,true,1);key(d,&d._gtkConf,false,2);assert(keySets==2&&live==l0+2);
 // A frame being built holds this pointer across teardown.
 ieee80211_key_conf*held=d._ptkConf;
 d.clearKeys();assert(!d._ptkConf&&!d._gtkConf&&keyDisables==2);
 assert(held->key[0]==1&&held->keyidx==0);        // readable and intact: not a zero key on the air
 // A second teardown (deauth and monitor both) finds nothing to do.
 d.clearKeys();assert(keyDisables==2&&live==l0+2);
 // The next install uses the same memory: no allocation, and old material is gone.
 key(d,&d._ptkConf,true,3);assert(d._ptkConf==held&&held->key[0]==3&&!d._retiredPtk&&live==l0+2);
 // Rekey: same bytes keep packet numbers and touch nothing; new bytes go through retire.
 int s=keySets;d._ccmpTxPn[0]=9;key(d,&d._ptkConf,true,3);assert(keySets==s&&d._ccmpTxPn[0]==9);
 key(d,&d._ptkConf,true,4);assert(keySets==s+1&&d._ptkConf==held&&held->key[0]==4&&!d._retiredPtk&&d._ccmpTxPn[0]==0&&live==l0+2);
 // Powered off: slots still empty, hardware left alone.
 int k=keyDisables;d._powered=false;d.clearKeys();assert(keyDisables==k&&!d._ptkConf);
 d.freeRetiredKey(&d._retiredPtk);d.freeRetiredKey(&d._retiredGtk);assert(!d._retiredPtk&&live==l0);d.freeRetiredKey(&d._retiredPtk);
}
static V saeFrame(uint16_t txn,uint16_t st,V body){V f(30,0);f[24]=3;f[26]=(uint8_t)txn;f[27]=(uint8_t)(txn>>8);f[28]=(uint8_t)st;f[29]=(uint8_t)(st>>8);f.insert(f.end(),body.begin(),body.end());return f;}
static void rx(D&d,const V&f){d.saeRxFrame(f.data(),(uint32_t)f.size());}
static void saeJoin(D&d){d._state=RTW88_STATE_AUTHENTICATING;d._saeJoin=true;}
static bool failed(D&d){return d._joinFailPending;}
static void test_sae_frames(){
 const uint16_t T=kStatusAntiClog,H=kStatusSaeH2e;
 // Commit, confirm, associate.
 {D d;saeJoin(d);saeCommitRet=saeConfirmRet=0;rx(d,saeFrame(1,0,{1,2,3}));assert(d._saeConfirmSent&&d.sends==1&&d.arms==1);rx(d,saeFrame(2,0,{1,2}));
  assert(d.associates==1&&d._pmkProvided&&d._pmk[0]==0x77&&d.saeEnds==1&&!failed(d));}
 // Confirm before commit, other transactions, wrong state, cancelled: ignored.
 {D d;saeJoin(d);rx(d,saeFrame(2,0,{}));rx(d,saeFrame(3,0,{}));assert(d.associates==0&&!failed(d));}
 {D d;saeJoin(d);d._state=RTW88_STATE_ASSOCIATING;rx(d,saeFrame(1,0,{}));assert(d.sends==0&&!failed(d));}
 {D d;saeJoin(d);d._connectCancelled=true;rx(d,saeFrame(1,0,{}));assert(d.sends==0);}
 {D d;saeJoin(d);d._sae=nullptr;rx(d,saeFrame(1,0,{}));assert(d.sends==0);}
 // Wrong password, refused confirm: failed, no fallback, no association.
 {D d;saeJoin(d);d._saeFallbackAllowed=true;saeConfirmRet=-1;rx(d,saeFrame(1,0,{}));rx(d,saeFrame(2,0,{}));assert(failed(d)&&d.associates==0&&d.txFrames==0);saeConfirmRet=0;}
 {D d;saeJoin(d);rx(d,saeFrame(1,0,{}));rx(d,saeFrame(2,1,{}));assert(failed(d)&&d.associates==0);}
 // Refused or bad commit: fall back when allowed, otherwise failed.
 {D d;saeJoin(d);rx(d,saeFrame(1,1,{}));assert(failed(d));}
 {D d;saeJoin(d);saeCommitRet=-1;rx(d,saeFrame(1,0,{}));assert(failed(d)&&!d._saeConfirmSent);saeCommitRet=0;}
 {D d;saeJoin(d);d._saeFallbackAllowed=true;d._targetBSS.akms=(1u<<kAkmPsk)|(1u<<kAkmSae);d._targetBSS.cipher=WLAN_CIPHER_SUITE_CCMP;strcpy(d._password,"goodpassword");
  rx(d,saeFrame(1,1,{}));assert(!failed(d)&&d.txFrames==1&&!d._saeJoin&&d.saeEnds==1);}
 // A short password has no fallback to fall to, even if the flag somehow says so.
 {D d;saeJoin(d);d._saeFallbackAllowed=true;d._targetBSS.akms=(1u<<kAkmPsk)|(1u<<kAkmSae);d._targetBSS.cipher=WLAN_CIPHER_SUITE_CCMP;strcpy(d._password,"abc");
  rx(d,saeFrame(1,1,{}));assert(failed(d)&&d.txFrames==0);}
 // Anti-clogging: token kept, resent; oversize and short bodies ignored; H2E container unwrapped.
 {D d;saeJoin(d);rx(d,saeFrame(1,T,{19,0,0xaa,0xbb}));assert(d._saeTokenLen==2&&d._saeToken[0]==0xaa&&d.sends==1&&d._authAttempts==0);}
 {D d;saeJoin(d);rx(d,saeFrame(1,T,{19}));assert(d.sends==0);V big(200,1);rx(d,saeFrame(1,T,big));assert(d.sends==0);}
 {D d;saeJoin(d);d._saeH2e=true;rx(d,saeFrame(1,T,{19,0,kEidExtension,3,kEidExtAntiClog,0xcc,0xdd}));assert(d._saeTokenLen==2&&d._saeToken[0]==0xcc);}
 // The AP wants H2E: started over with it; after that status H2E is the good one.
 {D d;saeJoin(d);rx(d,saeFrame(1,H,{}));assert(d.saeStarts==1&&d._saeH2e&&d.sends==1&&!failed(d));rx(d,saeFrame(1,H,{}));assert(d._saeConfirmSent);rx(d,saeFrame(1,0,{}));assert(failed(d));}
 // Send failure: failed.
 {D d;saeJoin(d);d.sendOk=false;rx(d,saeFrame(1,0,{}));assert(failed(d));}
}
static void put32(V&v,size_t at,uint32_t x){for(int i=0;i<4;i++)v[at+i]=(uint8_t)(x>>(8*i));}
static V wire(uint32_t upper,uint32_t keyLen,uint32_t cipher,uint32_t keyVer=1){V p(RTW88AssocWire::PrefixSize,0);put32(p,0,1);put32(p,4,2);put32(p,8,1);put32(p,12,upper);put32(p,16,4);memcpy(&p[20],"home",4);put32(p,60,keyVer);put32(p,64,keyLen);put32(p,68,cipher);
 for(uint32_t i=0;i<keyLen&&i<64;i++)p[76+i]='k';return p;}
static bool dec(const V&p,RTW88AssocWire::Personal*o=nullptr){RTW88AssocWire::Personal x{};bool r=RTW88AssocWire::decode(p.data(),p.size(),x);if(o)*o=x;return r;}
static void test_wire(){
 using namespace RTW88AssocWire;const uint32_t PASS=CipherPassphrase;
 // What 1.0.1 sees on the user's network: exactly as before.
 {Personal o;assert(dec(wire(8,32,6),&o));assert(o.upper==8&&o.keyLength==32&&o.cipher==6&&o.ssidLength==4&&o.mode==2&&o.lower==1&&o.key[0]=='k');}
 assert(!dec(wire(8,31,6))&&!dec(wire(8,33,6))&&!dec(wire(8,0,6)));
 // Open, including no key version.
 assert(dec(wire(0,0,0))&&dec(wire(0,0,0,0))&&!dec(wire(0,1,0))&&!dec(wire(8,32,6,0))&&!dec(wire(0,0,0,2)));
 // Passphrase lengths.
 for(uint32_t u:{8u,0x80u,0x88u,0x1000u,0x200u,0x1008u,0x1080u,0x1088u,0x208u}){
  assert(!dec(wire(u,0,PASS)));assert(dec(wire(u,1,PASS)));assert(dec(wire(u,7,PASS)));assert(dec(wire(u,8,PASS)));assert(dec(wire(u,63,PASS)));assert(dec(wire(u,64,PASS)));assert(!dec(wire(u,65,PASS)));}
 // SHA256-PSK with a master key; SAE never with one.
 for(uint32_t u:{0x80u,0x88u})assert(dec(wire(u,32,6))&&!dec(wire(u,16,6)));
 for(uint32_t u:{0x1000u,0x1080u,0x1008u,0x200u})assert(!dec(wire(u,32,6)));
 // Enterprise: no key; not when mixed with personal.
 for(uint32_t u:{1u,4u,0x20u,0x100u,0x24u})assert(isEnterprise(u)&&dec(wire(u,0,0))&&!dec(wire(u,32,6)));
 for(uint32_t u:{0x88u,0x80u,8u,0x1000u,0x104u})assert(!isEnterprise(u)||u==0x104);
 // Anything else is not understood: WPA-PSK alone or mixed, unknown bits.
 for(uint32_t u:{2u,0xau,0x82u,0x10u,0x40u,0x400u,0x1002u,0x1010u,0x4000u,0x80000000u})assert(!dec(wire(u,32,6))&&!dec(wire(u,8,PASS)));
 // Shape.
 {V p=wire(8,32,6);assert(!RTW88AssocWire::decode(p.data(),p.size()-1,*new(alloca(sizeof(Personal)))Personal));
  put32(p,16,0);assert(!dec(p));put32(p,16,33);assert(!dec(p));put32(p,16,4);p[21]=0;assert(!dec(p));p[21]='o';p[52]=1;assert(!dec(p));p[52]=2;assert(dec(p));put32(p,0,2);assert(!dec(p));}
}
int main(){
 test_scan_failure_cleans();test_scan_slices();test_join_security();test_mgmt();test_link_monitor();test_join_failure_report();test_keys();test_sae_frames();test_wire();
 assert(live==0);
 puts("PASS: scan start failures leave nothing, slices capped while connected and not when disconnected; join security incl. unchanged WPA2 path and short passwords; PMF filter and unprotect; link monitor and CSA corroboration; deferred failed-join report; key retire; SAE frames; association wire forms");
}
'''

# handleCIPHER_KEY, handleSCAN_REQ and startScanRequest against a mock backend.
CONTROLLER = COMMON + r'''
#define APPLE80211_VERSION 1
#define APPLE80211_KEY_BUFF_LEN 32
#define APPLE80211_MAX_SSID_LEN 32
#define APPLE80211_MAX_CHANNELS 64
#define WLAN_CIPHER_SUITE_CCMP 0x000fac04
#define WLAN_CIPHER_SUITE_TKIP 0x000fac02
#define kOSBooleanTrue 1
#define kOSBooleanFalse 0
typedef uint32_t UInt32;
enum {APPLE80211_CIPHER_NONE=0,APPLE80211_CIPHER_TKIP=3,APPLE80211_CIPHER_AES_CCM=5,APPLE80211_CIPHER_PMK=6,APPLE80211_CIPHER_PMKSA=7};
enum {APPLE80211_M_SCAN_DONE=1,APPLE80211_M_RSN_HANDSHAKE_DONE=2};
struct apple80211_key{uint32_t version,key_len,key_cipher_type;uint16_t key_flags,key_index;uint8_t key[APPLE80211_KEY_BUFF_LEN];uint8_t tail[64];};
struct chan{uint32_t version,channel,flags;};
struct apple80211_scan_data{uint32_t version,ssid_len;uint8_t ssid[32];uint32_t num_channels;chan channels[APPLE80211_MAX_CHANNELS];};
struct RTW88StateResult{unsigned state;};
struct Mock{
 unsigned raw=RTW88_STATE_IDLE;IOReturn pmkRet=0,keyRet=0,scanRet=0;int pmks=0,plain=0,directed=0;uint8_t pmk[32];
 struct{bool pair;uint8_t idx;uint32_t cipher;uint8_t len;}lastKey{};int keys=0;
 const uint8_t*ssid=nullptr;size_t ssidLen=0;uint32_t nChannels=0;uint8_t chans[64];bool slice=false;
 IOReturn cmdSetEnterprisePMK(const uint8_t*k,size_t n){pmks++;assert(n==32);memcpy(pmk,k,32);return pmkRet;}
 IOReturn cmdInstallExternalKey(bool p,uint8_t i,uint32_t c,const uint8_t*,uint8_t l){keys++;lastKey={p,i,c,l};return keyRet;}
 unsigned rawState()const{return raw;}bool associatedVisible()const{return raw==RTW88_STATE_CONNECTED;}bool externalKeysReady()const{return false;}
 IOReturn cmdGetState(RTW88StateResult*s){s->state=raw;return 0;}
 IOReturn cmdScan(){plain++;return scanRet;}
 IOReturn cmdScanDirected(const uint8_t*s,size_t n,const uint8_t*c,uint32_t nc,bool sl){directed++;ssid=s;ssidLen=n;nChannels=nc;if(nc)memcpy(chans,c,nc);slice=sl;return scanRet;}
};
struct Netif{std::vector<int> posted;void postMessage(int m,void* =nullptr,size_t=0){posted.push_back(m);}};
static bool bgEnabled=true;
static bool backgroundScansEnabled(){return bgEnabled;}
class RTL88WiFi{
public:
 Mock m;Mock*_ieee80211=&m;Netif n;Netif*_netif=&n;bool _rsnHandshakeReported=false,_scanInProgress=false;uint32_t _scanCursor=9;uint64_t _lastBgScanMs=0,_lastNamedScanMs=0;
 template<class...A>void setProperty(A...){}
 IOReturn handleCIPHER_KEY(apple80211_key*);IOReturn handleSCAN_REQ(void*);IOReturn startScanRequest(const uint8_t*,size_t,const uint8_t*,uint32_t);
};
''' + '\n'.join(fn(x, wifi) for x in (
    'IOReturn RTL88WiFi::handleCIPHER_KEY(', 'IOReturn RTL88WiFi::handleSCAN_REQ(', 'IOReturn RTL88WiFi::startScanRequest(')
) + r'''
static apple80211_key K(uint32_t type,uint32_t len,uint16_t flags=0){apple80211_key k{};k.version=APPLE80211_VERSION;k.key_len=len;k.key_cipher_type=type;k.key_flags=flags;memset(k.key,0xab,sizeof(k.key));return k;}
static int count(RTL88WiFi&w,int msg){int c=0;for(int x:w.n.posted)c+=x==msg;return c;}
static void test_cipher_key(){
 RTL88WiFi w;apple80211_key k=K(APPLE80211_CIPHER_PMK,32);
 assert(w.handleCIPHER_KEY(nullptr)==kIOReturnBadArgument);k.version=2;assert(w.handleCIPHER_KEY(&k)==kIOReturnBadArgument);k.version=1;
 // PMK and whole master session key reach the handshake as 32 bytes.
 assert(w.handleCIPHER_KEY(&k)==0&&w.m.pmks==1&&w.m.pmk[0]==0xab);k=K(9,64);assert(w.handleCIPHER_KEY(&k)==0&&w.m.pmks==2);
 // No key: forget; wrong sizes refused without touching the backend.
 k=K(APPLE80211_CIPHER_PMK,0);assert(w.handleCIPHER_KEY(&k)==0&&w.m.pmks==2);
 k=K(APPLE80211_CIPHER_PMK,31);assert(w.handleCIPHER_KEY(&k)==kIOReturnBadArgument);k=K(9,65);assert(w.handleCIPHER_KEY(&k)==kIOReturnBadArgument);assert(w.m.pmks==2);
 // Not on 802.1X: harmless. Real errors pass up.
 w.m.pmkRet=kIOReturnNotReady;k=K(APPLE80211_CIPHER_PMK,32);assert(w.handleCIPHER_KEY(&k)==0);w.m.pmkRet=kIOReturnBadArgument;assert(w.handleCIPHER_KEY(&k)==kIOReturnBadArgument);w.m.pmkRet=0;
 k=K(APPLE80211_CIPHER_PMKSA,16);assert(w.handleCIPHER_KEY(&k)==0);k=K(APPLE80211_CIPHER_NONE,0);assert(w.handleCIPHER_KEY(&k)==0);
 k=K(APPLE80211_CIPHER_AES_CCM,33);assert(w.handleCIPHER_KEY(&k)==kIOReturnBadArgument);
 // Traffic keys: flags 4 pairwise, 0 group; each posts handshake-done.
 assert(w.m.keys==0&&count(w,APPLE80211_M_RSN_HANDSHAKE_DONE)==0);
 k=K(APPLE80211_CIPHER_AES_CCM,16,4);assert(w.handleCIPHER_KEY(&k)==0&&w.m.lastKey.pair&&w.m.lastKey.cipher==WLAN_CIPHER_SUITE_CCMP&&count(w,APPLE80211_M_RSN_HANDSHAKE_DONE)==1&&w._rsnHandshakeReported);
 k=K(APPLE80211_CIPHER_TKIP,32,0);k.key_index=2;assert(w.handleCIPHER_KEY(&k)==0&&!w.m.lastKey.pair&&w.m.lastKey.idx==2&&w.m.lastKey.cipher==WLAN_CIPHER_SUITE_TKIP&&count(w,APPLE80211_M_RSN_HANDSHAKE_DONE)==2);
 k=K(APPLE80211_CIPHER_AES_CCM,16,1);assert(w.handleCIPHER_KEY(&k)==kIOReturnUnsupported);k=K(4,16,4);assert(w.handleCIPHER_KEY(&k)==kIOReturnUnsupported);
 w.m.keyRet=kIOReturnNotReady;k=K(APPLE80211_CIPHER_AES_CCM,16,4);assert(w.handleCIPHER_KEY(&k)==kIOReturnNotReady&&count(w,APPLE80211_M_RSN_HANDSHAKE_DONE)==2);
}
static apple80211_scan_data req(const char*ssid,uint32_t channels){apple80211_scan_data d{};d.version=APPLE80211_VERSION;d.ssid_len=ssid?(uint32_t)strlen(ssid):0;if(ssid)memcpy(d.ssid,ssid,d.ssid_len);d.num_channels=channels;for(uint32_t i=0;i<channels;i++)d.channels[i].channel=i+1;return d;}
static void test_scan_requests(){
 // Disconnected: the whole list goes through, not sliced, unlimited; open-ended uses plain cmdScan.
 {RTL88WiFi w;auto d=req(nullptr,39);assert(w.handleSCAN_REQ(&d)==0&&w.m.directed==1&&w.m.nChannels==39&&w.m.chans[38]==39&&!w.m.slice&&w._scanInProgress);
  w._scanInProgress=false;d=req(nullptr,64);assert(w.handleSCAN_REQ(&d)==0&&w.m.directed==2&&w.m.nChannels==64);w._scanInProgress=false;
  d=req("net",0);assert(w.handleSCAN_REQ(&d)==0&&w.m.directed==3&&w.m.ssidLen==3);w._scanInProgress=false;
  d=req(nullptr,0);assert(w.handleSCAN_REQ(&d)==0&&w.m.plain==1);w._scanInProgress=false;
  assert(w.n.posted.empty());}
 // Bad requests; one while scanning coalesced.
 {RTL88WiFi w;auto d=req(nullptr,1);d.version=9;assert(w.handleSCAN_REQ(&d)==kIOReturnBadArgument);d=req(nullptr,1);d.ssid_len=33;assert(w.handleSCAN_REQ(&d)==kIOReturnBadArgument);d=req(nullptr,1);d.num_channels=65;assert(w.handleSCAN_REQ(&d)==kIOReturnBadArgument);assert(w.handleSCAN_REQ(nullptr)==kIOReturnBadArgument);
  d=req(nullptr,1);w._scanInProgress=true;assert(w.handleSCAN_REQ(&d)==0&&w.m.directed==0);}
 // Invalid channel numbers do not reach the radio.
 {RTL88WiFi w;auto d=req(nullptr,3);d.channels[1].channel=0;d.channels[2].channel=197;assert(w.handleSCAN_REQ(&d)==0&&w.m.nChannels==1);}
 // Connected: sliced, and the limit includes lists.
 {RTL88WiFi w;w.m.raw=RTW88_STATE_CONNECTED;nowMs=1000000;auto list=req(nullptr,16),open=req(nullptr,0);
  assert(w.handleSCAN_REQ(&list)==0&&w.m.directed==1&&w.m.slice&&w.m.nChannels==16);w._scanInProgress=false;
  // Within 30 s a list is answered from the cache, as is an open-ended scan.
  nowMs+=29000;assert(w.handleSCAN_REQ(&list)==0&&w.m.directed==1&&count(w,APPLE80211_M_SCAN_DONE)==1&&w._scanCursor==0);assert(w.handleSCAN_REQ(&open)==0&&w.m.directed==1&&count(w,APPLE80211_M_SCAN_DONE)==2);
  assert(!w._scanInProgress);nowMs+=1000;assert(w.handleSCAN_REQ(&open)==0&&w.m.directed==2&&w.m.slice);w._scanInProgress=false;
  // Naming a network: its own 10 s limit, sliced too, and it does not use up the other.
  auto net=req("phone",0);nowMs+=1000;assert(w.handleSCAN_REQ(&net)==0&&w.m.directed==3&&w.m.ssidLen==5&&w.m.slice);w._scanInProgress=false;
  nowMs+=9000;assert(w.handleSCAN_REQ(&net)==0&&w.m.directed==3);nowMs+=1000;assert(w.handleSCAN_REQ(&net)==0&&w.m.directed==4);w._scanInProgress=false;
  assert(w.m.plain==0);}
 // -rtl88nobgscan: nothing at all while connected, which README promises; disconnected unaffected.
 {RTL88WiFi w;bgEnabled=false;w.m.raw=RTW88_STATE_CONNECTED;nowMs+=100000;auto list=req(nullptr,4),net=req("phone",1),open=req(nullptr,0);
  for(auto*d:{&list,&net,&open})assert(w.handleSCAN_REQ(d)==0);assert(w.m.directed==0&&w.m.plain==0&&count(w,APPLE80211_M_SCAN_DONE)==3&&!w._scanInProgress);
  w.m.raw=RTW88_STATE_IDLE;assert(w.handleSCAN_REQ(&list)==0&&w.m.directed==1);bgEnabled=true;}
 // Connected but scanning already: cache. A busy radio while connected: also cache, in-progress cleared.
 {RTL88WiFi w;w.m.raw=RTW88_STATE_CONNECTED;nowMs+=100000;w.m.scanRet=kIOReturnBusy;auto o=req(nullptr,0);assert(w.handleSCAN_REQ(&o)==0&&!w._scanInProgress&&count(w,APPLE80211_M_SCAN_DONE)==1);}
 // Failure when disconnected goes back to the caller.
 {RTL88WiFi w;w.m.scanRet=kIOReturnNotReady;auto o=req(nullptr,0);assert(w.handleSCAN_REQ(&o)==kIOReturnNotReady&&!w._scanInProgress);}
}
int main(){test_cipher_key();test_scan_requests();puts("PASS: handleCIPHER_KEY forms and sizes; SCAN_REQ lists uncut when disconnected, connected scans sliced and rate limited including lists, -rtl88nobgscan means none");}
'''

SOURCE_CHECKS = [
    # The failing thread must never wait for the gate; the RX workloop reports.
    ('failJoin does not touch the gate', '->setLinkStatus' not in fn('void RTW88IEEE80211::failJoin(', ieee)),
    ('failJoin does not post', 'rtw88Event' not in fn('void RTW88IEEE80211::failJoin(', ieee)),
    ('a new join clears a pending report', '_joinFailPending, false' in fn('IOReturn RTW88IEEE80211::cmdConnect(', ieee)),
    ('a disconnect clears a pending report', '_joinFailPending, false' in fn('void RTW88IEEE80211::cancelAuthentication(', ieee)),
    ('monitor timer is on the RX workloop in both init paths',
     ieee.count('rxwl->addEventSource(_monitorTimer)') == 2 and '_wl->addEventSource(_monitorTimer)' not in ieee),
    ('failed-join timer is on the RX workloop in both init paths', ieee.count('rxwl->addEventSource(_joinFailTimer)') == 2),
    ('timers leave the workloop they joined', 'rxwl->removeEventSource(_monitorTimer)' in fn('void RTW88IEEE80211::free(', ieee)
     and 'rxwl->removeEventSource(_joinFailTimer)' in fn('void RTW88IEEE80211::free(', ieee)),
    ('retired keys are freed on teardown', fn('void RTW88IEEE80211::free(', ieee).count('freeRetiredKey') == 2),
    ('auth rejection is reported', 'failJoin("auth-rejected")' in ieee),
    ('assoc rejection is reported', 'failJoin("assoc-rejected")' in ieee),
    ('handshake timeout is reported', 'kRTW88EventJoinFailed' in fn('void RTW88IEEE80211::onTimer(', ieee)),
    ('macOS hears of a failed join', 'kRTW88EventJoinFailed:' in wifi and
     'APPLE80211_M_ASSOC_DONE' in wifi[wifi.index('case kRTW88EventJoinFailed:'):wifi.index('case kRTW88EventRSSIChanged:')]),
    ('802.1X links are keyed from the start', '_externalPTKInstalled || _enterprise' in fn('void RTW88IEEE80211::deliverDataFrame(', ieee)),
]

with tempfile.TemporaryDirectory(prefix='rtw88-join-') as td:
    p = Path(td)
    for name, src in (('driver', DRIVER), ('controller', CONTROLLER)):
        (p / f'{name}.cpp').write_text('#include <alloca.h>\n#include <new>\n' + src)
        subprocess.run(['xcrun', 'clang++', '-std=c++17', '-w', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-g',
                        f'-I{root}', str(p / f'{name}.cpp'), '-o', str(p / name)], check=True)
        r = subprocess.run([str(p / name)], capture_output=True, text=True)
        print('\n'.join(l for l in r.stdout.splitlines() if l.startswith('PASS')))
        if r.returncode:
            print(r.stdout[-2000:], r.stderr[-3000:])
            raise SystemExit(r.returncode)

failed = [name for name, ok in SOURCE_CHECKS if not ok]
if failed:
    raise SystemExit('source checks failed: ' + '; '.join(failed))
print(f'PASS: {len(SOURCE_CHECKS)} source checks: failed joins, workloops, key lifetime')
