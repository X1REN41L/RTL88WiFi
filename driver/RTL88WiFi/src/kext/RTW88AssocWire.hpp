/* Modified by X1REN41L on 2026-11-04 for RTL88WiFi 1.1.0; see the repository NOTICE.md. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Sonoma 856-byte, Sequoia 900-byte and Tahoe 908-byte ASSOCIATE envelopes.
// Validate the shared prefix independently; never interpret the unknown tail.
// Mode and both auth fields use 32 bits rather than the Ventura controller ABI.
// Never cast this wire prefix to apple80211_assoc_data.
// Open, WPA2-PSK, SAE and 802.1X; the unknown tail is not interpreted as RSN.
namespace RTW88AssocWire {
constexpr size_t SonomaRequestSize = 856, RequestSize = 900, TahoeRequestSize = 908, PrefixSize = 140;
// The key type when the key is the passphrase itself, as macOS sends it to a
// card that says it does SAE.
constexpr uint32_t CipherPassphrase = 10;
// SAE: the header's bit, and the one Sequoia's IO80211 framework builds.
constexpr uint32_t SaeAuth = (1u << 9) | 0x1000;
constexpr uint32_t EnterpriseAuth = (1u << 0) | (1u << 2) | (1u << 5) | (1u << 8);
constexpr uint32_t PersonalAuth = (1u << 1) | (1u << 3) | (1u << 7);
constexpr uint32_t PskAuth = (1u << 3) | (1u << 7);
inline bool supportedRequestSize(size_t n) {
    return n == SonomaRequestSize || n == RequestSize || n == TahoeRequestSize;
}
inline bool isEnterprise(uint32_t upper) {
    return (upper & EnterpriseAuth) && !(upper & (PersonalAuth | SaeAuth));
}
struct Personal {
    uint32_t mode, lower, upper, ssidLength, keyLength, cipher;
    uint8_t ssid[32], bssid[6], key[64];
};
inline uint32_t le32(const uint8_t *p) {
    return uint32_t(p[0]) | uint32_t(p[1])<<8 | uint32_t(p[2])<<16 | uint32_t(p[3])<<24;
}
inline bool decode(const uint8_t *p, size_t n, Personal &out) {
    if (!p || n != PrefixSize || le32(p)!=1 || le32(p+4)!=2 || le32(p+8)!=1)
        return false;
    const uint32_t upper=le32(p+12), ssidLength=le32(p+16), keyLength=le32(p+64), cipher=le32(p+68);
    // The key's version: none on an open network (seen on Sequoia).
    if (le32(p+60)!=1 && !(le32(p+60)==0 && upper==0 && keyLength==0)) return false;
    // WPA2-PSK and/or PSK-SHA256; SAE, alone or with them (a mixed network).
    const bool psk=upper && !(upper&~PskAuth);
    const bool sae=(upper&SaeAuth) && !(upper&~(SaeAuth|PskAuth));
    const bool enterprise=isEnterprise(upper);
    const bool passphrase=(psk || sae) && cipher==CipherPassphrase;
    if ((upper!=0 && !psk && !sae && !enterprise) || !ssidLength || ssidLength>32 ||
        (sae && !passphrase) ||
        // SAE has no minimum; prepareJoinSecurity() holds WPA2 to its own limits.
        (passphrase ? keyLength<1 || keyLength>64 : psk ? keyLength!=32 : keyLength!=0))
        return false;
    for (uint32_t i=0;i<ssidLength;++i) if (!p[20+i]) return false;
    if (p[52]&1) return false; // A selected BSSID must be unicast (zero is allowed).
    out={};out.mode=2;out.lower=1;out.upper=upper;out.ssidLength=ssidLength;
    out.keyLength=keyLength;out.cipher=cipher;
    memcpy(out.ssid,p+20,ssidLength);memcpy(out.bssid,p+52,6);
    if (keyLength) memcpy(out.key,p+76,keyLength);
    return true;
}
inline void wipe(void *p,size_t n) {
    volatile uint8_t *q=static_cast<volatile uint8_t *>(p);while(n--) *q++=0;
}
}
