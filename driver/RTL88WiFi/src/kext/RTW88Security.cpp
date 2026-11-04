/* Modified by X1REN41L on 2026-11-04 for RTL88WiFi 1.1.0; see the repository NOTICE.md. */
// SPDX-License-Identifier: GPL-2.0
/*
 * RTW88Security.cpp - WPA3-Personal (SAE), protected management frames,
 * 802.1X key handling and the link monitor for RTL88WiFi.
 *
 * The flows follow AirPort_RTW89's MLME (GPL-2.0, https://github.com/FranciumOS-org/AirPort_RTW89),
 * adapted to this driver's state machine.  See NOTICE.md.
 */
#include "RTW88IEEE80211.hpp"
#include "RTW88MgmtValidation.hpp"

#include <IOKit/IOLib.h>
#include <IOKit/network/IONetworkMedium.h>
#include <string.h>
#include <sys/random.h>
#include <pexpert/pexpert.h>

extern "C" {
#include "../compat/rtw88_compat.h"
#include "rtw88_crypto.h"
#include "rtw88_sae.h"
}

#define IOLog rtw88_candidate_log

enum {
    kAuthAlgSae = 3,
    kStatusAntiClog = 76,
    kStatusSaeH2e = 126,
    kEidRsnx = 244,
    kEidExtension = 255,
    kEidExtAntiClog = 93,
    kRsnxCapSaeH2e = 5,
    kSelectorSaeH2e = 123,
    kCategorySaQuery = 8,
    kSaQueryRequest = 0,
    kSaQueryResponse = 1,
};

static const uint16_t kRsnCapMfpr = 1u << 6, kRsnCapMfpc = 1u << 7;

/* Boot-args are read once; they cannot change while running. */
static bool bootFlag(const char *name)
{
    int dummy = 0;
    return PE_parse_boot_argn(name, &dummy, sizeof(dummy));
}

bool rtw88Wpa3Enabled()
{
    static int state; /* 0 unknown, 1 on, 2 off */
    if (!state)
        state = bootFlag("-rtl88nowpa3") ? 2 : 1;
    return state == 1;
}

/* -rtl88saemixed: use SAE on WPA2/WPA3 mixed networks too.  By default they
 * stay on WPA2, the path this driver has been proven on. */
static bool preferSaeOnMixed()
{
    static int state;
    if (!state)
        state = bootFlag("-rtl88saemixed") ? 1 : 2;
    return state == 1;
}

/* An RSN element with one CCMP pairwise cipher and one AKM.  Without MFP and
 * with PSK this is byte for byte what rtw88BuildSelectedRsnIe() writes. */
static uint16_t buildRsnIe(uint8_t *out, uint32_t group, uint8_t akm, uint16_t caps)
{
    uint8_t *p = out;
    *p++ = WLAN_EID_RSN;
    *p++ = 20;
    *p++ = 1; *p++ = 0;
    *p++ = (uint8_t)(group >> 24); *p++ = (uint8_t)(group >> 16);
    *p++ = (uint8_t)(group >> 8);  *p++ = (uint8_t)group;
    *p++ = 1; *p++ = 0;
    *p++ = 0x00; *p++ = 0x0f; *p++ = 0xac; *p++ = 4;
    *p++ = 1; *p++ = 0;
    *p++ = 0x00; *p++ = 0x0f; *p++ = 0xac; *p++ = akm;
    *p++ = (uint8_t)caps; *p++ = (uint8_t)(caps >> 8);
    return (uint16_t)(p - out);
}

void RTW88IEEE80211::resetJoinSecurity()
{
    _mfp = false;
    _keyVer = 2;
    _enterprise = false;
    _saeJoin = false;
    _saeFallbackAllowed = false;
    _ownRsnLen = 0;
    _ownRsnxeLen = 0;
    _saQueryPending = false;
    _mgmtRxPnValid = false;
    _mgmtRxPn = 0;
    _heldM1Len = 0;
    _assocComebacks = 0;
    _assocRetryPending = false;
}

/* WPA2's limits: 8 to 63 characters, or the key itself in 64 hex digits. */
static bool passphraseFitsWpa2(const char *p)
{
    const size_t n = strnlen(p, 65);
    if (n != 64)
        return n >= 8 && n <= 63;
    for (size_t i = 0; i < n; i++) {
        const char c = p[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return false;
    }
    return true;
}

/*
 * The key management for this join, from what the AP offers and what macOS
 * gave us.  WPA2-only and mixed networks keep the proven WPA2 path; SAE is
 * used where the network requires it (or with -rtl88saemixed).  Returns
 * kIOReturnUnsupported for a network this driver cannot join with them.
 */
IOReturn RTW88IEEE80211::prepareJoinSecurity(const char *password, const uint8_t *pmk,
                                             bool enterprise, bool forcePsk)
{
    const bool haveRsn = _targetBSS.akms != 0;
    const uint32_t akms = _targetBSS.akms;
    const uint16_t caps = _targetBSS.rsn_caps;
    const bool havePass = password && password[0];
    const bool saeOffered = (akms & (1u << kAkmSae)) != 0;
    const bool pskOffered = (akms & ((1u << kAkmPsk) | (1u << kAkmPskSha256))) != 0;
    uint8_t akm;

    resetJoinSecurity();
    _enterprise = enterprise;

    if (enterprise) {
        if (_targetBSS.cipher != WLAN_CIPHER_SUITE_CCMP || !(akms & (1u << kAkm8021X)) ||
            (caps & kRsnCapMfpr)) {
            IOLog("rtw88: 802.1X join: network not usable akms=0x%x caps=0x%x cipher=0x%x\n",
                  akms, caps, _targetBSS.cipher);
            return kIOReturnUnsupported;
        }
        _ownRsnLen = buildRsnIe(_ownRsnIE, _targetBSS.group_cipher, kAkm8021X, 0);
        return kIOReturnSuccess;
    }

    /* No RSN parsed (open, legacy WPA, or a suite list only macOS could
     * read): nothing changes for this join. */
    if (!haveRsn || _targetBSS.cipher != WLAN_CIPHER_SUITE_CCMP || (!havePass && !pmk))
        return kIOReturnSuccess;

    /* A password WPA2 cannot use is still good for SAE, even on a mixed network. */
    const bool passFitsPsk = havePass && passphraseFitsWpa2(password);
    if (!forcePsk && havePass && saeOffered && rtw88Wpa3Enabled() &&
        (!pskOffered || preferSaeOnMixed() || !passFitsPsk)) {
        akm = kAkmSae;
        _saeFallbackAllowed = pskOffered && passFitsPsk;
    } else if (pskOffered) {
        if (!pmk && !passFitsPsk) {
            IOLog("rtw88: the password does not fit WPA2 and the network has no SAE to use it with\n");
            return kIOReturnBadArgument;
        }
        akm = (akms & (1u << kAkmPsk)) ? kAkmPsk : kAkmPskSha256;
    } else {
        IOLog("rtw88: no usable key management akms=0x%x password=%d pmk=%d\n",
              akms, havePass, pmk != nullptr);
        return kIOReturnUnsupported;
    }

    _mfp = (caps & kRsnCapMfpc) && (akm != kAkmPsk || (caps & kRsnCapMfpr));
    if (!_mfp && (caps & kRsnCapMfpr)) {
        IOLog("rtw88: network requires protected management frames it does not offer\n");
        return kIOReturnUnsupported;
    }
    _saeJoin = akm == kAkmSae;
    _keyVer = akm == kAkmPsk ? 2 : akm == kAkmPskSha256 ? 3 : 0;
    if (_mfp || akm != kAkmPsk) {
        uint16_t own = _mfp ? (uint16_t)(kRsnCapMfpc | (_saeJoin ? kRsnCapMfpr : 0)) : 0;
        _ownRsnLen = buildRsnIe(_ownRsnIE, _targetBSS.group_cipher, akm, own);
    }
    IOLog("rtw88: join security akm=%u mfp=%d keyver=%u\n", akm, _mfp, _keyVer);
    return kIOReturnSuccess;
}

/* The master key from the passphrase macOS sent: a 64-digit hex key, or
 * PBKDF2 as usual (the caller's derivation). */
bool RTW88IEEE80211::pmkFromHexPassword()
{
    if (strnlen(_password, sizeof(_password)) != 64)
        return false;
    uint8_t out[32];
    for (int i = 0; i < 64; i++) {
        char c = _password[i];
        int v = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 :
                c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
        if (v < 0) { bzero(out, sizeof(out)); return false; }
        if (i & 1) out[i / 2] |= (uint8_t)v;
        else out[i / 2] = (uint8_t)(v << 4);
    }
    memcpy(_pmk, out, sizeof(_pmk));
    bzero(out, sizeof(out));
    return true;
}

/* ------------------------------------------------------------------ */
/*  SAE                                                                 */
/* ------------------------------------------------------------------ */

static bool iesSayH2e(const uint8_t *ies, uint32_t len)
{
    for (uint32_t i = 0; i + 2 <= len;) {
        uint32_t n = 2u + ies[i + 1];
        if (i + n > len) break;
        if (ies[i] == kEidRsnx && ies[i + 1] >= 1 && (ies[i + 2] & (1u << kRsnxCapSaeH2e)))
            return true;
        if (ies[i] == WLAN_EID_SUPP_RATES || ies[i] == WLAN_EID_EXT_SUPP_RATES)
            for (uint32_t j = 2; j < n; j++)
                if (ies[i + j] == (0x80 | kSelectorSaeH2e))
                    return true;
        i += n;
    }
    return false;
}

bool RTW88IEEE80211::saeStart(bool h2e)
{
    if (_sae) rtw88_sae_end(_sae);
    _sae = rtw88_sae_begin(_macAddr, _targetBSS.bssid, (const uint8_t *)_targetBSS.ssid,
                           _targetBSS.ssid_len, (const uint8_t *)_password,
                           strnlen(_password, sizeof(_password)), h2e);
    if (!_sae)
        return false;
    _saeH2e = h2e;
    _saeConfirmSent = false;
    _saeTokenLen = 0;
    _ownRsnxeLen = 0;
    if (h2e) {
        _ownRsnxe[0] = kEidRsnx;
        _ownRsnxe[1] = 1;
        _ownRsnxe[2] = 1u << kRsnxCapSaeH2e;
        _ownRsnxeLen = 3;
    }
    return true;
}

void RTW88IEEE80211::saeEnd()
{
    if (_sae) { rtw88_sae_end(_sae); _sae = nullptr; }
    _saeConfirmSent = false;
    _saeTokenLen = 0;
}

/* Our commit, or our confirm once the AP's commit is in. */
bool RTW88IEEE80211::saeSendAuth()
{
    uint8_t *frame = (uint8_t *)IOMallocZero(kSaeFrameMax);
    if (!frame) return false;
    struct ieee80211_hdr_3addr *hdr = (struct ieee80211_hdr_3addr *)frame;
    hdr->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_AUTH);
    memcpy(hdr->addr1, _targetBSS.bssid, 6);
    memcpy(hdr->addr2, _macAddr, 6);
    memcpy(hdr->addr3, _targetBSS.bssid, 6);
    hdr->seq_ctrl = cpu_to_le16((uint16_t)(_txSeq++ << 4));
    uint8_t *b = frame + sizeof(*hdr);
    uint16_t status = (_saeH2e && !_saeConfirmSent) ? kStatusSaeH2e : 0;
    b[0] = kAuthAlgSae; b[1] = 0;
    b[2] = _saeConfirmSent ? 2 : 1; b[3] = 0;
    b[4] = (uint8_t)status; b[5] = (uint8_t)(status >> 8);
    const size_t room = kSaeFrameMax - sizeof(*hdr) - 6;
    int n = _saeConfirmSent ?
        rtw88_sae_write_confirm(_sae, b + 6, room) :
        rtw88_sae_write_commit(_sae, _saeTokenLen ? _saeToken : nullptr, _saeTokenLen, b + 6, room);
    bool ok = n >= 0 && txMgmtFrame(frame, (uint32_t)(sizeof(*hdr) + 6 + n));
    IOFree(frame, kSaeFrameMax);
    return ok;
}

void RTW88IEEE80211::saeArmTimer()
{
    uint64_t d;
    clock_interval_to_deadline(3000, kMillisecondScale, &d);
    _timer->wakeAtTime(d);
}

/* SAE did not get through on a network that also takes WPA2-PSK: join it with
 * WPA2 from the authentication on. */
bool RTW88IEEE80211::saeFallBack(const char *why)
{
    if (!_saeJoin || !_saeFallbackAllowed)
        return false;
    IOLog("rtw88: %s: joining with WPA2 instead\n", why);
    saeEnd();
    if (prepareJoinSecurity(_password, nullptr, false, true) != kIOReturnSuccess)
        return false;
    _authAttempts = 0;
    uint8_t auth[30] = {};
    uint32_t authlen = 0;
    buildAuthReq(auth, &authlen);
    if (!txMgmtFrame(auth, authlen))
        return false;
    saeArmTimer();
    return true;
}

/* Runs on the SAE worker: the curve arithmetic has no place on the RX path. */
void RTW88IEEE80211::saeRxFrame(const uint8_t *f, uint32_t flen)
{
    uint16_t transaction = (uint16_t)(f[26] | (f[27] << 8));
    uint16_t status = (uint16_t)(f[28] | (f[29] << 8));
    const uint8_t *body = f + 30;
    size_t len = flen - 30;

    if (!_sae || _state != RTW88_STATE_AUTHENTICATING || authenticationCancelled())
        return;

    if (transaction == 1) {
        if (status == kStatusAntiClog && !_saeConfirmSent) {
            /* the group, then the token; with H2E the token comes in a
             * container element, which our commit puts back around it */
            if (len < 2) return;
            body += 2; len -= 2;
            if (_saeH2e && len >= 3 && body[0] == kEidExtension && body[2] == kEidExtAntiClog &&
                body[1] >= 1 && (size_t)body[1] + 2 <= len) {
                len = body[1] - 1u;
                body += 3;
            }
            if (len > sizeof(_saeToken)) return;
            memcpy(_saeToken, body, len);
            _saeTokenLen = (uint8_t)len;
            _authAttempts = 0;
            if (!saeSendAuth()) { failJoin("sae-tx"); return; }
            saeArmTimer();
            return;
        }
        if (status == kStatusSaeH2e && !_saeH2e && !_saeConfirmSent) {
            IOLog("rtw88: the AP wants SAE with hash-to-element\n");
            if (!saeStart(true)) { failJoin("sae-h2e-start"); return; }
            _authAttempts = 0;
            if (!saeSendAuth()) { failJoin("sae-tx"); return; }
            saeArmTimer();
            return;
        }
        if (status != (_saeH2e ? kStatusSaeH2e : 0)) {
            IOLog("rtw88: the AP refused the SAE commit, status %u\n", status);
            if (!saeFallBack("SAE commit refused")) failJoin("sae-commit-refused");
            return;
        }
        if (_saeConfirmSent)
            return;     /* its commit again: the timer resends our confirm */
        int ret = rtw88_sae_rx_commit(_sae, body, len);
        if (ret) {
            IOLog("rtw88: the AP's SAE commit does not check out: %d\n", ret);
            if (!saeFallBack("bad SAE commit")) failJoin("sae-bad-commit");
            return;
        }
        _saeConfirmSent = true;
        _authAttempts = 0;
        if (!saeSendAuth()) { failJoin("sae-tx"); return; }
        saeArmTimer();
        return;
    }

    if (transaction != 2 || !_saeConfirmSent)
        return;
    _timer->cancelTimeout();
    if (status != 0) {
        IOLog("rtw88: the AP refused our SAE confirm, status %u\n", status);
        failJoin("sae-confirm-refused");
        return;
    }
    if (rtw88_sae_rx_confirm(_sae, body, len)) {
        /* No fallback: a mismatch means a wrong password. */
        IOLog("rtw88: the AP's SAE confirm does not match: wrong password\n");
        failJoin("sae-wrong-password");
        return;
    }
    uint8_t pmkid[16];
    rtw88_sae_keys(_sae, _pmk, pmkid);
    bzero(pmkid, sizeof(pmkid));
    _pmkProvided = true;
    saeEnd();
    IOLog("rtw88: SAE done, associating\n");
    doAssociate();
}

/* Any context that owns the frame: queued for the SAE worker. */
void RTW88IEEE80211::saeQueueFrame(const uint8_t *f, uint32_t len)
{
    if (len < 30 || len > kSaeFrameMax || f[24] != kAuthAlgSae || f[25] != 0 || !_saeTC)
        return;
    SaeFrame *n = (SaeFrame *)IOMalloc(sizeof(SaeFrame));
    if (!n) return;
    n->next = nullptr;
    n->len = len;
    memcpy(n->data, f, len);
    IOLockLock(_saeLock);
    SaeFrame **pp = &_saeQueue;
    int depth = 0;
    while (*pp) { pp = &(*pp)->next; depth++; }
    if (depth < 4) { *pp = n; n = nullptr; }
    IOLockUnlock(_saeLock);
    if (n) IOFree(n, sizeof(SaeFrame));
    thread_call_enter(_saeTC);
}

void RTW88IEEE80211::saeFlushQueue()
{
    for (;;) {
        IOLockLock(_saeLock);
        SaeFrame *n = _saeQueue;
        if (n) _saeQueue = n->next;
        IOLockUnlock(_saeLock);
        if (!n) break;
        IOFree(n, sizeof(SaeFrame));
    }
}

void RTW88IEEE80211::saeTCFn(thread_call_param_t self, thread_call_param_t)
{
    RTW88IEEE80211 *me = (RTW88IEEE80211 *)self;
    for (;;) {
        IOLockLock(me->_saeLock);
        SaeFrame *n = me->_saeQueue;
        if (n) me->_saeQueue = n->next;
        IOLockUnlock(me->_saeLock);
        if (!n) break;
        IOLockLock(me->_saeOpLock);
        me->saeRxFrame(n->data, n->len);
        IOLockUnlock(me->_saeOpLock);
        IOFree(n, sizeof(SaeFrame));
    }
}

/* First attempt of doAuthenticate(): the (slow) commit, then the frame; a
 * retry only resends the message due. */
void RTW88IEEE80211::saeBeginOrResend()
{
    if (!_sae && !saeStart(iesSayH2e(_targetBSS.ies, _targetBSS.ies_len))) {
        failJoin("sae-start");
        return;
    }
    if (authenticationCancelled()) return;
    if (!saeSendAuth()) { failJoin("sae-tx"); return; }
    if (authenticationCancelled() || _state != RTW88_STATE_AUTHENTICATING) return;
    saeArmTimer();
}

/* ------------------------------------------------------------------ */
/*  Protected management frames (802.11w)                               */
/* ------------------------------------------------------------------ */

/* 802.11-2020 12.6.6.2. */
static bool frameIsRobust(const uint8_t *f, uint32_t len)
{
    if (len < 24 || (f[0] & 0x0c) != 0) return false;
    const uint8_t stype = f[0] & 0xf0;
    if (stype == 0xa0 || stype == 0xc0) return true;
    if (stype != 0xd0 || len < 25) return false;
    switch (f[24] & 0x7f) {
    case 4: case 7: case 11: case 15: case 20: case 21: case 127:
        return false;
    default:
        return !(f[24] & 0x80);
    }
}

/* rtw88 flags CCMP keys SW_MGMT_TX: robust frames are encrypted here, with
 * the packet numbers of the data path, as mac80211 does. */
bool RTW88IEEE80211::txMgmtFrame(const uint8_t *frame, uint32_t len)
{
    struct ieee80211_key_conf *ptk = __atomic_load_n(&_ptkConf, __ATOMIC_ACQUIRE);
    if (!_mfp || !ptk || !frame || !frameIsRobust(frame, len) ||
        memcmp(frame + 4, _targetBSS.bssid, 6) != 0)
        return txMgmtFrameRaw(frame, len);

    const uint32_t hdrlen = 24, body = len - hdrlen, total = len + 8 + 8;
    uint8_t *out = (uint8_t *)IOMalloc(total);
    if (!out) return false;
    uint8_t pnb[6];
    nextCcmpPn(pnb);
    uint64_t pn = 0;
    for (int i = 5; i >= 0; i--) pn = (pn << 8) | pnb[i];
    memcpy(out, frame, hdrlen);
    out[1] |= IEEE80211_FCTL_PROTECTED >> 8;
    uint8_t *ccmp = out + hdrlen;
    ccmp[0] = pnb[0]; ccmp[1] = pnb[1]; ccmp[2] = 0;
    ccmp[3] = (uint8_t)(0x20 | (((uint8_t)ptk->keyidx & 3) << 6));
    ccmp[4] = pnb[2]; ccmp[5] = pnb[3]; ccmp[6] = pnb[4]; ccmp[7] = pnb[5];
    memcpy(ccmp + 8, frame + hdrlen, body);
    rtw88_ccmp_encrypt(ptk->key, out, hdrlen, pn, ccmp + 8, body, ccmp + 8 + body);
    bool ok = txMgmtFrameRaw(out, total);
    IOFree(out, total);
    return ok;
}

/* A protected frame from the AP: decrypted if the hardware did not, replay
 * checked, CCMP header and MIC removed.  False if it is to be dropped. */
bool RTW88IEEE80211::mgmtUnprotect(struct sk_buff *skb)
{
    const uint32_t hdrlen = 24;
    const struct ieee80211_key_conf *ptk = __atomic_load_n(&_ptkConf, __ATOMIC_ACQUIRE);
    if (!_mfp || !ptk || skb->len < hdrlen + 8 + 8)
        return false;
    uint8_t *hdr = skb->data, *ccmp = hdr + hdrlen;
    if (!(ccmp[3] & 0x20))
        return false;
    uint64_t pn = ccmp[0] | (uint64_t)ccmp[1] << 8 | (uint64_t)ccmp[4] << 16 |
                  (uint64_t)ccmp[5] << 24 | (uint64_t)ccmp[6] << 32 | (uint64_t)ccmp[7] << 40;
    if (_mgmtRxPnValid && pn <= _mgmtRxPn)
        return false;
    uint32_t body = skb->len - hdrlen - 8 - 8;
    if (!(IEEE80211_SKB_RXCB(skb)->flag & RX_FLAG_DECRYPTED) &&
        !rtw88_ccmp_decrypt(ptk->key, hdr, hdrlen, pn, ccmp + 8, body, ccmp + 8 + body))
        return false;
    _mgmtRxPn = pn;
    _mgmtRxPnValid = true;
    memmove(hdr + 8, hdr, hdrlen);
    skb_pull(skb, 8);
    skb_trim(skb, skb->len - 8);
    skb->data[1] &= (uint8_t)~(IEEE80211_FCTL_PROTECTED >> 8);
    return true;
}

/*
 * Applied to deauth, disassoc and action frames before they are acted on.
 * True: go on with the (now plain) frame.  False: drop it.  An unprotected
 * "leave" cannot be believed under 802.11w: ask the AP (SA Query).
 */
bool RTW88IEEE80211::mgmtFilterRx(struct sk_buff *skb)
{
    if (!_mfp || !_ptkConf || skb->len < 24)
        return true;
    if (skb->data[1] & (IEEE80211_FCTL_PROTECTED >> 8))
        return mgmtUnprotect(skb);
    if (!frameIsRobust(skb->data, skb->len))
        return true;
    const uint8_t stype = skb->data[0] & 0xf0;
    if ((stype == 0xa0 || stype == 0xc0) && skb->len >= 26 &&
        memcmp(skb->data + 4, _macAddr, 6) == 0 &&
        memcmp(skb->data + 10, _targetBSS.bssid, 6) == 0 && !_saQueryPending) {
        _saQueryReason = (uint16_t)(skb->data[24] | (skb->data[25] << 8));
        read_random(_saQueryId, sizeof(_saQueryId));
        _saQueryPending = true;
        _saQueryStartMs = rtw88NowMs();
        sendSaQuery(kSaQueryRequest, _saQueryId);
    }
    return false;
}

void RTW88IEEE80211::sendSaQuery(uint8_t action, const uint8_t id[2])
{
    uint8_t f[24 + 4] = {};
    struct ieee80211_hdr_3addr *hdr = (struct ieee80211_hdr_3addr *)f;
    hdr->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ACTION);
    memcpy(hdr->addr1, _targetBSS.bssid, 6);
    memcpy(hdr->addr2, _macAddr, 6);
    memcpy(hdr->addr3, _targetBSS.bssid, 6);
    hdr->seq_ctrl = cpu_to_le16((uint16_t)(_txSeq++ << 4));
    f[24] = kCategorySaQuery;
    f[25] = action;
    f[26] = id[0];
    f[27] = id[1];
    txMgmtFrame(f, sizeof(f));
}

bool RTW88IEEE80211::handleSaQuery(const uint8_t *b, uint32_t len)
{
    if (len < 4 || b[0] != kCategorySaQuery)
        return false;
    if (b[1] == kSaQueryRequest) {
        sendSaQuery(kSaQueryResponse, b + 2);
    } else if (b[1] == kSaQueryResponse && _saQueryPending && memcmp(b + 2, _saQueryId, 2) == 0) {
        _saQueryPending = false;
        IOLog("rtw88: the AP still knows us: an unprotected leave message was ignored\n");
    }
    return true;
}

/* ------------------------------------------------------------------ */
/*  802.1X (macOS's eapolclient signs in, the key handshake is ours)    */
/* ------------------------------------------------------------------ */

void RTW88IEEE80211::rxEapolKey(const uint8_t *data, uint32_t len)
{
    /* The AP starts the handshake as soon as the sign-in is through; the
     * master key reaches us a moment later.  Keep message 1 until then. */
    if (_enterprise && !_pmkProvided) {
        if (len >= 99 && len <= sizeof(_heldM1) && !(((data[5] << 8) | data[6]) & 0x0100)) {
            memcpy(_heldM1, data, len);
            _heldM1Len = (uint16_t)len;
        }
        return;
    }
    handleEAPOL(data, len);
}

IOReturn RTW88IEEE80211::cmdSetEnterprisePMK(const uint8_t *pmk, size_t len)
{
    if (!_enterprise || !_associatedVisible)
        return kIOReturnNotReady;
    if (!pmk || len < 32)
        return kIOReturnBadArgument;
    memcpy(_pmk, pmk, 32);
    _pmkProvided = true;
    _snonceValid = false;
    IOLog("rtw88: 802.1X sign-in done, master key received held_m1=%u\n", _heldM1Len);
    /* Handled on the RX workloop, in order with arriving frames. */
    if (_heldM1Len && _heldM1Timer)
        _heldM1Timer->setTimeoutMS(1);
    return kIOReturnSuccess;
}

void RTW88IEEE80211::heldM1TimerFired(OSObject *owner, IOTimerEventSource *)
{
    RTW88IEEE80211 *self = OSDynamicCast(RTW88IEEE80211, owner);
    if (!self || !self->_heldM1Len) return;
    uint16_t n = self->_heldM1Len;
    self->_heldM1Len = 0;
    self->handleEAPOL(self->_heldM1, n);
}

/* ------------------------------------------------------------------ */
/*  Link monitor: AP gone, AP changing channel, unanswered SA Query     */
/* ------------------------------------------------------------------ */

void RTW88IEEE80211::noteApBeacon(const uint8_t *ies, uint32_t len)
{
    uint8_t announced = 0;
    for (uint32_t i = 0; i + 2 <= len;) {
        uint32_t n = 2u + ies[i + 1];
        if (i + n > len) break;
        /* Channel Switch Announcement: mode, new channel, count. */
        if (ies[i] == 37 && ies[i + 1] >= 3 && ies[i + 3] != 0 && ies[i + 3] != _targetBSS.channel)
            announced = ies[i + 3];
        i += n;
    }
    /* Beacons are not protected, so an announcement proves nothing by itself:
     * a beacon without one means the AP is still here and staying. */
    if (!announced) {
        _csaChannel = 0;
        _csaBeacons = 0;
        return;
    }
    if (announced != _csaChannel) {
        _csaChannel = announced;
        _csaBeacons = 0;
    }
    if (_csaBeacons < kCsaMinBeacons && ++_csaBeacons == kCsaMinBeacons && !_csaLogged) {
        _csaLogged = true;
        IOLog("rtw88: the AP announces a move to channel %u\n", announced);
    }
}

void RTW88IEEE80211::startLinkMonitor()
{
    _lastApRxMs = rtw88NowMs();
    _probeNoAcks = 0;
    _lastProbeMs = 0;
    _csaChannel = 0;
    _csaBeacons = 0;
    _csaQuietTicks = 0;
    _csaLogged = false;
    if (_monitorTimer) _monitorTimer->setTimeoutMS(1000);
}

void RTW88IEEE80211::linkLost(uint16_t reason, const char *why)
{
    IOLog("rtw88: link lost: %s\n", why);
    _deauthReason = reason;
    clearKeys();
    _txBaActive = false;
    rxBaTeardownAll();
    _associatedVisible = false;
    _state = RTW88_STATE_IDLE;
    _scanReturnState = RTW88_STATE_IDLE;
    if (_parent) _parent->setLinkStatus(kIONetworkLinkValid);
    if (_delegate) _delegate->rtw88Event(kRTW88EventDeauth, &_deauthReason);
}

void RTW88IEEE80211::monitorTimerFired(OSObject *owner, IOTimerEventSource *)
{
    RTW88IEEE80211 *self = OSDynamicCast(RTW88IEEE80211, owner);
    if (self) self->monitorTick();
}

void RTW88IEEE80211::monitorTick()
{
    if (!_powered || !_associatedVisible)
        return;     /* re-armed by the next association */
    if (_state == RTW88_STATE_CONNECTED) {
        const uint64_t now = rtw88NowMs();
        /* The announcement was repeated and then the AP went quiet on this
         * channel: forged beacons cannot silence the real one.  Heard while
         * here on the channel, so time away scanning does not count. */
        if (_csaBeacons >= kCsaMinBeacons && !_awdlOffChannel && now - _lastApRxMs >= 1000) {
            if (++_csaQuietTicks >= kCsaQuietTicks) {
                linkLost(WLAN_REASON_DEAUTH_LEAVING, "AP changed channel");
                return;
            }
        } else {
            _csaQuietTicks = 0;
        }
        if (_saQueryPending && now - _saQueryStartMs > 1000) {
            _saQueryPending = false;
            linkLost(_saQueryReason, "no answer to the SA Query");
            return;
        }
        /* Nothing heard from the AP: ask it.  Only an explicit lack of ACK
         * counts; a missing TX report proves nothing. */
        const uint64_t idle = now - _lastApRxMs;
        if (_probeNoAcks >= 3 && idle >= 20000) {
            linkLost(WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY, "the AP does not answer");
            return;
        }
        if (idle >= 8000 && now - _lastProbeMs >= 2000 && !_awdlOffChannel) {
            _lastProbeMs = now;
            txNullFunc(false, true);
        }
        /* An encrypted ADDBA request sent right after M4 can reach the AP
         * before it has installed the key.  900, not 1000: the tick must not
         * skip a retry because of timer jitter. */
        if (_txBaPending && !_awdlOffChannel && now - _txBaSentMs >= 900) {
            if (_txBaRetries < kTxBaMaxRetries) {
                _txBaRetries++;
                IOLog("rtw88: TX ADDBA retry %u (tid=%u)\n", _txBaRetries, _baTid);
                sendAddbaRequest(_baTid);
            } else {
                _txBaPending = false;
                IOLog("rtw88: TX ADDBA no answer after %u retries\n", _txBaRetries);
            }
        }
    }
    _monitorTimer->setTimeoutMS(1000);
}
