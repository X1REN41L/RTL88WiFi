# hostap (wpa_supplicant / hostapd), unmodified subset

- Source: https://git.w1.fi/cgit/hostap
- Commit: `5b156e272a0266ca6be0f394192bad42b0ff176c`
- Copied unchanged from the AirPort_RTW89 repository (https://github.com/FranciumOS-org/AirPort_RTW89, commit `a8441a7`), which fetched it on 2026-10-02.
- Licence: BSD-3-Clause (`COPYING`)

Only what the SAE (WPA3-Personal) exchange needs: `src/common/sae.[ch]`,
`dragonfly.[ch]`, the crypto interface `src/crypto/crypto.h` and the utility
headers they include. Do not edit these files; the adaptation to the kext lives
in `driver/RTL88WiFi/src/compat/wpa3/`.
