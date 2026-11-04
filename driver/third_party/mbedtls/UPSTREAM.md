# Mbed TLS 3.6 LTS, unmodified subset

- Source: https://github.com/Mbed-TLS/mbedtls, branch `mbedtls-3.6`
- Commit: `1ee94c5a1147`
- Copied unchanged from the AirPort_RTW89 repository (https://github.com/FranciumOS-org/AirPort_RTW89, commit `a8441a7`), which fetched it on 2026-10-02.
- Licence: Apache-2.0 OR GPL-2.0-or-later (`LICENSE`); used here under GPL-2.0

Only the multi-precision integer and elliptic-curve code (`library/bignum*`,
`ecp*`, `constant_time*`, `platform_util.c` and their headers), for the P-256
arithmetic hostap's SAE code needs. Do not edit these files; configuration and
the kernel adaptation live in `driver/RTL88WiFi/src/compat/wpa3/`.
