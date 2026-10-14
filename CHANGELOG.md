# Changelog

## 1.0.1 — 2026-10-14

Final maintenance release. It only corrects what macOS shows in System
Information (`system_profiler SPAirPortDataType`) and the Option-click Wi-Fi
menu. Throughput, connecting, sleep/wake and the data path are unchanged.
Build identity `1.0.1-rtl88wifi-r12-20261014`.

- **Transmit Rate and MCS Index** now show the card's real current transmit
  rate (for example 866 Mbps, MCS 9 on an 80 MHz 802.11ac link). Before, they
  showed the router's fastest basic rate (displayed as 108) and MCS 0. Right
  after joining, both stay empty for a moment until the card reports its
  first rate; no placeholder value is shown.
- **Signal / Noise** no longer shows a fixed −95 dBm noise. On RTL8822BE and
  RTL8822CE the noise value comes from the signal-to-noise ratio the card
  measures on the connected network (noise = signal − SNR; the cards have no
  direct noise-floor measurement, so this is an estimate). RTL8821CE does not
  measure SNR, so it reports no noise value. Other networks in the list show
  no noise value (0) instead of −95 dBm.
- **Channel width of nearby networks** now shows 40 or 80 MHz when the network
  uses it, instead of always 20 MHz.
- **Supported Channels** now follow the Wi-Fi country code: channel 14 is
  listed only in Japan, and channels 12–13 are hidden in the US, Canada and US
  territories. Elsewhere (for example Brazil) channels 1–13 are listed. When
  macOS has not set a country, the full list is shown as before.

Not changed in 1.0.1:

- **Card Type** shows the Realtek vendor ID and the card's PCI subsystem ID
  (for example `0x10EC, 0xC123` on some RTL8822CE boards). The value comes
  from the card itself; the driver does not set it.
- **AirDrop and Auto Unlock** are still listed as "Supported" although they
  do not work. The capability flags behind them are kept because changing
  them risks breaking driver loading.

These fixes have been built and checked for compilation only; they have not
been tested on hardware.

## Discontinued — 2026-10-06

Development has stopped. 1.0.0 is the final release; the kext in `Kexts/` is
unchanged. The README lists the remaining issues, which will not be fixed.

- Removed unused source files (Linux-only chip, transport and optional
  feature code, unreachable compatibility headers, an unbuilt kext class).
  The driver still builds to the same binary.
- Test fixtures use generic network names and addresses.

## 1.0.0 — 2026-10-02

First release under the RTL88WiFi name.

- Driver, executable and bundle renamed to `RTL88WiFi`
  (`io.github.x1ren41l.RTL88WiFi`), with native controller/interface classes
  `RTL88WiFi` / `RTL88WiFiInterface`. Build identity
  `1.0.0-rtl88wifi-r11-20261002`.
- WPA2 handshake retries, key installation and group rekeys fixed; stable
  SNonce; idempotent key install.
- Router HT/VHT capabilities parsed and used (5 GHz at line rate).
- Memory, firmware-bounds and station-lifetime fixes.
- Correct disconnect reasons, Sonoma-format network info, SSIDs kept in scan
  results, AP IE list ABI fix.
- Beacon TIM kept for the connected network and scan padding no longer
  copied (hidden-network label after wakes and network switches).
- Undecrypted/plaintext frames on protected links dropped; FragAttacks
  A-MSDU check; multicast and NoAck QoS traffic bypass RX reordering.
- Output-pull limit and two experimental output gates. On the current
  IO80211 push data path these gates do not engage; they are kept for
  diagnostics.
- Built-in `DiagnosticLog` with queue drop/stall counters.
- Added `tools/rtl88wifi-check.sh`, `docs/COMPATIBILITY.md` and issue
  templates for compatibility reports.

Hardware verification (RTL8821CE, Sonoma 14.8.9): load and join, ~15 minutes
of load and idle without link drops, 0% idle ping loss, `networkQuality`
86–87 down / 89–105 up Mbps. Known remaining issue: queue drops under heavy
parallel uploads (see README).
