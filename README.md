# RTL88WiFi

Native macOS Wi-Fi for Realtek **RTL8821CE, RTL8822BE and RTL8822CE** PCIe cards
on Hackintosh. The card works like a Mac's AirPort card: it shows up in the
Wi-Fi menu, auto-joins and reconnects after sleep. SIP stays enabled, and no
client app is needed.

> [!IMPORTANT]
> **Discontinued.** Development stopped after version 1.0.0. Version 1.0.1 is
> a final maintenance release that only corrects what System Information
> reports (transmit rate, noise, channel widths, supported channels); see
> [CHANGELOG](CHANGELOG.md). The driver stays usable as is, but the
> [remaining issues](#remaining-issues) will not be fixed. Keep a bootable EFI
> backup on USB.

<p align="center">
  <img src="docs/images/speedtest-2.0.1.png" alt="RTL8821CE speed test: 93.40 Mbps down, 92.45 Mbps up" width="380">
</p>

On a 100 Mbps line, RTL8821CE on Sonoma reaches 86–93 Mbps down and 89–105 Mbps
up. The link held through load tests and sleep/wake. Before these fixes, the
same card managed 7 Mbps and kept disconnecting.

## Compatibility

| Chip | PCI ID | Status |
|---|---|---|
| RTL8821CE | `10ec:c821`, `10ec:b821` | ✅ Verified |
| RTL8822BE | `10ec:b822` | 🟡 Supported, needs reports |
| RTL8822CE | `10ec:c822`, `10ec:c82f` | 🟡 Supported, needs reports |

| macOS | Status |
|---|---|
| Sonoma 14 | ✅ Verified on 14.8.9 |
| Sequoia 15 / Tahoe 26 | 🟡 Same setup, needs reports |
| Ventura 13.7.7–13.7.8 | 🟡 Add only `RTL88WiFi.kext` (no other kexts or Block entry), needs reports |
| Monterey and older | ❌ |

PCIe only; USB and SDIO adapters are not supported. Confirmed machines are
listed in [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

**Check your machine** (read-only, before or after installing):

```sh
bash tools/rtl88wifi-check.sh           # chip, macOS, kexts, link
bash tools/rtl88wifi-check.sh --speed   # plus ping and networkQuality
```

It ends with a report block (without MAC, IP or network name) for a
[compatibility report](../../issues/new?template=compatibility-report.yml).

## Features

**Works:** WPA2-Personal, WPA2/WPA3 transition mode (connects as WPA2), open
networks, 2.4 and 5 GHz (80 MHz), Wi-Fi menu and auto-join, network switching,
group rekeys, sleep/wake.

**Doesn't work:** WPA3-only, Enterprise, hidden networks, AirDrop and
Continuity (AWDL). Bluetooth is a separate device and is not covered. TKIP is
untested.

## Remaining issues

These are known and will not be fixed:

- **Upload drops.** Heavy parallel uploads overflow macOS's 256-packet Wi-Fi
  output queue (about 1–4% drops in `networkQuality`, much more in some
  multi-stream tests). The number varies widely between runs. Speed stays at
  line rate.
- **Small UDP loss.** Packet-loss tests (for example speed.cloudflare.com)
  show about 0.4% loss on Wi-Fi, in short bursts. The likely contributors are
  AWDL off-channel windows and the upload drops above; this was not confirmed.
- **AWDL.** The driver periodically leaves the router's channel for AWDL
  (AirDrop/Continuity) advertising, which adds short latency spikes. No AWDL
  peer has ever been seen, so AirDrop and Continuity do not work.
- **Occasional slow transmit stalls.** Under load the card sometimes sends very
  slowly for 10–50 ms. The cause is unknown.
- **"Hidden" network label.** Fixed after wake; after switching networks,
  macOS may still label the network as hidden. The connection is not
  affected.
- **Unsupported security and joins:** WPA3-only (SAE), Enterprise/802.1X,
  OWE, PMF-required networks and joining hidden networks. TKIP is untested.
- **Untested hardware and systems:** RTL8822BE/CE, macOS other than Sonoma
  14.8.9, roaming, and long standby/hibernate.
- **System Information leftovers.** AirDrop and Auto Unlock are listed as
  "Supported" but do not work. Card Type shows the card's PCI subsystem ID,
  not its device ID. RTL8821CE reports no noise value.
- The two output gates in the driver never engage on the IO80211 push data
  path; the code is inert and kept as is.

## Setup (OpenCore)

You need a working OpenCore EFI with Lilu. Back up your EFI to USB first.

1. **Copy the kexts.** Copy `AMFIPass`, `IOSkywalkFamily`, `IO80211FamilyLegacy`
   and `RTL88WiFi` from [`Kexts/`](Kexts) to `EFI/OC/Kexts/`. Disable any other
   Wi-Fi kext.
2. **`Kernel → Add`.** Add the kexts after Lilu, in that order. Executable path:
   `Contents/MacOS/<name>`. For each entry set `MinKernel 23.0.0` and
   `Enabled true`.
   Do **not** add the `AirPortBrcmNIC.kext` plugin inside IO80211FamilyLegacy.
3. **`Kernel → Block`.** Add `com.apple.iokit.IOSkywalkFamily`, Strategy
   `Exclude`, `MinKernel 23.0.0`, `Enabled true`.
4. **Security.** Set `SecureBootModel` to `Disabled`. SIP can stay enabled, and
   no boot-args are needed.
5. **Validate, reboot and verify.** Run `ocvalidate`, reboot, join your
   network, then run `bash tools/rtl88wifi-check.sh --speed`.

Steps 2 and 3 are ready to paste from
[docs/opencore-wifi-snippet.plist](docs/opencore-wifi-snippet.plist).

## Troubleshooting

| Problem | Fix |
|---|---|
| No Wi-Fi | Check the Block entry, the kext order and `MinKernel`; run the check script |
| Panic at boot | Boot the USB backup; remove `AirPortBrcmNIC.kext`; set `SecureBootModel` to `Disabled` |
| Can't join | Use WPA2-Personal or WPA2/WPA3 mixed mode |
| Lid closes but the laptop doesn't sleep | `sudo pmset -a powernap 0 proximitywake 0 standby 0 hibernatemode 0` |
| Driver log | `ioreg -l -w0 \| grep DiagnosticLog` (contains no passwords or traffic) |

## Build

```sh
cd driver/RTL88WiFi && make rtl88wifi   # output: build/out/RTL88WiFi.kext
```

Requires the Xcode Command Line Tools and `python3`. Load the kext through
OpenCore, not `make install`. Host tests: [tests/README.md](tests/README.md).
Changes: [CHANGELOG.md](CHANGELOG.md).

## Status

Discontinued: no further development, fixes or releases are planned. The
source is GPL-2.0, so anyone may fork it and continue.

Tested on an HP 15-da0003tu (i3-8130U), OpenCore 1.0.7, macOS 14.8.9.

## License

GPL-2.0. See [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md).
