# WiFi Security Monitor
![Platform](https://img.shields.io/badge/Platform-ESP8266-blue)
![Framework](https://img.shields.io/badge/Framework-PlatformIO-orange)
![Language](https://img.shields.io/badge/C%2B%2B-17-blue)
![License](https://img.shields.io/badge/License-MIT-green)

A passive, receive-only 802.11 anomaly detector for ESP8266, built as a
university-lab research platform for studying WiFi management-frame attacks
and how to detect them.

**This project transmits nothing.** It listens to management frames already
present in the air and flags patterns consistent with deauthentication
floods and rogue/evil-twin access points. There is no packet injection, no
deauth/disassoc generation, and no captive-portal credential capture
anywhere in this codebase — by design, not as an afterthought.

---

## 1. Motivation

Wi-Fi's management frames (beacons, probe requests/responses,
deauthentication, disassociation) are, on most deployed networks, sent
**unencrypted and unauthenticated**. That design choice — dating back to the
original 802.11 standard — is what makes attacks like deauthentication
flooding and evil-twin access points possible: any device can forge a
management frame claiming to be an access point (or a client) it isn't.

Understanding *why* these attacks work, and what a real-time detector looks
like, is a standard and well-documented area of wireless security research.
This project gives students a cheap, self-contained ESP8266 platform to:

- Capture and parse live 802.11 management frames
- Recognize the signatures of deauth/disassoc floods and rogue APs
- Build and extend detection heuristics incrementally
- Visualize alerts on a simple read-only dashboard

The threat model here is defensive: **"how would a monitoring system on a
university network notice this attack class, and how quickly?"**

## 2. Background: relevant 802.11 frame types

| Frame type | Subtype byte | Purpose | Why it's exploitable |
|---|---|---|---|
| Beacon | `0x80` | AP periodically announces its presence (SSID, channel, capabilities) | Can be forged to impersonate any AP (rogue AP / evil twin) |
| Probe Request/Response | `0x40` / `0x50` | Client/AP discovery handshake | Reveals client's preferred-network list; can be spoofed |
| Deauthentication | `0xC0` | AP or client tears down an association | Unauthenticated in pre-802.11w networks — anyone can forge one |
| Disassociation | `0xA0` | Similar to deauth, different 802.11 state transition | Same weakness as deauth |

**802.11w (Protected Management Frames / PMF)** cryptographically signs
deauth/disassoc frames, which is the actual long-term fix for the deauth
class of attacks. Part of this project's value is demonstrating *why* PMF
matters by showing how trivially the unprotected version can be detected
being abused.

## 3. Architecture

```
                 ┌─────────────────┐
   RF (air) ───► │   FrameSniffer   │  promiscuous-mode capture,
                 │                  │  parses raw 802.11 headers
                 └────────┬─────────┘
                          │ ParsedFrame
              ┌───────────┼────────────┐
              ▼                        ▼
     ┌─────────────────┐    ┌──────────────────┐
     │  DeauthDetector  │    │ RogueAPDetector   │
     │ rate/threshold   │    │ duplicate SSID /  │
     │ analysis on      │    │ BSSID mismatch    │
     │ deauth+disassoc  │    │ analysis on       │
     └────────┬─────────┘    └─────────┬─────────┘
              │        Alert            │
              └───────────┬─────────────┘
                           ▼
                 ┌──────────────────┐
                 │   AlertLogger     │  timestamped ring buffer,
                 │                   │  Serial output
                 └────────┬──────────┘
                           ▼
                 ┌──────────────────┐
                 │  WebDashboard     │  read-only status page,
                 │                   │  no forms, no input capture
                 └──────────────────┘
```

**Design principle:** data flows one direction, air → sniffer → detectors →
logger → dashboard. Nothing in this pipeline writes back to the radio.

### Modules

- **`FrameSniffer`** — configures the ESP8266 radio in promiscuous mode via
  the SDK's `wifi_set_promiscuous_rx_cb`, parses the raw buffer into a
  `ParsedFrame` struct (type/subtype, source/dest/BSSID MACs, channel, RSSI,
  sequence number), and dispatches it to registered listeners.
- **`DeauthDetector`** — tracks the rate of deauth/disassoc frames per
  source MAC in a sliding time window; raises an alert when the rate
  exceeds a configurable threshold (a strong signal of an active flood,
  since legitimate deauths are infrequent).
- **`RogueAPDetector`** — periodically active-scans (`WiFi.scanNetworks`,
  the same benign API used by any WiFi analyzer app) and flags SSIDs that
  appear on multiple BSSIDs/channels inconsistently, a common evil-twin
  signature.
- **`AlertLogger`** — a small ring buffer of timestamped alerts, printed to
  Serial and made available to the dashboard.
- **`WebDashboard`** — a minimal `ESP8266WebServer` page that renders
  current alert state. Read-only: no `<form>` elements, no credential
  fields, no redirect tricks.

## 4. Build instructions

1. Install [PlatformIO](https://platformio.org/) (VS Code extension or CLI).
2. Clone this repo and open the folder in PlatformIO.
3. Connect an ESP8266 board (NodeMCU v2 or Wemos D1 Mini).
4. `pio run --target upload`
5. `pio device monitor` to view Serial alert output.
6. Connect to the device's IP (printed on boot) to view the dashboard.

## 5. Ethical use & scope

- **Lab/university use only**, on networks and hardware you own or have
  explicit written authorization to monitor.
- Promiscuous-mode capture of management frames from third-party networks
  may be restricted by local law even when no attack is performed — check
  your institution's policy and applicable regulations before operating
  this off an isolated test network.
- This project intentionally excludes any transmit/injection capability.
  Extending it to send deauth, disassoc, or spoofed beacon frames would
  turn it into an attack tool and is out of scope for this repository.

## 6. Suggested extensions (good next steps for coursework)

- Add a `ProbeRequestLogger` to study client-tracking privacy leakage.
- Correlate `DeauthDetector` alerts with RSSI to estimate attacker
  proximity.
- Export alerts over MQTT to a central dashboard for a multi-node deployment.
- Add unit tests for the frame parser using PlatformIO's native test runner
  (no radio hardware required — feed it captured byte arrays).

## 7. References

- IEEE 802.11-2020 standard, clause 9 (Frame formats)
- IEEE 802.11w-2009 (Protected Management Frames)
- Espressif ESP8266 Non-OS SDK API reference (promiscuous mode)
- Bellardo & Savage, *"802.11 Denial-of-Service Attacks: Real Vulnerabilities
  and Practical Solutions"*, USENIX Security 2003

  ## Limitations

- ESP8266 monitors one WiFi channel at a time.
- Hidden SSIDs cannot always be identified.
- PMF-protected networks reduce detectable deauthentication attacks.
- Detection is heuristic-based and may produce false positives.
