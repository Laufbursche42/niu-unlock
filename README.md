# Laufbursche NIU KQi Tool (read-out)

A static web page that reads a NIU KQi kick-scooter over Web Bluetooth. Pick your KQi family, enter
the device keys, connect, and the page runs the handshake and displays live telemetry, read-only
settings and advanced status. Nothing to install: no app store, no signing, no developer account. It
runs in **Bluefy** on iOS and in **Chrome** or Edge on Android or desktop.

> **Read-out only. This tool does not tune anything.** It connects, runs the handshake and shows what
> the scooter reports. It sends no state-changing commands. The one frame it writes is the refresh
> heartbeat (`foc_k_cmd=16`), a telemetry nudge that changes no setting.

> **This is a feasibility study.** It exists to show what NIU's KQi Bluetooth protocol lets a client
> read, not to be a finished product. The protocol was reconstructed from the official app
> (com.niu.manager 5.12.2) and is documented byte for byte in [PROTOCOL.md](PROTOCOL.md). It is not
> verified on a vehicle. Error-free operation is not promised and there is no warranty of any kind.

Run it yourself, no build step and no dependencies: serve the folder over a local HTTP server. Opening
`index.html` directly as a `file://` URL will not work, the page fetches its own documents and browsers
block that over `file://`.

```
python -m http.server 8000
```

Then open the printed address in a browser that supports Web Bluetooth.

## Why read-out only

Two grounded reasons, both from the reverse-engineering notes:

1. **The write/command path is unverified.** It is reconstructed from static analysis of the app and
   has never been run against a real vehicle. The device-side session-key formation is OPEN. Writing
   unverified frames to a live controller is out of scope for a read-out tool.
2. **The real speed cap is in firmware.** The hard top-speed cap sits in the encrypted, region-locked
   FOC firmware. No BLE command lifts it; setting `foc_k_def_max_speed` never gets past that cap
   (see [MODELL-FEATURE-MATRIX.md](MODELL-FEATURE-MATRIX.md)).

The tuning card on the page is shown greyed on purpose, so you can see what the protocol could do,
with the reason on each control. Nothing on it is wired to send.

## One tool for the whole KQi family

The BLE protocol is the same for every KQi and the BLE-e-bike variant: one GATT service
(`8ec94e30-...daea50`, notify `...e31`, write `...e32`), one handshake (verifyPwd1/verifyPwd2) and one
command set (`foc_k_*`). The only model-dependent parameter is the speed prefix `foc_k_cmd` (10 for
Gen 1 and the e-bike, 30 for Gen 2 / the 90-100-200 series), which lives on the write path only and is
not sent by this tool. You pick the family from the dropdown because the real product type comes from
NIU's cloud and cannot be read reliably from the BLE name.

A full per-model, per-feature breakdown is in [MODELL-FEATURE-MATRIX.md](MODELL-FEATURE-MATRIX.md).

## The device keys (why you have to enter them)

NIU encrypts all BLE traffic with AES-128. The two keys live per vehicle on the NIU server and the app
downloads them after login (endpoint `v5/ble/bleinfo`, JSON fields `blePassword` and `bleAes`). They
cannot be computed from the MAC or serial number, so they cannot be baked into the tool. You enter them
yourself:

- **secret** (`blePassword`), 16 ASCII chars or 32 hex chars
- **aesSecret** (`bleAes`), 16 ASCII chars or 32 hex chars
- **MAC**, entered by hand because Web Bluetooth does not expose the address

Without these the handshake cannot run and the telemetry cannot be decrypted. The keys you enter stay
on your device (they are remembered in this browser's local storage only).

## What it reads

- **Live telemetry:** speed, gear, range, set max speed (`21003C`), rated max speed (`21003B`),
  acceleration mode (raw, `210029`), error code (`110006`) and a status word.
- **Settings (read-only):** the same set/rated max speed, acceleration mode (raw) and gear, as a
  key/value list from the last decoded frame. The display unit is a write-only command in the
  protocol, so as a read value it is shown "unknown".
- **Advanced (read-only):** `realtime_status` (`110004`) and `function_status` (`110005`) as raw U32
  hex (bit meanings are undocumented, so no decoded flags), the error code, the raw decrypted data area
  of the last frame, and the resolved GATT service and notify/write UUIDs. A BLE firmware version is
  not readable over the protocol and shows "unknown".

## The handshake

After connecting, the page runs verifyPwd1/verifyPwd2:

1. It builds `firstKey` from your secret, the MAC and a timestamp, and sends verifyPwd1 (unencrypted).
2. The scooter's answer becomes the AES session key.
3. It sends verifyPwd2 to confirm, then the session is up and telemetry can be decrypted.

The session key is formed on the device side, so the handshake has to run against your real scooter.
The details are in [PROTOCOL.md](PROTOCOL.md).

## The log

The bottom log captures every byte sent and received, newest at the bottom, with a `HH:MM:SS`
timestamp, spaced hex and TX/RX colouring. **Anonymize log** is on by default and redacts MAC, keys,
the session key and raw device IDs, so a shared log is safe. You can copy it, clear it or save it as
`niu-unlock-log.txt`. A diagnostic log toggle adds raw GATT details, and "Diagnostics: all devices"
lists the GATT services of any picked device.

## Browser support

- **iOS:** the **Bluefy** browser. Safari and every other iOS browser run on the Safari engine, which
  has no Web Bluetooth at all.
- **Android or desktop:** **Chrome** or another Chromium browser (Edge). Web Bluetooth is built in.

There is no OTA firmware flashing here.

## Project structure

```
index.html                  - the single page: cards, dialogs, the model dropdown
aes.js                      - AES-128-ECB (fixed S-box), CRC16, checksum, frame and handshake builders
app.js                      - connect, handshake state machine, telemetry decode, read-out UI, log
i18n.js                     - the German and English string table
styles.css                  - theme and layout
GUIDE.de.md / GUIDE.en.md   - the step-by-step guide (German / English)
PROTOCOL.md                 - the byte-level protocol
MODELL-FEATURE-MATRIX.md    - what works per model and feature
PRIVACY.de.md / PRIVACY.md  - privacy note (German / English)
LICENSE.md / LICENSE.de.md  - license (English is binding, German is a reading aid)
TRADEMARKS.md / TRADEMARKS.de.md - trademark note
```

## Self-tests

On load the page runs two self-tests and writes the result to the log:

- the AES-128 FIPS-197 block vector (`69c4e0d86a7b0430d8cdb78070b4c55a`),
- a block frame for 25.0 km/h whose data area decrypts back to `210016000A21003C00FA000000000000`.

## Legal

This tool only reads and changes no setting. Use it on your own vehicle only. Everything you do with
this page is at your own risk.

## Trademarks

An independent project, not affiliated with NIU. "NIU" and "KQi" are trademarks of their respective
owner and are used here only to say which scooters this page works with.
