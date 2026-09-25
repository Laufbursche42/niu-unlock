# Guide: Laufbursche NIU KQi Tool (read-out)

> **Feasibility study.** This tool shows what can be read out of a NIU KQi over Bluetooth. It is not a
> finished product. Error-free operation is not promised and there is no warranty of any kind. Whatever
> you do here, you do at your own risk and on your own vehicle only.

> **Read-out only.** This tool reads and changes no setting. The only frame it writes is the refresh
> heartbeat (foc_k_cmd=16), a pure nudge to make the scooter re-send telemetry. Tuning is disabled on
> purpose (reasons in section 8).

## 1. What you need

Everything happens in the browser over Web Bluetooth: pick the model, enter the keys, connect, read the
values. There is nothing to install. You need:

**A browser that supports Web Bluetooth.**

- **iOS:** the **Bluefy** browser (free on the App Store). Safari and every other iOS browser run on
  the Safari engine, which has no Web Bluetooth at all.
- **Android or desktop:** **Chrome** or Edge. Web Bluetooth is built in, no extra browser needed.

**A NIU KQi.** Supported are all KQi kick-scooters (Gen 1 and Gen 2) plus the BLE-e-bike variant.

**The device keys.** More on those in section 2.

---

## 2. Getting the device keys

NIU encrypts all BLE traffic with AES-128. The keys live per vehicle on the NIU server. The app
downloads them after login from the endpoint `v5/ble/bleinfo`. They cannot be computed from the MAC or
serial number, so they cannot be baked into the tool. You enter them yourself:

- **secret** (server field `blePassword`): 16 chars or 32 hex chars.
- **aesSecret** (server field `bleAes`): 16 chars or 32 hex chars.
- **MAC**: your scooter's Bluetooth address, form `AA:BB:CC:DD:EE:FF`.

Where do secret and aesSecret come from? From your own NIU account, which is bound to that exact serial
number. Practical routes are a capture of the app's traffic (the app fetches the values on connect) or
reading the local app cache. Without them the handshake cannot run and the telemetry cannot be
decrypted. Web Bluetooth does not reveal the MAC for privacy reasons, so you enter it by hand (it is in
the NIU app device info or on the sticker).

The values you enter stay on your device and are remembered by the browser locally.

---

## 3. Pick the model

The dropdown at the top selects your KQi family. On a read-out tool this is only informational: it names
the write-path speed prefix (Gen 1 -> 10, Gen 2 / 90-100-200 -> 30) that this tool does not send.
Connect, handshake and read-out are identical for all families.

---

## 4. Connect

1. Open the page in Bluefy or Chrome.
2. Turn the KQi on. Keep it a few metres from the phone.
3. Enter secret, aesSecret and MAC.
4. Tap **Connect** and pick your KQi in the browser chooser. Because NIU sends no fixed name prefix, all
   Bluetooth devices in range appear there. Recognise your KQi by the name shown.
5. The handshake then runs automatically (verifyPwd1 then verifyPwd2). Watch the status pill top right:
   first `connecting`, then `handshake`, then `connected`.

**Android: location must be on.** Chrome on Android only scans for Bluetooth when location services are
on and Chrome has the nearby-devices permission. Otherwise the device list stays empty. Also close the
NIU app fully beforehand, or it holds the connection.

The log shows every step of the handshake. If it ends with `session established`, the session is up. If
the log shows `random1 echo MISMATCH`, the secret or MAC is wrong.

---

## 5. Read live values

Once data arrives after the handshake, the tiles fill in (speed, gear, range, set and rated max speed,
acceleration mode, error, status word). If nothing arrives, tap **Request live values (heartbeat)**. The
heartbeat only triggers a refresh and changes no setting. The notification format is only partly
documented, so some fields stay a dash. Scalings such as speed /10 are derived from the app and should
be confirmed on the vehicle. The raw data is always in the log.

---

## 6. Settings and advanced status (read-only)

The **Settings** card shows, as a key/value list, the set max speed (21003C), the rated max speed
(21003B), the acceleration mode (210029, raw) and the gear (210009). The display unit is only a write
command in the protocol (12/13) and is not documented as a read value, so it shows "unknown".

The **Advanced** card shows the raw status words realtime_status (110004) and function_status (110005)
as U32 hex. Their bit meanings are undocumented (OPEN), so only the raw word is shown, never invented
individual flags. It also shows the error code, the raw decrypted data area of the last frame and the
resolved GATT UUIDs (service, notify, write). A BLE firmware version is not readable over the protocol
and shows "unknown".

---

## 7. Copy and share the log

The log at the bottom is the full capture of every byte sent and received, newest line at the bottom.
**Anonymize log** is on by default and redacts the MAC, secret, aesSecret, the session key and raw
device IDs so a shared log is safe. **Copy log** gives you the capture as text, **Save as .txt** as a
file. For devices that do not show up cleanly, **Diagnostics: all devices** lists the GATT services plus
characteristics after connecting.

---

## 8. Why no tuning

The tuning card is visible, but every control is disabled and wired to nothing. Two reasons, both
documented:

- The write / command path is only reconstructed from static analysis of the app and not verified on
  any vehicle. The device-side session-key formation stays OPEN.
- The real speed cap sits in the encrypted, region-locked FOC firmware. No BLE command lifts it. Setting
  foc_k_def_max_speed never gets past that hard cap.

The byte-level detail of the documented write path is in PROTOCOL.md. This tool does not run it.

---

## 9. Limits worth knowing

- The session key is formed on the device side. The handshake has to run against your real vehicle; a
  key computed purely offline does not work.
- There is no firmware flashing and no OTA in this tool.
- The whole protocol comes from static analysis of the app. Nothing is verified on a vehicle.

---

## 10. Legal

This tool only reads and changes no setting. Use it on your own vehicle only and at your own risk.
