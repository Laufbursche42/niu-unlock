# NIU KQi - BLE-Protokoll (byte-genau, so wie das Tool es umsetzt)

Diese Datei dokumentiert das Protokoll genau so, wie `aes.js` plus `app.js` es senden. Grundlage ist
die statische Analyse der App com.niu.manager 5.12.2 (jadx plus apktool-smali), festgehalten in den
work/notes des NIU-Projekts. Nichts davon ist am Fahrzeug verifiziert. Zahlen sind big-endian.

## 1. GATT-Profil

- Dienst (KQi Gen 1 und Gen 2 plus BLE-E-Bike): `8ec94e30-f315-4f60-9fb8-838830daea50`
- Notify (Scooter -> App): `8ec94e31-...daea50`
- Write (App -> Scooter): `8ec94e32-...daea50`
- Zusätzlich Standard-HID `00001812-...` (SmartKey, nicht für Steuerkommandos).

Ältere oder CAN-Firmware kann die Varianten `...daea51` oder `...daea52` tragen. Das Tool trägt alle
drei als optionalServices ein und ordnet Notify plus Write nach dem Verbinden über die
Characteristic-Eigenschaften zu (notify/write), nicht über eine feste UUID. NIU advertisiert keinen
garantierten Namens-Präfix, darum wählt der Nutzer sein Gerät am angezeigten BLE-Namen aus.

## 2. Verschlüsselung

- Der gesamte Nutzverkehr ist AES-128 im Modus ECB ohne Padding (16-Byte-Blöcke). Kein IV, kein DES,
  kein HMAC.
- Integrität je Frame: eine additive 1-Byte-Prüfsumme (Summe aller Bytes mod 256) plus ein CRC16 im
  Klartextblock der Handshake-Frames (Init 0xFFFF, Polynom 0xA1E8, kein Final-XOR).
- Der Krypto-Kern in `aes.js` hat eine feste Rijndael-S-Box und besteht den FIPS-197-Selbsttest
  (Key `000102..0f`, Klartext `00112233..ff` -> `69c4e0d86a7b0430d8cdb78070b4c55a`).

### Woher die Schlüssel kommen (wichtig)

- `secret` (JSON-Feld `blePassword`, 16 Zeichen) und `aesSecret` (JSON-Feld `bleAes`, 16 Zeichen)
  liegen pro Fahrzeug auf dem NIU-Server. Die App lädt sie nach dem Login vom Endpunkt
  `v5/ble/bleinfo` je Seriennummer.
- Sie sind NICHT aus MAC oder Seriennummer ableitbar und können darum nicht im Tool stehen. Der
  Nutzer trägt secret, aesSecret und MAC selbst ein. Format je Feld: 16 ASCII-Zeichen oder 32 Hex.

## 3. Handshake (verifyPwd1 / verifyPwd2, v2-Zweig bei BleVersion >= 20)

### 3.1 firstKey

16-Byte-Klartextblock, dann AES-ECB mit dem Schlüssel `secret`:

| Offset | Länge | Inhalt |
|---|---|---|
| 0 | 4 | Zufall (random1) |
| 4 | 4 | (unixtime_s + 604800) big-endian; 604800 = 7 Tage |
| 8 | 6 | MAC ohne Trenner, sonst 000000000000 |
| 14 | 2 | CRC16 über Byte 0..13 |

`firstKey` = AES-ECB(block, secret) als 32 Hex. `random1` = die 4 Zufallsbytes.

### 3.2 verifyPwd1 (unverschlüsselt gesendet)

```
013401            Header
<firstKey>        32 Hex
SS                additive Prüfsumme über "013401" + firstKey
```

Länge 20 Byte. Die Antwort des Scooters wird 1:1 zum AES-Sitzungsschlüssel (das Tool nimmt die ersten
16 Byte der Antwort). Die ersten 8 Hex der Antwort sind das Echo von random1 (Prüfung).

OFFEN: Die geräteseitige Bildung der Antwort steht in der Controller-Firmware und ist aus der App
nicht belegbar. Der Handshake muss real gegen das eigene Gerät laufen (secret plus MAC vorausgesetzt)
und der zurückgegebene Wert wird verwendet. Ein rein offline berechneter Sitzungsschlüssel ist nicht
rekonstruierbar.

### 3.3 verifyPwd2

16-Byte-Klartextblock, dann AES-ECB mit dem Sitzungsschlüssel:

| Offset | Länge | Inhalt |
|---|---|---|
| 0 | 4 | Byte 4..7 der verifyPwd1-Antwort (resp1[8:16) in Hex) |
| 4 | 4 | Zufall (random2) |
| 8 | 6 | 000000000000 |
| 14 | 2 | CRC16 über Byte 0..13 |

```
011400            Header
<AES16>           AES-ECB(block, sessionKey), 32 Hex
SS                Prüfsumme über "011400" + AES16
```

Länge 20 Byte. Erfolg: die ersten 8 Hex der Antwort sind das Echo von random2. Danach nimmt der
Scooter Nutzkommandos an.

## 4. Kommando-Frame (Block-Write, NormalCmd Action 1)

> HINWEIS: Dieser Schreib-/Kommandopfad ist dokumentiert, wird von diesem Auslese-Werkzeug aber NICHT
> ausgeführt. Die Seite sendet nur die Handshake-Frames (verifyPwd1/verifyPwd2) und den
> Refresh-Heartbeat (foc_k_cmd=16), der keine Einstellung ändert. Alle zustandsändernden Kommandos
> unten stehen nur zur Dokumentation und sind in der UI deaktiviert.

Datenbereich: pro Feld `code` (6 Hex) gefolgt von `U16(wert)` (4 Hex big-endian), aneinander. Der
Klartext wird rechts mit `0`-Zeichen auf 16 Byte (32 Hex) aufgefüllt, dann AES-ECB mit dem
Sitzungsschlüssel.

```
0122              Header erster (und einziger) Block
00                Restframe-Zähler (1 Block -> 00)
<AES16>           16 Byte AES-ECB(Klartext16, sessionKey)
SS                Prüfsumme = ( 0x01 + 0x22 + 0x00 + Summe(AES16-Bytes) ) mod 256
```

-> 20 Byte GATT-Write auf die Write-Characteristic.

### Beispiel Speed 25.0 km/h (Gen 1, Vorspann 10)

| Feld | code | value | U16 | Beitrag |
|---|---|---|---|---|
| foc_k_cmd | 210016 | 10 | 000A | 210016000A |
| foc_k_def_max_speed | 21003C | 250 | 00FA | 21003C00FA |

Klartext auf 16 Byte gepolstert: `210016000A21003C00FA000000000000`. Genau dieser Wert kommt beim
Frame-Selbsttest nach AES-Entschlüsselung wieder heraus.

Gen 2 nutzt Vorspann 30 statt 10: Klartext dann `210016001E21003C...`.

## 5. foc_k_cmd-Werte (Referenz)

| Wert | Bedeutung | Klartext (nur foc_k_cmd) |
|---|---|---|
| 5 / 6 | Zero-Launch aus / an | 2100160005 / 2100160006 |
| 7 / 8 | Cruise an / aus | 2100160007 / 2100160008 |
| 10 / 11 | Dynamic-Mode an / aus (Gen 1) | 210016000A / 210016000B |
| 30 / 31 | Dynamic-Mode an / aus (Gen 2) | 210016001E / 210016001F |
| 12 / 13 | Einheit km/h / mph | 210016000C / 210016000D |
| 16 | Refresh / Heartbeat | 2100160010 |
| 18 / 19 | Fast-Lock an / aus | 2100160012 / 2100160013 |

## 6. Telemetrie (best-effort)

Eingehende Block-Frames werden mit dem Sitzungsschlüssel entschlüsselt. Im Klartext-Datenbereich sucht
das Tool code-präfixierte Felder:

| Code | Feld | Typ | Anzeige |
|---|---|---|---|
| 21000B | foc_k_rt_speed | U16 | Geschwindigkeit (/10 km/h, Skalierung angenommen) |
| 210009 | foc_k_gears | U8 | Gang |
| 21003B / 21003C | max_speed / def_max_speed | U16 | Max-Speed (/10 km/h) |
| 210029 | foc_k_throttle_mode_set | U8 | Beschleunigungs-/Gas-Modus (Rohbyte; Kodierung OFFEN) |
| 11000D | db_k_estimated_mileage | U16 | Restreichweite (Rohwert) |
| 110006 | db_k_f_code | U8 | Fehlercode |
| 110004 / 110005 | realtime_status / function_status | U32 | Statuswort (Hex) |

OFFEN: exakte Skalierungen, Bit-Bedeutungen der Statuswörter und ob Push oder Poll. Die Rohbytes
stehen immer im Log.

## 7. Grenzen und OFFEN

- Der real erreichbare Speed hängt am FOC-Firmware-Deckel (Region-Firmware). Reines Setzen von
  foc_k_def_max_speed kommt darüber nicht hinaus.
- Der Sitzungsschlüssel wird vom Gerät gebildet; der Handshake muss real gegen das eigene Fahrzeug
  laufen.
- CRC16 (Polynom 0xA1E8) ist aus dem App-Code übernommen, aber nicht am Gerät gegengeprüft.
- Der v1-Handshake (BleVersion < 20, sehr alte Firmware) ist hier nicht umgesetzt; aktuelle KQi laufen
  über v2.
- Dieses Werkzeug ist reines Auslesen. Der in Abschnitt 4 und 5 dokumentierte Schreibpfad wird nicht
  ausgeführt (Ausnahme: der Heartbeat foc_k_cmd=16, der keine Einstellung ändert). Grund: Der
  Schreibpfad ist an keinem Fahrzeug verifiziert und der reale Speed-Deckel sitzt in der
  verschlüsselten FOC-Firmware, nicht per BLE anhebbar.
