# NIU KQi - Modell- und Feature-Matrix (was geht per Bluetooth)

Diese Übersicht sagt ehrlich, was das Protokoll pro Modell und Feature über Bluetooth zulässt.
Grundlage ist die statische Analyse der App com.niu.manager 5.12.2 (jadx plus apktool-smali). Nichts
davon ist am Fahrzeug gegengeprüft. Trennung: BELEGT = aus dem App-Code mit Fundstelle, ERSCHLOSSEN =
abgeleitet, OFFEN = am Gerät zu klären.

> WICHTIG: Die Spalte "geht per BT" beschreibt, was das **Protokoll** erlaubt, nicht was dieses
> Werkzeug tut. Dieses Werkzeug ist reines Auslesen. Es führt nur aus: Verbinden plus Handshake und
> Live-Telemetrie (plus den Heartbeat foc_k_cmd=16, der keine Einstellung ändert). Alle Schreib-Toggles
> unten (Speed-Zielwert, Kickstart, Tempomat, Fast-Lock, Einheit) sind nur DOKUMENTIERT und in der UI
> deaktiviert - sie werden nicht gesendet.

## Kernaussage in einem Satz

EIN Tool bedient alle KQi (Gen 1 und Gen 2) plus die BLE-E-Bike-Variante: gleicher GATT-Dienst
(`8ec94e30-...daea50`, Notify `...e31`, Write `...e32`), gleicher Handshake (verifyPwd1/verifyPwd2)
und dasselbe Kommandoset (`foc_k_*`). Der einzige modellabhängige Parameter im Sendepfad ist der
Speed-Vorspann `foc_k_cmd` (10 bei Gen 1, 30 bei Gen 2).

## Matrix Modell x Feature

| Feature | KQi Gen 1 (bleKickScooter) | KQi Gen 2 (V2 / 90-100-200) | BLE-E-Bike (E_BIKE) | geht per BT | dieses Tool |
|---|---|---|---|---|---|
| Verbinden plus Handshake | ja (v2, BleVersion >= 20) | ja (v2) | ja (v2) | JA | FÜHRT AUS |
| Speed-Zielwert setzen | ja, Vorspann `foc_k_cmd=10` | ja, Vorspann `foc_k_cmd=30` | ja, Vorspann `foc_k_cmd=10` | JA - aber nur bis Firmware-Deckel | nur dokumentiert (deaktiviert) |
| Kickstart / Zero-Launch | ja (6 an / 5 aus) | ja (6/5) | ja (6/5) | JA - reiner Toggle | nur dokumentiert (deaktiviert) |
| Tempomat / Cruise | ja (7 an / 8 aus), wenn SupFocNav | ja (7/8), wenn SupFocNav | ja (7/8), wenn SupFocNav | JA - falls Modell-Support | nur dokumentiert (deaktiviert) |
| Fast-Lock | ja (18 an / 19 aus) | ja (18/19) | ja (18/19) | JA - reiner Toggle | nur dokumentiert (deaktiviert) |
| Anzeige-Einheit km/h / mph | ja (12 / 13) | ja (12/13) | ja (12/13) | JA - reiner Toggle | nur dokumentiert (deaktiviert) |
| Live-Telemetrie (Speed, Gang, Reichweite, Fehler) | teilweise | teilweise | teilweise | TEILWEISE - Format teils unbelegt | LIEST AUS |

## Erklärung je Feature

### Speed-Zielwert (foc_k_def_max_speed, Code 21003C)

- BELEGT: Das Tool schreibt `foc_k_cmd=<Vorspann>` gefolgt von `foc_k_def_max_speed=<km/h * 10>` in
  einem 16-Byte-Block (feature-kommandos.md Abschnitt 1, protokoll-final.md Abschnitt 1). Der Wert ist
  U16 big-endian in 0.1-km/h-Schritten (25.0 km/h -> 250 -> `00FA`).
- Vorspann-Split (BELEGT, feature-kommandos.md Abschnitt 4): `SkateCarLinkReviseActivity.m44889g3`
  wählt `L1||M1 ? 30 : 10`. L1 = bleKickScooterV2, M1 = KQi mit Version 90/100/200. Das E-Bike ist
  weder L1 noch M1, bekommt also 10 wie Gen 1.
- WICHTIG (BELEGT speed-modus.md, Memory niu-speed-deckel-firmware.md): Der numerische Zielwert geht
  per BLE durch, aber der real erreichbare Speed wird vom FOC-Controller auf den in der
  region-abhängigen Firmware hinterlegten Deckel begrenzt. Das reine Setzen von `foc_k_def_max_speed`
  kommt über diesen harten Deckel NICHT hinaus. Ob dein Controller einen höheren Wert real fährt,
  zeigt nur der Test am Fahrzeug.

### Kickstart / Zero-Launch (foc_k_cmd 6/5)

- BELEGT (feature-kommandos.md Abschnitt 2): `foc_k_cmd=6` schaltet Zero-Launch AN (Anfahren aus dem
  Stand ohne Antreten), `foc_k_cmd=5` schaltet es AUS (Kick zum Anfahren nötig). Die
  Controller-Bedeutung der Zahlen ist fest, unabhängig vom Modell.
- Kein Firmware- oder Region-Deckel: reiner Funktions-Schalter, wirkt sofort per Bluetooth.
- Hinweis: Der reine Anfahr-Geschwindigkeitswert ist ein separates Feld (`foc_k_no_zero_start`,
  Code 21002B) über einen anderen Sendepfad und wird von diesem Tool nicht gesetzt. Das 5/6-Kommando
  schaltet nur die Funktion an oder aus.

### Tempomat / Cruise (foc_k_cmd 7/8)

- BELEGT (feature-kommandos.md Abschnitt 3): `foc_k_cmd=7` an, `foc_k_cmd=8` aus. Feste Werte, keine
  Polaritäts-Inversion.
- Voraussetzung (BELEGT): Der Cruise-Schalter ist in der App nur sichtbar, wenn `getSupFocNav()=="1"`.
  Ob dein konkretes Modell die Funktion unterstützt, ist ein SKU-Flag aus der Cloud und im Tool nicht
  prüfbar. Ist die Funktion nicht vorhanden, ignoriert der Controller das Kommando vermutlich.
- Kein Firmware- oder Region-Deckel: reiner Funktions-Schalter.

### Fast-Lock (foc_k_cmd 18/19)

- BELEGT (feature-kommandos.md Abschnitt 5): `foc_k_cmd=18` an, `foc_k_cmd=19` aus. Reiner Toggle.

### Anzeige-Einheit (foc_k_cmd 12/13)

- BELEGT (feature-kommandos.md Abschnitt 5): `foc_k_cmd=12` = km/h, `foc_k_cmd=13` = mph. Reiner
  Toggle, kein Deckel.

### Live-Telemetrie

- BELEGT (telemetrie.md): Die App kennt code-präfixierte Push-Felder `foc_k_rt_speed` (21000B, U16),
  `foc_k_gears` (210009, U8), `db_k_realtime_status` (110004, U32), `db_k_function_status` (110005,
  U32) und `db_k_f_code` (110006, U8). Die Restreichweite kommt als `db_k_estimated_mileage` (11000D,
  U16) vom Display-Board.
- Das Tool entschlüsselt eingehende Block-Frames (0122/0102) mit dem Sitzungsschlüssel und sucht diese
  Codes darin. Skalierungen (z. B. Speed /10) sind aus den App-Records abgeleitet und am Gerät zu
  bestätigen. OFFEN: Ob die Felder per Notify gepusht oder gepollt werden und die genaue Framerahmung
  der Notifications sind nicht hart belegt. Unbekannte Felder bleiben als "-" stehen.

## Was NICHT per BLE geht

- Kein Firmware-Flashen und kein OTA in diesem Tool. Der harte Speed-Deckel sitzt in der
  verschlüsselten FOC-Firmware und lässt sich per BLE-Kommando nicht anheben (nur Region-Firmware zu
  flashen würde das ändern - kein Ziel dieses Werkzeugs).
- Nicht vom KQi-Profil bedient: Moped-Zubehör (Hub/Helm/Radar, Dienst `...daea52`, Version 21),
  Smart-Akku (eigenes Profil), TPMS-Reifensensor und Dashcam. Das sind keine Tuning-Ziele.

## Wichtiger Hinweis zu den Schlüsseln

Alle Kommandos setzen einen bestehenden AES-Sitzungsschlüssel voraus. Der entsteht erst im Handshake
aus dem Geräte-`secret` (blePassword) plus der Antwort des Scooters auf verifyPwd1. secret und
aesSecret kommen pro Fahrzeug vom NIU-Server (Endpunkt v5/ble/bleinfo) und lassen sich nicht aus MAC
oder Seriennummer berechnen. Ohne diese Werte nimmt der Scooter keine Kommandos an. Details in
PROTOCOL.md.
