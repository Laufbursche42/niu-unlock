# Anleitung: Laufbursche NIU KQi Tool (Auslesen)

> **Machbarkeitsstudie.** Dieses Werkzeug zeigt, was sich per Bluetooth aus einem NIU KQi auslesen
> lässt. Es ist kein fertiges Produkt. Fehlerfreier Betrieb wird nicht versprochen, es gibt keinerlei
> Gewährleistung. Was du hier tust, tust du auf eigenes Risiko und nur am eigenen Fahrzeug.

> **Nur Auslesen.** Dieses Werkzeug liest aus und ändert keine Einstellung. Der einzige Frame, den es
> schreibt, ist der Refresh-Heartbeat (foc_k_cmd=16), ein reiner Anstoß zum Nachliefern der
> Telemetrie. Tuning ist bewusst deaktiviert (Gründe in Abschnitt 8).

## 1. Was du brauchst

Alles passiert im Browser über Web Bluetooth: Modell wählen, Schlüssel eintragen, verbinden, Werte
lesen. Es gibt nichts zu installieren. Gebraucht wird:

**Ein Browser, der Web Bluetooth kann.**

- **iOS:** der Browser **Bluefy** (kostenlos im App Store). Safari und jeder andere iOS-Browser laufen
  auf der Safari-Engine, die überhaupt kein Web Bluetooth hat.
- **Android oder Desktop:** **Chrome** oder Edge. Web Bluetooth ist eingebaut, kein Extra-Browser
  nötig.

**Ein NIU KQi.** Unterstützt sind alle KQi-Tretroller (Gen 1 und Gen 2) plus die BLE-E-Bike-Variante.

**Die Geräte-Schlüssel.** Dazu gleich mehr in Abschnitt 2.

---

## 2. Die Geräte-Schlüssel besorgen

NIU verschlüsselt den gesamten BLE-Verkehr mit AES-128. Die dafür nötigen Schlüssel liegen pro
Fahrzeug auf dem NIU-Server. Die App lädt sie nach dem Login vom Endpunkt `v5/ble/bleinfo`. Sie lassen
sich NICHT aus MAC oder Seriennummer berechnen und können darum nicht im Tool stehen. Du musst sie
selbst eintragen:

- **secret** (Server-Feld `blePassword`): 16 Zeichen oder 32 Hexzeichen.
- **aesSecret** (Server-Feld `bleAes`): 16 Zeichen oder 32 Hexzeichen.
- **MAC**: die Bluetooth-Adresse deines Scooters, Form `AA:BB:CC:DD:EE:FF`.

Woher bekommst du secret und aesSecret? Aus dem eigenen NIU-Konto, das an genau diese Seriennummer
gebunden ist. Praktische Wege sind ein Mitschnitt des App-Verkehrs (die App holt die Werte beim
Verbinden) oder das Auslesen des lokalen App-Caches. Ohne diese Werte läuft der Handshake nicht und die
Telemetrie lässt sich nicht entschlüsseln. Die MAC zeigt Web Bluetooth aus Datenschutzgründen nicht an,
darum trägst du sie von Hand ein (sie steht in der NIU-App unter Geräteinfo oder auf dem Aufkleber).

Die eingetragenen Werte bleiben auf deinem Gerät und merkt sich der Browser lokal.

---

## 3. Modell wählen

Oben im Dropdown wählst du deine KQi-Familie. Beim Auslesen ist das nur informativ: Die Wahl benennt
den Speed-Vorspann des Schreibpfads (Gen 1 -> 10, Gen 2 / 90-100-200 -> 30), den dieses Werkzeug nicht
sendet. Verbinden, Handshake und Auslesen laufen für alle Familien gleich.

---

## 4. Verbinden

1. Öffne die Seite in Bluefy oder Chrome.
2. Schalte den KQi ein. Er muss ein paar Meter neben dem Handy bleiben.
3. Trage secret, aesSecret und MAC ein.
4. Tippe auf **Verbinden** und wähle deinen KQi in der Auswahl des Browsers. Da NIU keinen festen
   Namens-Präfix sendet, erscheinen dort alle Bluetooth-Geräte in Reichweite. Erkenne deinen KQi am
   angezeigten Namen.
5. Danach läuft automatisch der Handshake (verifyPwd1 dann verifyPwd2). Beobachte die Statusanzeige
   oben rechts: erst `connecting`, dann `Handshake`, dann `connected`.

**Android: Standort muss an sein.** Chrome scannt auf Android nur nach Bluetooth, wenn die
Standortdienste an sind und Chrome die Berechtigung Geräte in der Nähe hat. Sonst bleibt die
Geräteliste leer. Schließe außerdem die NIU-App vorher ganz, sonst hält sie die Verbindung.

Im Log siehst du jeden Schritt des Handshakes. Steht am Ende `session established`, ist die Sitzung
aktiv. Zeigt der Log `random1 echo MISMATCH`, stimmen secret oder MAC nicht.

---

## 5. Live-Werte lesen

Sobald nach dem Handshake Daten ankommen, füllen sich die Kacheln (Geschwindigkeit, Gang,
Restreichweite, gesetzter und werksseitiger Max-Speed, Beschleunigungs-Modus, Fehler, Statuswort).
Kommt nichts an, tippe auf **Live-Werte anfordern (Heartbeat)**. Der Heartbeat stößt nur eine
Aktualisierung an und ändert keine Einstellung. Das Notification-Format ist nur teilweise belegt,
deshalb bleibt manches ein Strich. Skalierungen wie Speed /10 sind aus der App abgeleitet und am Gerät
zu bestätigen. Die rohen Daten stehen immer im Log.

---

## 6. Einstellungen und erweiterter Status (nur lesen)

Die Karte **Einstellungen** zeigt als Schlüssel/Wert-Liste den gesetzten Max-Speed (21003C), den
werksseitigen Max-Speed (21003B), den Beschleunigungs-Modus (210029, roh) und den Gang (210009). Die
Anzeige-Einheit ist im Protokoll nur ein Schreib-Kommando (12/13) und als Lesewert nicht belegt, darum
steht dort "unbekannt".

Die Karte **Erweitert** zeigt die rohen Statuswörter realtime_status (110004) und function_status
(110005) als U32-Hex. Die Bit-Bedeutungen sind nicht belegt (OFFEN), darum steht dort nur das rohe
Wort, nie erfundene Einzel-Flags. Dazu der Fehlercode, der rohe entschlüsselte Datenbereich des letzten
Frames und die aufgelösten GATT-UUIDs (Dienst, notify, write). Eine BLE-Firmware-Version ist per
Protokoll nicht auslesbar und steht als "unbekannt".

---

## 7. Log kopieren und teilen

Der Log unten ist der vollständige Mitschnitt jedes gesendeten und empfangenen Bytes, neueste Zeile
unten. **Log anonymisieren** ist standardmäßig an und schwärzt MAC, secret, aesSecret, den
Sitzungsschlüssel und rohe Geräte-IDs, damit ein geteilter Log sicher ist. Mit **Log kopieren**
bekommst du den Mitschnitt als Text, mit **Als .txt speichern** als Datei. Für Geräte, die nicht sauber
auftauchen, hilft **Diagnose: alle Geräte**, der nach dem Verbinden die GATT-Dienste plus
Characteristics auflistet.

---

## 8. Warum kein Tuning

Die Tuning-Karte ist sichtbar, aber jede Steuerung ist deaktiviert und mit nichts verbunden. Zwei
Gründe, beide belegt:

- Der Schreib- beziehungsweise Kommandopfad ist nur aus der statischen Analyse der App rekonstruiert
  und an keinem Fahrzeug verifiziert. Die geräteseitige Bildung des Sitzungsschlüssels bleibt OFFEN.
- Der reale Speed-Deckel sitzt in der verschlüsselten, region-gebundenen FOC-Firmware. Kein
  BLE-Kommando hebt ihn an. Das Setzen von foc_k_def_max_speed kommt über diesen harten Deckel nicht
  hinaus.

Die Byte-Details des dokumentierten Schreibpfads stehen in PROTOCOL.md. Dieses Werkzeug führt sie
bewusst nicht aus.

---

## 9. Grenzen, die man kennen sollte

- Der Sitzungsschlüssel wird vom Gerät gebildet. Der Handshake muss real gegen dein Fahrzeug laufen, ein
  rein offline berechneter Schlüssel geht nicht.
- Es gibt kein Firmware-Flashen und kein OTA in diesem Tool.
- Das ganze Protokoll stammt aus der statischen Analyse der App. Nichts ist am Fahrzeug verifiziert.

---

## 10. Recht

Dieses Werkzeug liest nur aus und ändert keine Einstellung. Nutzung ausschließlich am eigenen Gerät und
auf eigenes Risiko.
