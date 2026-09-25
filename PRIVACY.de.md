# Datenschutzerklärung

Diese Webanwendung ist darauf gebaut, deine Daten auf deinem Gerät zu halten. Diese Erklärung sagt
genau, was sie mit deinen Daten tut und was nicht.

## Kurz gefasst

Die Anwendung sammelt nichts. Es gibt keine Anmeldung, keine Statistik, keine Telemetrie, keine
Verfolgung, keine Werbung, keine Cookies und keine Skripte von Dritten. Nichts geht an den Entwickler
oder an ein Backend von NIU.

## Welche Daten die Anwendung verarbeitet und wo sie bleiben

Alles Folgende bleibt auf deinem Gerät und wird nirgendwohin hochgeladen:

- Die Geräte-Schlüssel, die du einträgst (secret, aesSecret, MAC). Sie werden lokal im Browserspeicher
  dieses Geräts gehalten, damit du sie nicht bei jedem Besuch neu eingeben musst. Sie verlassen dein
  Gerät nie über das Netz. Auf einem geteilten Gerät solltest du sie nach der Nutzung über den Browser
  löschen.
- Die Live-Daten des Scooters, über Bluetooth LE gelesen (die rohen Antworten, die der Scooter
  zurückschickt). Dieses Werkzeug liest nur aus und ändert keine Einstellung am Fahrzeug.
- Die Einstellungen, die du triffst (Modell). Sie leben lokal auf diesem Gerät.
- Das Protokoll auf dem Bildschirm. Es lebt nur in der offenen Seite während deiner Sitzung, wird
  nicht hochgeladen. Beim Teilen schwärzt die Option "Log anonymisieren" (standardmäßig an) MAC,
  Schlüssel, den Sitzungsschlüssel und rohe Geräte-IDs.

## Die einzige Netzverbindung

Die Anwendung baut in genau zwei Fällen eine Verbindung auf, in keinem anderen:

### 1. Laden der Seite

Wenn du die Seite öffnest oder neu lädst, holt dein Browser die statischen Dateien vom Anbieter, also
`index.html`, `aes.js`, `app.js`, `i18n.js`, `styles.css` und das Symbol. Der Anbieter sieht dabei die
üblichen Zugriffsprotokolle jeder Website: deine IP-Adresse und welche Datei du abgerufen hast. Er
sieht nie Daten des Scooters, nie deine Schlüssel und nie Kommandos. Diese Dinge erreichen überhaupt
keinen Server.

### 2. Bluetooth LE zum Scooter

Eine lokale Funkverbindung zu deinem Scooter über Web Bluetooth. Das ist keine Internetverbindung,
dafür verlassen keine Daten dein Gerät über das Netz. Die Leseanfragen (der Refresh-Heartbeat) und die
Antworten laufen ausschließlich zwischen deinem Browser und dem Scooter.

## Kein Backend des Entwicklers oder von NIU

Nichts geht an den Entwickler oder an ein Backend von NIU. Es gibt kein Konto in einer Cloud und
keinen Server dieses Projekts, der deine Daten annimmt. Zum Vergleich: die Original-App von NIU meldet
dich an und spricht ausgiebig mit einem Backend (Konto, GPS, Fahrtdaten). Diese Anwendung tut nichts
davon.

## Kontakt

Bei Fragen zum Datenschutz wende dich an den Autor (Laufbursche) auf GitHub:
https://github.com/Laufbursche42
