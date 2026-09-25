# Privacy notice

This web application is built to keep your data on your device. This notice says exactly what it does
with your data and what it does not.

## In short

The application collects nothing. There is no sign-in, no analytics, no telemetry, no tracking, no ads,
no cookies and no third-party scripts. Nothing goes to the developer or to any NIU backend.

## What the application processes and where it stays

Everything below stays on your device and is uploaded nowhere:

- The device keys you enter (secret, aesSecret, MAC). They are held in this device's local browser
  storage so you do not have to type them on every visit. They never leave your device over the network.
  On a shared device you should clear them through the browser after use.
- The scooter's live data, read over Bluetooth LE (the raw answers the scooter sends back). This tool
  only reads; it changes no setting on the vehicle.
- The settings you make (model choice). They live locally on this device.
- The log on the screen. It lives only in the open page during your session and is not uploaded. When
  you share it, the "Anonymize log" option (on by default) redacts the MAC, keys, the session key and
  raw device IDs.

## The only network connection

The application makes a connection in exactly two cases, no other:

### 1. Loading the page

When you open or reload the page, your browser fetches the static files from the host: `index.html`,
`aes.js`, `app.js`, `i18n.js`, `styles.css`, the documents and the icon. The host sees the usual access
logs of any website: your IP address and which file you requested. It never sees scooter data, never
your keys and never any command. Those things reach no server at all.

### 2. Bluetooth LE to the scooter

A local radio connection to your scooter over Web Bluetooth. This is not an internet connection; no data
leaves your device over the network. The requests (the read heartbeat) and the answers run only between
your browser and the scooter.

## No developer or NIU backend

Nothing goes to the developer or to any NIU backend. There is no cloud account and no server of this
project that accepts your data. By comparison, NIU's original app signs you in and talks extensively to
a backend (account, GPS, ride data). This application does none of that.

## Contact

For privacy questions, reach the author (Laufbursche) on GitHub: https://github.com/Laufbursche42
