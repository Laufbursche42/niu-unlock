// Laufbursche NIU KQi Tool: a Web Bluetooth READ-OUT client for the NIU KQi BLE protocol.
// Copyright (c) 2026 Laufbursche (https://github.com/Laufbursche42)
//
// Read-out only. It connects to a NIU KQi, runs the verifyPwd1/verifyPwd2 handshake and displays
// live telemetry, read-only settings and advanced status. It sends NO state-changing commands. The
// only frame it writes is the refresh/heartbeat (foc_k_cmd=16), a telemetry nudge that changes no
// setting. The tuning card is shown greyed so the reader sees the protocol capability without any
// wired send. ONE protocol for all KQi (V1/V2) and the BLE-e-bike variant: GATT service
// 8ec94e30-...daea50, notify ...e31, write ...e32. The crypto/frame core is in aes.js (window.NIU).
//
// All protocol knowledge is from static analysis of the app com.niu.manager 5.12.2 (jadx plus
// apktool smali), documented in the NIU project's work/notes. Not verified on a vehicle.
// Runs in a Web Bluetooth browser: Bluefy on iOS, Chrome/Edge on Android and desktop.

'use strict';

const BUILD = 'v8';   // logged on load so a tester's log reveals which deployed build is running
const N = window.NIU;

// --------------------------- GATT constants ---------------------------
// The KQi data channel is fixed daea50 (from modelle-matrix.md / ble-architektur.md). We list all
// three variants plus HID as optionalServices and assign notify/write at run time by characteristic
// property, so the tool stays robust on daea51/52 firmware too.
const SVC_50 = '8ec94e30-f315-4f60-9fb8-838830daea50';
const SVC_51 = '8ec94e30-f315-4f60-9fb8-838830daea51';
const SVC_52 = '8ec94e30-f315-4f60-9fb8-838830daea52';
const HID    = '00001812-0000-1000-8000-00805f9b34fb';
const SERVICE_CANDIDATES = [SVC_50, SVC_51, SVC_52];
const OPTIONAL_SERVICES = [SVC_50, SVC_51, SVC_52, HID];

// --------------------------- field codes (KConfig, from telemetrie.md/feature-kommandos.md) ---
const FOC_K_CMD = '210016';   // U16, controller command (only value used here: 16 refresh/heartbeat)
const CMD_REFRESH = 16;       // heartbeat/refresh, telemetry nudge; changes no setting

// Telemetry read codes (documented; see PROTOCOL.md section 6, MODELL-FEATURE-MATRIX.md).
const C_RT_SPEED = '21000b';  // U16, /10 km/h (scaling assumed)
const C_GEARS    = '210009';  // U8
const C_MAX_RATED= '21003b';  // U16, /10, rated top speed (read-only)
const C_MAX_SET  = '21003c';  // U16, /10, set top speed
const C_ACCEL    = '210029';  // U8 foc_k_throttle_mode_set, value encoding unknown - shown as raw hex
const C_RANGE    = '11000d';  // U16, remaining range (unit unconfirmed)
const C_FCODE    = '110006';  // U8, error code (0 = OK)
const C_RT_STATUS= '110004';  // U32, status word (bit meanings unknown)
const C_FN_STATUS= '110005';  // U32, status word (bit meanings unknown)

// --------------------------- model register ---------------------------
// The only difference between the KQi families is the speed prefix (foc_k_cmd sent before the speed
// value on the WRITE path): Gen 1 (bleKickScooter) and e-bike = 10, Gen 2 = 30 (feature-kommandos.md
// section 4). This read-out tool never sends the speed value; the model choice is informational and
// only labels which family the greyed tuning card documents.
const MODELS = {
  gen1:  { label: 'KQi Gen 1 (KQi1 / bleKickScooter)', prefix: 10 },
  gen2:  { label: 'KQi Gen 2 / 90-100-200 series',     prefix: 30 },
  ebike: { label: 'NIU BLE e-bike',                    prefix: 10 },
  auto:  { label: 'auto / unknown (prefix 30)',        prefix: 30, uncertain: true },
};
const MODEL_ORDER = ['gen1', 'gen2', 'ebike', 'auto'];
const DEFAULT_MODEL = 'gen2';

// --------------------------- state ---------------------------
const LS_THEME = 'niu_theme', LS_MODEL = 'niu_model';
const LS_SECRET = 'niu_secret', LS_AES = 'niu_aes', LS_MAC = 'niu_mac';   // scan-ok: localStorage key names, not secret values
const LS_PUBLOG = 'niu_publiclog';

let modelKey = DEFAULT_MODEL;
let device = null, server = null, writeChar = null, notifyChar = null, usedService = null;
let connected = false, connecting = false;

// handshake state: 'idle' | 'await1' | 'await2' | 'ready'
let hsState = 'idle';
let secretBytes = null, aesBytes = null, macArr = null;
let sessionKey = null;       // Uint8Array(16), after the verifyPwd1 answer
let random1Hex = '', random2Hex = '';

// Last decoded read-out values (null until seen). Rendered into tiles + settings + advanced.
const live = {
  rtSpeed: null, gears: null, maxSet: null, maxRated: null, accelHex: null,
  range: null, fCode: null, rtStatus: null, fnStatus: null, rawData: null,
};

function $(id) { return document.getElementById(id); }

// --------------------------- log (lb-tool-web pattern: newest at bottom, autoscroll, redaction) ---
const SENT = '\x01';                       // wraps a sensitive span so the public-log mask is exact
function wrap(v) { return SENT + v + SENT; }
const state = { logBuffer: [], publicLog: true, diag: false };

// One central redaction filter; copy/save use the same anonymized text. Ported from lb-tool-web.
function redact(text) {
  let s = String(text);
  if (device && device.id) s = s.split(device.id).join('[redacted-id]');
  s = s.replace(/\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g, '[redacted-mac]');
  s = s.replace(/\b(secret|token|key|aes|pwd|password|pin|mac|serial|vin|uid|imei)\b(\s*[:=]\s*)("?)([^\s",]+)\3/gi,
    (m, k, sep) => k + sep + '[redacted]');
  s = s.replace(/\b[0-9A-Fa-f]{16,}\b/g, '[redacted-hex]');
  return s;
}
// Mask driver-marked sensitive spans (\x01..\x01) and run the generic redaction, but ONLY when the
// public log is on. Off = the full raw line (local debugging only, do not share).
function anonymize(s) {
  if (state.publicLog === false) return s.replace(/\x01/g, '');
  return redact(s.replace(/\x01[^\x01]*\x01/g, 'XX').replace(/\x01/g, ''));
}
function log(msg, cls) {
  const ts = new Date().toISOString().slice(11, 19);   // HH:MM:SS
  const raw = '[' + ts + '] ' + msg;
  state.logBuffer.push({ raw, cls: cls || '' });
  const pre = $('log');
  if (pre) {
    const span = document.createElement('span');
    if (cls) span.className = cls;
    span.textContent = anonymize(raw) + '\n';
    pre.appendChild(span);
    pre.scrollTop = pre.scrollHeight;   // autoscroll to bottom
  }
}
function renderLog() {
  const pre = $('log'); if (!pre) return;
  pre.textContent = '';
  state.logBuffer.forEach(e => {
    const span = document.createElement('span');
    if (e.cls) span.className = e.cls;
    span.textContent = anonymize(e.raw) + '\n';
    pre.appendChild(span);
  });
  pre.scrollTop = pre.scrollHeight;
}
function printDiagnostics() {
  const nav = (typeof navigator !== 'undefined') ? navigator : {};
  log('=== niu-unlock diagnostic ===');
  log('build: ' + BUILD);
  log('time: ' + new Date().toISOString());
  log('userAgent: ' + (nav.userAgent || '(unknown)'));
  log('platform: ' + (nav.platform || '(unknown)'));
  log('webBluetooth: ' + (nav.bluetooth ? 'yes' : 'no'));
  log('=============================');
  const aesT = N.selfTestAES();
  log('AES-128 FIPS-197 self-test: ' + (aesT.ok ? 'OK' : 'FAILED') + ' (CT=' + aesT.ct + ')', aesT.ok ? 'log-ok' : 'log-err');
  const frT = N.selfTestFrame();
  log('block-frame self-test (25.0 km/h): ' + (frT.ok ? 'OK' : 'FAILED') + ' data area=' + frT.plainHex, frT.ok ? 'log-ok' : 'log-err');
  log('model: ' + MODELS[modelKey].label + ' [write-path prefix ' + MODELS[modelKey].prefix + ', not sent by this tool]');
}
function clearLog() { state.logBuffer = []; const pre = $('log'); if (pre) pre.textContent = ''; log(t('logCleared')); printDiagnostics(); }
function copyLog() {
  const text = state.logBuffer.map(e => anonymize(e.raw)).join('\n');
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => log(t('logCopied'), 'log-ok'), () => copyLogFallback(text));
  } else copyLogFallback(text);
}
function copyLogFallback(text) {
  try {
    const ta = document.createElement('textarea');
    ta.value = text; ta.setAttribute('readonly', ''); ta.className = 'copy-offscreen';
    document.body.appendChild(ta); ta.select(); ta.setSelectionRange(0, text.length);
    const ok = document.execCommand && document.execCommand('copy');
    document.body.removeChild(ta);
    log(ok ? t('logCopied') : 'copy failed, select the log text manually', ok ? 'log-ok' : 'log-err');
  } catch (e) { log('copy failed: ' + e, 'log-err'); }
}
function saveLog() {
  const text = state.logBuffer.map(e => anonymize(e.raw)).join('\n');
  try {
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'niu-unlock-log.txt';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    log(t('logSaved'), 'log-ok');
  } catch (e) { log('save failed: ' + (e && e.message ? e.message : e), 'log-err'); }
}

// --------------------------- help modal ---------------------------
const HELP = {
  keys: ['helpKeysTitle', 'helpKeys'],
  publiclog: ['publicLogTitle', 'publicLogHelp'],
  diaglog: ['diagLogTitle', 'diagLogHelp'],
  tuning: ['tuningDisabledTitle', 'tuningDisabledHelp'],
  disclaimer: ['disclaimerTitle', 'disclaimerText'],
};
function openHelp(key) {
  const m = HELP[key]; if (!m) return;
  const dlg = $('help'); if (!dlg) return;
  const ti = $('help-title'); if (ti) ti.textContent = t(m[0]);
  const bo = $('help-body'); if (bo) bo.textContent = t(m[1]);
  if (dlg.showModal) { try { dlg.showModal(); } catch (e) { dlg.setAttribute('open', ''); } } else dlg.setAttribute('open', '');
}
function closeHelp() { const dlg = $('help'); if (!dlg) return; if (dlg.close) dlg.close(); else dlg.removeAttribute('open'); }

// --------------------------- tiles / settings / advanced (all read-only) ---------------------------
function setTile(id, val) { const el = $(id); if (el) el.textContent = (val == null ? '-' : val); }
function fmtSpeed(v) { return v == null ? null : (v / 10).toFixed(1) + ' km/h'; }
function resetLive() {
  Object.keys(live).forEach(k => { live[k] = null; });
  renderReadout();
}
function renderTiles() {
  setTile('t-speed', fmtSpeed(live.rtSpeed));
  setTile('t-gear', live.gears == null ? null : String(live.gears));
  setTile('t-range', live.range == null ? null : live.range + ' km');
  setTile('t-max', fmtSpeed(live.maxSet));
  setTile('t-maxrated', fmtSpeed(live.maxRated));
  setTile('t-mode', live.accelHex == null ? null : '0x' + live.accelHex.toUpperCase());
  setTile('t-err', live.fCode == null ? null : (live.fCode === 0 ? 'OK' : String(live.fCode)));
  setTile('t-status', live.rtStatus != null ? live.rtStatus : (live.fnStatus != null ? live.fnStatus : null));
}
function kvRow(label, value, muted) {
  const tr = document.createElement('tr');
  const th = document.createElement('td'); th.className = 'kv-k'; th.textContent = label;
  const td = document.createElement('td'); td.className = 'kv-v' + (muted ? ' kv-muted' : '');
  td.textContent = (value == null || value === '') ? t('valUnknownDash') : value;
  tr.appendChild(th); tr.appendChild(td); return tr;
}
function renderSettings() {
  const body = $('set-body'); if (!body) return;
  body.textContent = '';
  body.appendChild(kvRow(t('setMaxSet'), fmtSpeed(live.maxSet)));
  body.appendChild(kvRow(t('setMaxRated'), fmtSpeed(live.maxRated)));
  body.appendChild(kvRow(t('setAccelMode'), live.accelHex == null ? null : '0x' + live.accelHex.toUpperCase() + ' ' + t('rawSuffix')));
  body.appendChild(kvRow(t('setGear'), live.gears == null ? null : String(live.gears)));
  body.appendChild(kvRow(t('setUnitLabel'), t('valUnknown'), true));   // display unit: write-only (12/13), GATED as a read value
}
function renderAdvanced() {
  const body = $('adv-body'); if (!body) return;
  body.textContent = '';
  body.appendChild(kvRow(t('advRtStatus'), live.rtStatus != null ? live.rtStatus : null));
  body.appendChild(kvRow(t('advFnStatus'), live.fnStatus != null ? live.fnStatus : null));
  body.appendChild(kvRow(t('advErr'), live.fCode == null ? null : (live.fCode === 0 ? '0 (OK)' : String(live.fCode))));
  body.appendChild(kvRow(t('advRawData'), live.rawData));
  const gatt = usedService ? (usedService + '  notify=' + (notifyChar ? notifyChar.uuid : '-') + '  write=' + (writeChar ? writeChar.uuid : '-')) : null;
  body.appendChild(kvRow(t('advGatt'), gatt));
  body.appendChild(kvRow(t('advFw'), t('valUnknown'), true));   // no documented BLE firmware-version read, GATED
}
function renderReadout() { renderTiles(); renderSettings(); renderAdvanced(); }

function statusLabel(s) {
  const map = { disconnected: 'stDisconnected', connecting: 'stConnecting', handshake: 'stHandshake', connected: 'stConnected', 'no-service': 'stNoService', 'no-char': 'stNoChar' };
  return t(map[s] || 'stDisconnected') || s;
}
function setStatus(s) {
  const el = $('status'); if (el) { el.dataset.state = s; el.textContent = statusLabel(s); }
  const cb = $('btn-conn');
  if (cb) {
    const on = (s === 'connecting' || s === 'handshake' || s === 'connected');
    cb.textContent = on ? t('btnDisconnect') : t('btnConnect');
    cb.dataset.act = on ? 'disconnect' : 'connect';
  }
}
function updateEncState() {
  const el = $('enc-state'); if (!el) return;
  if (!connected) { el.textContent = t('encNone'); return; }
  el.textContent = (hsState === 'ready') ? t('encSession') : t('encInit');
}
// The heartbeat button is the only read-nudge; enabled only once the session is ready.
function setControlsEnabled(on) { const b = $('btn-heartbeat'); if (b) b.disabled = !on; document.querySelectorAll('.conn-only').forEach(function (el) { el.hidden = !on; }); }

function modelPrefix() { return (MODELS[modelKey] || MODELS.auto).prefix; }

// --------------------------- model selection ---------------------------
function buildModelDropdown() {
  const sel = $('model-in'); if (!sel) return;
  sel.textContent = '';
  MODEL_ORDER.forEach(key => {
    const opt = document.createElement('option');
    opt.value = key; opt.textContent = MODELS[key].label;
    sel.appendChild(opt);
  });
  sel.value = modelKey;
}
function setModel(key, quiet) {
  if (!MODELS[key]) key = DEFAULT_MODEL;
  modelKey = key;
  try { localStorage.setItem(LS_MODEL, key); } catch (e) {}
  const sel = $('model-in'); if (sel) sel.value = key;
  if (!quiet) log('model set: ' + MODELS[key].label + '  [write-path speed prefix foc_k_cmd=' + MODELS[key].prefix + ', not sent]', 'log-ok');
}

// --------------------------- connect / disconnect ---------------------------
function randBytes(n) {
  const a = new Uint8Array(n);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) crypto.getRandomValues(a);
  else for (let i = 0; i < n; i++) a[i] = Math.floor(Math.random() * 256);
  return a;
}
function readKeysFromInputs() {
  const s = ($('secret-in') || {}).value || '';
  const a = ($('aes-in') || {}).value || '';
  const m = ($('mac-in') || {}).value || '';
  try { localStorage.setItem(LS_SECRET, s); localStorage.setItem(LS_AES, a); localStorage.setItem(LS_MAC, m); } catch (e) {}
  let ok = true;
  try { secretBytes = N.keyBytesFromSecret(s); } catch (e) { secretBytes = null; log('secret invalid: ' + e.message + ' (need 16 ASCII or 32 hex chars).', 'log-err'); ok = false; }
  try { aesBytes = a ? N.keyBytesFromSecret(a) : null; } catch (e) { aesBytes = null; log('aesSecret invalid: ' + e.message, 'log-err'); }
  macArr = N.macBytes(m);
  if (N.bytesToHex(macArr) === '000000000000') log('note: MAC empty or malformed -> firstKey uses 000000000000 for the MAC field, the handshake will likely fail. Enter the real MAC.', 'log-err');
  return ok;
}

function charProps(c) { const p = c.properties || {}; return ['read', 'write', 'writeWithoutResponse', 'notify', 'indicate'].filter(k => p[k]).join(',') || '-'; }

async function pickAndConnect() {
  if (!navigator.bluetooth) { log('Web Bluetooth not available. Use Bluefy (iOS) or Chrome/Edge (Android/desktop).', 'log-err'); return; }
  if (!readKeysFromInputs()) { log('cannot connect: fix the device keys first.', 'log-err'); return; }
  try {
    // NIU advertises no guaranteed name prefix (from ble-architektur.md/modelle-matrix.md); the app
    // otherwise identifies the device via the cloud by its MAC. A standalone tool therefore shows all
    // devices and lets the user pick their KQi by the advertised name.
    log('scanning: all Bluetooth devices (NIU advertises no fixed name prefix). Pick your KQi ...');
    device = await navigator.bluetooth.requestDevice({ acceptAllDevices: true, optionalServices: OPTIONAL_SERVICES });
    log('selected: ' + (device.name || '(no name)') + ' ' + wrap('[' + device.id + ']'));
    await connectGatt(device);
  } catch (e) { log('scan/connect cancelled: ' + e, 'log-err'); }
}

async function resolveService(srv) {
  for (const uuid of SERVICE_CANDIDATES) {
    const svc = await srv.getPrimaryService(uuid).catch(() => null);
    if (svc) return svc;
  }
  return null;
}
// Assign notify/write by property, not by fixed UUID (robust across daea50/51/52).
async function assignChars(svc) {
  let chs = [];
  try { chs = await svc.getCharacteristics(); } catch (e) { return false; }
  notifyChar = null; writeChar = null;
  for (const c of chs) {
    const p = c.properties || {};
    if (!notifyChar && (p.notify || p.indicate)) notifyChar = c;
    if (!writeChar && (p.write || p.writeWithoutResponse)) writeChar = c;
  }
  if (state.diag) for (const c of chs) log('char ' + c.uuid + '  [' + charProps(c) + ']');
  return !!(notifyChar && writeChar);
}

async function connectGatt(dev) {
  if (connecting) { log('connect already in progress'); return; }
  connecting = true;
  try {
    device = dev;
    device.removeEventListener('gattserverdisconnected', onDisconnected);
    device.addEventListener('gattserverdisconnected', onDisconnected);
    setStatus('connecting');
    connected = false; hsState = 'idle'; sessionKey = null;
    server = await device.gatt.connect();
    const svc = await resolveService(server);
    if (!svc) { try { device.gatt.disconnect(); } catch (e) {} setStatus('no-service'); log('no NIU service found (8ec94e30-...daea50/51/52). Wrong device? Use the diagnostics button.', 'log-err'); return; }
    usedService = svc.uuid;
    if (!(await assignChars(svc))) { try { device.gatt.disconnect(); } catch (e) {} setStatus('no-char'); log('notify/write characteristic not found on ' + svc.uuid, 'log-err'); return; }
    await notifyChar.startNotifications();
    notifyChar.removeEventListener('characteristicvaluechanged', onCharacteristicValue);
    notifyChar.addEventListener('characteristicvaluechanged', onCharacteristicValue);
    connected = true;
    resetLive();
    log('connected: ' + (device.name || '(no name)') + ' ' + wrap('[' + device.id + ']'), 'log-ok');
    log('service ' + usedService + '  notify=' + notifyChar.uuid + '  write=' + writeChar.uuid, 'log-ok');
    const info = $('devinfo'); if (info) info.textContent = t('devPrefix') + ' ' + (device.name || '(no name)') + '  -  ' + usedService;
    updateEncState();
    startHandshake();
  } catch (e) { setStatus('disconnected'); log('connect failed: ' + e, 'log-err'); }
  finally { connecting = false; }
}

function onDisconnected(ev) {
  if (ev && ev.target && ev.target !== device) return;
  connected = false; hsState = 'idle'; sessionKey = null;
  setStatus('disconnected');
  setControlsEnabled(false); resetLive();
  const info = $('devinfo'); if (info) info.textContent = '';
  updateEncState();
  log('disconnected.', 'log-err');
}
function disconnectBle() {
  const d = device;
  if (d) { try { d.removeEventListener('gattserverdisconnected', onDisconnected); } catch (e) {} }
  try { if (d && d.gatt && d.gatt.connected) d.gatt.disconnect(); } catch (e) {}
  device = null; server = null; writeChar = null; notifyChar = null; usedService = null;
  connected = false; hsState = 'idle'; sessionKey = null;
  setStatus('disconnected'); setControlsEnabled(false); resetLive();
  const info = $('devinfo'); if (info) info.textContent = '';
  updateEncState();
}

// --------------------------- handshake ---------------------------
function startHandshake() {
  if (!secretBytes) { log('no valid secret - cannot run the handshake. The scooter will not send telemetry.', 'log-err'); setStatus('connected'); return; }
  setStatus('handshake');
  const nowSec = Math.floor(Date.now() / 1000);
  const rand4 = randBytes(4);
  const fk = N.buildFirstKey(secretBytes, macArr, nowSec, rand4);
  random1Hex = fk.random1Hex;
  hsState = 'await1';
  const frame = N.buildVerifyPwd1(fk.firstKeyHex);
  log('handshake: firstKey block=' + wrap(fk.blockHex) + ' (rand4=' + fk.random1Hex + ', t+7d, mac=' + wrap(N.bytesToHex(macArr)) + ', crc16)', 'log-ok');
  transmitRaw(frame, 'verifyPwd1 (013401 + firstKey + checksum, unencrypted)');
}
function handleHandshakeNotify(bytes) {
  const hex = N.bytesToHex(bytes);
  if (hsState === 'await1') {
    // Answer to verifyPwd1 -> session key. First 8 hex = echo of random1.
    const echo = hex.substr(0, 8);
    if (echo === random1Hex) log('handshake: random1 echo ok (' + echo + ').', 'log-ok');
    else log('handshake: random1 echo MISMATCH (got ' + echo + ', expected ' + random1Hex + '). Continuing, but secret/MAC may be wrong.', 'log-err');
    if (bytes.length < 16) { log('handshake: verifyPwd1 answer shorter than 16 bytes (' + bytes.length + '); cannot form a session key. Aborting handshake.', 'log-err'); setStatus('connected'); hsState = 'idle'; return; }
    sessionKey = bytes.subarray(0, 16);   // the answer becomes the session key 1:1 (first 16 bytes)
    log('handshake: session key set from verifyPwd1 answer = ' + wrap(N.bytesToHex(sessionKey)) + ' (first 16 bytes of the response, per app).', 'log-ok');
    random2Hex = N.bytesToHex(randBytes(4));
    const v2 = N.buildVerifyPwd2(hex, random2Hex, sessionKey);
    hsState = 'await2';
    log('handshake: verifyPwd2 block=' + wrap(v2.blockHex) + ' (resp1[4..7], random2=' + random2Hex + ', crc16)', 'log-ok');
    transmitRaw(v2.frame, 'verifyPwd2 (011400 + AES16(sessionKey) + checksum)');
    return;
  }
  if (hsState === 'await2') {
    const echo = hex.substr(0, 8);
    if (echo === random2Hex) log('handshake: random2 echo ok (' + echo + ') -> session established.', 'log-ok');
    else log('handshake: random2 echo MISMATCH (got ' + echo + ', expected ' + random2Hex + '). Treating session as up anyway; telemetry may not decrypt.', 'log-err');
    hsState = 'ready';
    setStatus('connected');
    setControlsEnabled(true);
    updateEncState();
    transmit([[FOC_K_CMD, CMD_REFRESH]], 'refresh/heartbeat foc_k_cmd=16 (telemetry nudge)');
    return;
  }
}

// --------------------------- notify receive ---------------------------
function onCharacteristicValue(ev) {
  try {
    const b = new Uint8Array(ev.target.value.buffer);
    log('RX  ' + N.hexSpaced(b), 'log-rx');
    if (hsState === 'await1' || hsState === 'await2') { handleHandshakeNotify(b); return; }
    if (hsState === 'ready') decodeNotify(b);
  } catch (e) { log('RX parse error: ' + e, 'log-err'); }
}

// Telemetry best-effort: decrypt the block frame (0122/0102), then look for code-prefixed fields.
// 5aa5 var-len frames are only logged raw (the deskramble is not confirmed).
function decodeNotify(b) {
  if (b.length < 4) { log('  frame too short to decode.'); return; }
  if (b[0] === 0x01 && (b[1] === 0x22 || b[1] === 0x02)) {
    if (!sessionKey) { log('  block frame but no session key.', 'log-err'); return; }
    const cipherLen = Math.floor((b.length - 4) / 16) * 16;   // without header(3) and checksum(1)
    if (cipherLen < 16) { log('  block frame too short for one AES block.'); return; }
    const cipher = b.subarray(3, 3 + cipherLen);
    let plain;
    try { plain = N.aesEcbDecrypt(cipher, sessionKey); } catch (e) { log('  decrypt error: ' + e, 'log-err'); return; }
    const plainHex = N.bytesToHex(plain);
    live.rawData = plainHex;
    log('  decrypted data area: ' + plainHex);
    scanFields(plainHex);
    renderReadout();
    return;
  }
  if (b[0] === 0x5a && b[1] === 0xa5) { log('  5aa5 var-len frame (response validator path). Raw hex above; field decode not implemented (deskramble -0x33 unverified).'); return; }
  log('  frame does not start with 0122/0102 or 5aa5; raw hex above.');
}

// Known live field codes (telemetrie.md). Scalings are derived from the app and should be confirmed
// on the vehicle; where uncertain, the raw value is logged too. Nothing here is invented; every code
// is documented in PROTOCOL.md section 6.
function readAfter(plainHex, code, byteLen) {
  const idx = plainHex.indexOf(code);
  if (idx < 0 || idx % 2 !== 0) return null;
  const v = plainHex.substr(idx + 6, byteLen * 2);
  if (v.length < byteLen * 2) return null;
  return v;
}
function scanFields(plainHex) {
  const parts = [];
  let v;
  if ((v = readAfter(plainHex, C_RT_SPEED, 2)) != null) { live.rtSpeed = parseInt(v, 16); parts.push('rt_speed=' + live.rtSpeed + ' (/10 -> ' + (live.rtSpeed / 10).toFixed(1) + 'km/h, scaling assumed)'); }
  if ((v = readAfter(plainHex, C_GEARS, 1)) != null) { live.gears = parseInt(v, 16); parts.push('gears=' + live.gears); }
  if ((v = readAfter(plainHex, C_MAX_RATED, 2)) != null) { live.maxRated = parseInt(v, 16); parts.push('max_speed(rated)=' + live.maxRated + ' (/10)'); }
  if ((v = readAfter(plainHex, C_MAX_SET, 2)) != null) { live.maxSet = parseInt(v, 16); parts.push('def_max_speed(set)=' + live.maxSet + ' (/10)'); }
  // 210029 accel/throttle mode: length is documented as 1 byte / U8 (telemetrie.md), only the value
  // encoding is unknown. Read exactly 1 byte and show it raw; never map to a named mode.
  if ((v = readAfter(plainHex, C_ACCEL, 1)) != null) { live.accelHex = v; parts.push('accel_mode(raw)=0x' + v + ' (encoding unconfirmed)'); }
  if ((v = readAfter(plainHex, C_RANGE, 2)) != null) { live.range = parseInt(v, 16); parts.push('est_mileage=' + live.range + ' (raw, unit unconfirmed)'); }
  if ((v = readAfter(plainHex, C_FCODE, 1)) != null) { live.fCode = parseInt(v, 16); parts.push('f_code=' + live.fCode); }
  if ((v = readAfter(plainHex, C_RT_STATUS, 4)) != null) { live.rtStatus = '0x' + v.toUpperCase(); parts.push('rt_status=0x' + v + ' (bit meanings unknown)'); }
  if ((v = readAfter(plainHex, C_FN_STATUS, 4)) != null) { live.fnStatus = '0x' + v.toUpperCase(); parts.push('fn_status=0x' + v + ' (bit meanings unknown)'); }
  if (parts.length) log('  fields: ' + parts.join('  '), 'log-ok');
  else log('  no known field code found in this frame.');
}

// --------------------------- sending (read path only) ---------------------------
// The tool writes exactly two kinds of frame: the handshake frames (verifyPwd1/2) and the refresh
// heartbeat (foc_k_cmd=16). NO tuning/state-changing command is ever built or sent from the UI.
const WRITE_SETTLE_MS = 250;
const sleep = ms => new Promise(r => setTimeout(r, ms));
let writeQueue = Promise.resolve();
function writeFrame(bytes) {
  const doWrite = () => {
    const wc = writeChar;
    if (!wc) throw new Error('not connected');
    if (wc.writeValueWithResponse) return wc.writeValueWithResponse(bytes);   // NIU: WRITE_TYPE_DEFAULT (with response)
    if (wc.writeValueWithoutResponse) return wc.writeValueWithoutResponse(bytes);
    return wc.writeValue(bytes);
  };
  const result = writeQueue.then(doWrite, doWrite);
  writeQueue = result.then(() => sleep(WRITE_SETTLE_MS), () => sleep(WRITE_SETTLE_MS));
  return result;
}
// Write an already-built raw frame - for verifyPwd1/2, which carry their own framing.
async function transmitRaw(frameBytes, label) {
  if (!connected || !writeChar) { log('not connected', 'log-err'); return; }
  try {
    log('TX  ' + N.hexSpaced(frameBytes) + '   (' + label + ')', 'log-tx');
    await writeFrame(frameBytes);
    log('sent.', 'log-ok');
  } catch (e) { log('send failed: ' + e, 'log-err'); }
}
// Build a block frame (AES(sessionKey)) and write it. Used only for the heartbeat and handshake path.
async function transmit(fields, label) {
  if (!connected || !writeChar) { log('not connected', 'log-err'); return; }
  if (hsState !== 'ready' && label.indexOf('heartbeat') < 0) { log('no session yet - "' + label + '" not sent.', 'log-err'); return; }
  if (!sessionKey) { log('no session key - cannot encrypt "' + label + '".', 'log-err'); return; }
  try {
    const built = N.buildBlockFrame(fields, sessionKey);
    log('TX  ' + N.hexSpaced(built.frame) + '   (' + label + ', block-write, plain ' + built.plainHex + ')', 'log-tx');
    await writeFrame(built.frame);
    log('sent.', 'log-ok');
  } catch (e) { log('send failed: ' + e, 'log-err'); }
}
function requestLiveValues() {
  if (hsState !== 'ready') { log('no session yet - connect and finish the handshake first.', 'log-err'); return; }
  transmit([[FOC_K_CMD, CMD_REFRESH]], 'refresh/heartbeat foc_k_cmd=16 (telemetry nudge)');
}

// --------------------------- diagnostics ---------------------------
async function scanAllDevicesDiagnostic() {
  if (!navigator.bluetooth) { log('Web Bluetooth not available.', 'log-err'); return; }
  let dev = null;
  try {
    log('DIAG: showing ALL Bluetooth devices. Pick your scooter.', 'log-ok');
    dev = await navigator.bluetooth.requestDevice({ acceptAllDevices: true, optionalServices: OPTIONAL_SERVICES });
  } catch (e) { log('DIAG cancelled: ' + e, 'log-err'); return; }
  log('DIAG selected: name="' + (dev.name || '(no name)') + '"  id=' + wrap(dev.id));
  try {
    log('DIAG: connecting to read the GATT services ...');
    const srv = await dev.gatt.connect();
    let svcs = [];
    try { svcs = await srv.getPrimaryServices(); } catch (e) { log('DIAG getPrimaryServices error: ' + e, 'log-err'); }
    if (!svcs || !svcs.length) log('DIAG: no services listed. On Android use nRF Connect for the full picture.', 'log-err');
    for (const s of svcs) {
      log('DIAG service ' + s.uuid, 'log-ok');
      try { const chs = await s.getCharacteristics(); for (const c of chs) log('DIAG   char ' + c.uuid + '  [' + charProps(c) + ']'); }
      catch (e) { log('DIAG   (characteristics unreadable: ' + e + ')'); }
    }
    try { dev.gatt.disconnect(); } catch (e) {}
    log('DIAG done. Copy the log and send it.', 'log-ok');
  } catch (e) { log('DIAG connect failed: ' + e, 'log-err'); }
}

// --------------------------- language ---------------------------
let lang = 'de';
function table() { return (window.I18N && window.I18N[lang]) || {}; }
function t(key) { const v = table()[key]; return (typeof v === 'string') ? v : ''; }
function applyLang() {
  document.documentElement.lang = lang;
  document.querySelectorAll('[data-t]').forEach(n => {
    const v = t(n.getAttribute('data-t'));
    if (/[<&]/.test(v)) n.innerHTML = v; else n.textContent = v;   // scan-ok: our own translation table
  });
  { const el = $('langs'); if (el) el.setAttribute('aria-label', t('langGroup')); }
  { const dark = document.documentElement.getAttribute('data-theme') !== 'light';
    const el = $('btn-theme'); if (el) { el.setAttribute('aria-label', t(dark ? 'themeToLight' : 'themeToDark')); el.title = el.getAttribute('aria-label'); } }
  { const el = $('build-ver'); if (el) el.textContent = t('buildLabel') + ' ' + BUILD; }
  document.querySelectorAll('#langs button').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.lang === lang)));
  updateDocLinks();
  renderReadout();
  { const el = $('status'); setStatus(el ? el.dataset.state : 'disconnected'); }
  updateEncState();
}
function initLangSwitch() {
  document.querySelectorAll('#langs button').forEach(b => b.addEventListener('click', () => { lang = b.dataset.lang; applyLang(); }));
}

// --------------------------- theme ---------------------------
function applyTheme(dark) {
  document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
  const b = $('btn-theme');
  if (b) { b.innerHTML = dark ? '&#9728;' : '&#9790;'; b.setAttribute('aria-label', t(dark ? 'themeToLight' : 'themeToDark')); b.title = b.getAttribute('aria-label'); }   // scan-ok: constant HTML-entity glyphs (sun/moon), no user input
  try { localStorage.setItem(LS_THEME, dark ? 'dark' : 'light'); } catch (e) {}
}
function initTheme() {
  let saved = null; try { saved = localStorage.getItem(LS_THEME); } catch (e) {}
  applyTheme(saved !== 'light');
  const b = $('btn-theme'); if (b) b.addEventListener('click', () => applyTheme(document.documentElement.getAttribute('data-theme') === 'light'));
}

// --------------------------- document viewer ---------------------------
// Paired docs resolve to the file for the current language; single docs are language-neutral.
const DOC_LOCALIZED = {
  GUIDE:      { de: 'GUIDE.de.md',  en: 'GUIDE.en.md',   titleKey: 'footGuide' },
  PRIVACY:    { de: 'PRIVACY.de.md', en: 'PRIVACY.md',   titleKey: 'footPrivacy' },
  LICENSE:    { de: 'LICENSE.de.md', en: 'LICENSE.md',   titleKey: 'footLicense' },
  TRADEMARKS: { de: 'TRADEMARKS.de.md', en: 'TRADEMARKS.md', titleKey: 'footTrademarks' },
};
const DOC_SINGLE = {
  README:   { file: 'README.md', titleKey: 'footReadme' },
  PROTOCOL: { file: 'PROTOCOL.md', titleKey: 'footProtocol' },
  MATRIX:   { file: 'MODELL-FEATURE-MATRIX.md', titleKey: 'footMatrix' },
};
// Filename -> title key, so internal markdown links like [x](GUIDE.de.md) still open in the viewer.
const DOC_TITLES = {
  'GUIDE.de.md': 'footGuide', 'GUIDE.en.md': 'footGuide',
  'README.md': 'footReadme', 'PROTOCOL.md': 'footProtocol',
  'MODELL-FEATURE-MATRIX.md': 'footMatrix',
  'PRIVACY.de.md': 'footPrivacy', 'PRIVACY.md': 'footPrivacy',
  'LICENSE.de.md': 'footLicense', 'LICENSE.md': 'footLicense',
  'TRADEMARKS.de.md': 'footTrademarks', 'TRADEMARKS.md': 'footTrademarks',
};
function docFileForKey(key) {
  if (DOC_LOCALIZED[key]) return DOC_LOCALIZED[key][lang] || DOC_LOCALIZED[key].en;
  if (DOC_SINGLE[key]) return DOC_SINGLE[key].file;
  return null;
}
// Keep footer/inline [data-doc] anchors pointing at the current-language file.
function updateDocLinks() {
  document.querySelectorAll('[data-doc]').forEach(a => {
    const key = a.getAttribute('data-doc');
    const file = docFileForKey(key);
    if (file) a.setAttribute('href', file);
  });
}
const escHtml = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const slug = s => s.toLowerCase().trim().replace(/[^\w\s-]/g, '').replace(/ /g, '-');
function mdToHtml(src) {
  const inline = s => escHtml(s)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (all, text, href) => {
      if (DOC_TITLES[href]) return `<a href="${href}" data-docfile="${href}">${text}</a>`;
      if (href.startsWith('#')) return `<a href="${href}" data-anchor="${href.slice(1)}">${text}</a>`;
      return `<a href="${href}" target="_blank" rel="noopener">${text}</a>`;
    });
  const lines = String(src).replace(/\r\n?/g, '\n').split('\n');
  const out = []; let listKind = null, li = null, para = [], inFence = false;
  const sink = () => (li ? li.parts : out);
  const flushPara = () => { if (para.length) { sink().push('<p>' + inline(para.join(' ')) + '</p>'); para = []; } };
  const closeNested = () => { if (li && li.nested) { li.parts.push('</ul>'); li.nested = false; } };
  const closeLi = () => { if (!li) return; flushPara(); closeNested(); out.push('<li>' + li.parts.join('\n') + '</li>'); li = null; };
  const closeList = () => { closeLi(); if (listKind) { out.push('</' + listKind + '>'); listKind = null; } };
  const block = () => { flushPara(); closeList(); };
  const openList = kind => { flushPara(); if (listKind !== kind) { closeList(); out.push('<' + kind + '>'); listKind = kind; } else closeLi(); };
  const cells = l => l.replace(/^\||\|$/g, '').split('|').map(c => c.trim());
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]; const body = l.trim(); const indented = /^ {2,}\S/.test(l);
    if (inFence) { if (body.startsWith('```')) { sink().push('</code></pre>'); inFence = false; } else sink().push(escHtml(l)); continue; }
    if (body.startsWith('```')) { if (li) { flushPara(); closeNested(); } else block(); sink().push('<pre><code>'); inFence = true; continue; }
    if (body === '') { if (li && /^ {2,}\S/.test(lines[i + 1] || '')) flushPara(); else block(); continue; }
    if (/^(-{3,}|\*{3,}|_{3,})\s*$/.test(body)) { block(); out.push('<hr>'); continue; }
    if (body.startsWith('|') && /^\|[\s:|-]+\|?\s*$/.test((lines[i + 1] || '').trim())) {
      if (li) { flushPara(); closeNested(); } else block();
      sink().push('<div class="doc-table"><table><thead><tr>' + cells(body).map(c => '<th>' + inline(c) + '</th>').join('') + '</tr></thead><tbody>');
      i++;
      while (i + 1 < lines.length && lines[i + 1].trim().startsWith('|')) sink().push('<tr>' + cells(lines[++i].trim()).map(c => '<td>' + inline(c) + '</td>').join('') + '</tr>');
      sink().push('</tbody></table></div>'); continue;
    }
    let m;
    if ((m = body.match(/^(#{1,4})\s+(.*)$/))) { block(); const n = m[1].length; out.push(`<h${n} id="${slug(m[2])}">${inline(m[2])}</h${n}>`); continue; }
    if ((m = body.match(/^>\s?(.*)$/))) { if (li) { flushPara(); closeNested(); } else block(); sink().push('<blockquote>' + inline(m[1]) + '</blockquote>'); continue; }
    if (indented && li && (m = body.match(/^[-*]\s+(.*)$/))) { flushPara(); if (!li.nested) { li.parts.push('<ul class="nested">'); li.nested = true; } li.parts.push('<li>' + inline(m[1]) + '</li>'); continue; }
    if ((m = body.match(/^[-*]\s+(.*)$/)) && !indented) { openList('ul'); li = { parts: [inline(m[1])], nested: false }; continue; }
    if ((m = body.match(/^\d+\.\s+(.*)$/)) && !indented) { openList('ol'); li = { parts: [inline(m[1])], nested: false }; continue; }
    if (li && !indented) closeList();
    if (li) closeNested();
    para.push(body);
  }
  if (inFence) sink().push('</code></pre>');
  block();
  return out.join('\n').replace(/<pre><code>\n/g, '<pre><code>');
}
const docCache = {};
function openDocFile(file, anchor, titleKey) {
  const dlg = $('doc'), body = $('doc-body');
  if (!dlg || !body) return;
  $('doc-title').textContent = t(titleKey || DOC_TITLES[file] || '') || file;
  if (typeof dlg.showModal === 'function') dlg.showModal();
  const show = html => {
    body.innerHTML = html;   // scan-ok: our own markdown, escaped first by mdToHtml
    const h1 = body.querySelector('h1');
    if (h1) { $('doc-title').textContent = h1.textContent.trim(); h1.remove(); }
    body.scrollTop = 0;
    if (!anchor) return;
    const target = body.querySelector('#' + (window.CSS && CSS.escape ? CSS.escape(anchor) : anchor));
    if (target) body.scrollTop = target.offsetTop - body.offsetTop;
  };
  if (docCache[file]) { show(docCache[file]); return; }
  body.innerHTML = '<p>' + escHtml(t('docLoading')) + '</p>';   // scan-ok: escaped
  fetch(file + '?v=' + BUILD)
    .then(r => { if (!r.ok) throw new Error(r.status + ' ' + r.statusText); return r.text(); })
    .then(txt => { docCache[file] = mdToHtml(txt); show(docCache[file]); })
    .catch(e => { body.innerHTML = '<p>' + escHtml(t('docFail')) + '</p><pre class="err">' + escHtml(file + ': ' + (e && e.message ? e.message : e)) + '</pre>'; });   // scan-ok: escaped via escHtml
}
function wireDocViewer() {
  document.addEventListener('click', e => {
    if (!e.target.closest) return;
    const jump = e.target.closest('[data-anchor]');
    if (jump) { e.preventDefault(); const body = $('doc-body'); const target = body && body.querySelector('#' + CSS.escape(jump.getAttribute('data-anchor'))); if (target) body.scrollTop = target.offsetTop - body.offsetTop; return; }
    const disc = e.target.closest('[data-open-disclaimer]');
    if (disc) { e.preventDefault(); openHelp('disclaimer'); return; }
    const keyed = e.target.closest('[data-doc]');
    if (keyed) {
      e.preventDefault();
      const key = keyed.getAttribute('data-doc');
      const file = docFileForKey(key);
      const titleKey = (DOC_LOCALIZED[key] && DOC_LOCALIZED[key].titleKey) || (DOC_SINGLE[key] && DOC_SINGLE[key].titleKey) || '';
      if (file) openDocFile(file, '', titleKey);
      return;
    }
    const a = e.target.closest('[data-docfile]');
    if (!a) return;
    e.preventDefault();
    openDocFile(a.getAttribute('data-docfile'), a.getAttribute('data-doc-anchor') || '', a.getAttribute('data-t') || '');
  });
  ['doc-x', 'doc-close'].forEach(id => { const b = $(id); if (b) b.addEventListener('click', () => { const d = $('doc'); if (d) d.close(); }); });
}

// --------------------------- init ---------------------------
window.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.help-btn').forEach(btn => btn.addEventListener('click', () => openHelp(btn.getAttribute('data-help'))));
  ['help-x', 'help-close'].forEach(id => { const b = $(id); if (b) b.addEventListener('click', closeHelp); });
  { const b = $('link-disclaimer'); if (b) b.addEventListener('click', e => { e.preventDefault(); openHelp('disclaimer'); }); }
  initLangSwitch();
  initTheme();
  wireDocViewer();
  buildModelDropdown();
  if (!navigator.bluetooth) { const n = document.getElementById('bt-note'); if (n) n.hidden = false; } // Web Bluetooth notice shows only where it is unavailable

  let savedModel = null; try { savedModel = localStorage.getItem(LS_MODEL); } catch (e) {}
  setModel(MODELS[savedModel] ? savedModel : DEFAULT_MODEL, true);
  try { const s = localStorage.getItem(LS_SECRET); if (s && $('secret-in')) $('secret-in').value = s; } catch (e) {}
  try { const a = localStorage.getItem(LS_AES); if (a && $('aes-in')) $('aes-in').value = a; } catch (e) {}
  try { const m = localStorage.getItem(LS_MAC); if (m && $('mac-in')) $('mac-in').value = m; } catch (e) {}

  // Public-log toggle: default on (anonymized). Diag toggle: default off each session.
  const pubCb = $('public-log');
  if (pubCb) {
    let saved = '1'; try { const v = localStorage.getItem(LS_PUBLOG); if (v != null) saved = v; } catch (e) {}
    state.publicLog = saved !== '0';
    pubCb.checked = state.publicLog;
    pubCb.addEventListener('change', () => { state.publicLog = pubCb.checked; try { localStorage.setItem(LS_PUBLOG, pubCb.checked ? '1' : '0'); } catch (e) {} renderLog(); });
  }
  const diagCb = $('diag-log');
  if (diagCb) {
    state.diag = false; diagCb.checked = false;
    diagCb.addEventListener('change', () => { state.diag = diagCb.checked; log(state.diag ? t('diagOn') : t('diagOff'), 'log-rx'); });
  }

  applyLang();
  printDiagnostics();

  $('btn-conn').addEventListener('click', () => { if ($('btn-conn').dataset.act === 'disconnect') disconnectBle(); else pickAndConnect(); });
  { const sel = $('model-in'); if (sel) sel.addEventListener('change', () => setModel(sel.value)); }
  { const b = $('btn-heartbeat'); if (b) b.addEventListener('click', requestLiveValues); }
  { const b = $('btn-copy-log'); if (b) b.addEventListener('click', copyLog); }
  { const b = $('btn-clear-log'); if (b) b.addEventListener('click', clearLog); }
  { const b = $('btn-save-log'); if (b) b.addEventListener('click', saveLog); }
  { const b = $('btn-diag'); if (b) b.addEventListener('click', scanAllDevicesDiagnostic); }

  setControlsEnabled(false);
  updateEncState();
  resetLive();
  if (!navigator.bluetooth) log('Web Bluetooth not available. On iOS use the Bluefy browser.', 'log-err');
});
