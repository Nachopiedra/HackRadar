import customtkinter as ctk
import asyncio
import threading
from bleak import BleakScanner
from datetime import datetime
import os
import collections
import time
import subprocess
import urllib.request
import urllib.parse
import json
import tempfile
import wave
import struct
import math

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# ─────────────────────────────────────────────────────────────────
# CONSTANTES GLOBALES
# ─────────────────────────────────────────────────────────────────
RSSI_HISTORY_SIZE        = 8
DISPLAY_REFRESH_INTERVAL = 0.5
ACTIVE_SIGNAL_THRESHOLD  = -80.0
SUSPECT_THRESHOLD        = -65.0
OUI_API_URL              = "https://api.macvendors.com/"

# Margen en dBm sobre la línea base para considerar anomalía SDR
ANOMALY_MARGIN_DBM       = 10.0

BAND_MAP = [
    (300e6,   400e6,  "📻 300–400 MHz", "Sub-GHz (domótica/mandos)"),
    (400e6,   500e6,  "📻 433 MHz IoT", "433 MHz (mandos/sensores)"),
    (800e6,   900e6,  "🎙️ 800–900 MHz", "GSM / Micrófono espía"),
    (900e6,  1000e6,  "📡 900 MHz ISM", "Zigbee 900 / Z-Wave"),
    (1000e6, 1200e6,  "📡 1 GHz",       "L-Band / GPS"),
    (1200e6, 1400e6,  "📡 1.2 GHz",     "Cámara inalámbrica AV"),
    (2400e6, 2484e6,  "📶 2.4 GHz",     "WiFi 2.4 / BLE / Zigbee"),
    (5150e6, 5850e6,  "📶 5 GHz",       "WiFi 5 (802.11ac/n)"),
    (5925e6, 7125e6,  "📶 6 GHz",       "WiFi 6E (802.11ax)"),
]

MAC_VENDORS = {
    "e0:41:36": "MitraStar (Movistar Router)",
    "a0:f3:c1": "MitraStar Technology",
    "70:9f:2d": "Askey Computer (Movistar HGU)",
    "00:03:c7": "Askey Computer Corp.",
    "00:90:4c": "ZTE Corporation",
    "fc:3f:db": "Huawei Technologies",
    "b0:b8:67": "Sagemcom",
    "50:8b:b9": "Apple, Inc.",
    "00:25:00": "Apple, Inc.",
    "18:de:50": "Google LLC (Nest/Pixel/Cast)",
    "00:1a:11": "Google LLC",
    "bc:d1:d3": "Samsung Electronics",
    "00:26:37": "Samsung Electronics",
    "64:a2:b9": "Xiaomi Communications",
    "1c:5a:3b": "Xiaomi Communications",
    "00:e0:4c": "Realtek (Tarjetas de Red/Audio)",
    "00:50:b6": "Intel Corporation",
    "11:95:0d": "Tuya Smart / Espressif",
    "24:0a:c4": "Espressif Systems (IoT)",
    "30:ae:a4": "Espressif Systems (IoT)",
    "0c:8b:95": "Hyundai Motor Co.",
    "d4:f5:47": "Tile Inc. (Rastreador)",
    "00:1f:3a": "AzureWave (Cámara IP)",
    "00:e0:36": "D-Link (Cámara IoT)",
}
BLACKLIST_VENDORS = ["espressif", "tuya", "desconocido", "tile", "azurewave", "d-link", "no registrado"]


# ─────────────────────────────────────────────────────────────────
# UTILIDADES
# ─────────────────────────────────────────────────────────────────
def is_random_mac(mac: str) -> bool:
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def classify_band(freq_hz: float):
    for f_low, f_high, label, desc in BAND_MAP:
        if f_low <= freq_hz < f_high:
            return label, desc
    return "❓ Desconocida", f"{freq_hz/1e6:.1f} MHz"


def assess_sdr_threat(freq_hz: float, power_dbm: float):
    label, _ = classify_band(freq_hz)
    if power_dbm < ACTIVE_SIGNAL_THRESHOLD:
        return False, "OK"
    if "Micrófono" in label and power_dbm >= SUSPECT_THRESHOLD:
        return True, "⚠️ ALERT: [MICRÓFONO ESPÍA]"
    if "Cámara" in label and power_dbm >= SUSPECT_THRESHOLD:
        return True, "⚠️ ALERT: [CÁMARA OCULTA AV]"
    if "433" in label and power_dbm >= SUSPECT_THRESHOLD:
        return True, "⚠️ ALERT: [MANDO/SENSOR IoT]"
    if "2.4" in label and power_dbm >= -60:
        return True, "⚠️ ALERT: [EMISOR 2.4 GHz CERCANO]"
    if "5 GHz" in label and power_dbm >= -60:
        return True, "⚠️ ALERT: [EMISOR 5 GHz CERCANO]"
    return False, "Señal detectada"


# ─────────────────────────────────────────────────────────────────
# SONIDO
# ─────────────────────────────────────────────────────────────────
def _generate_wav(freq_hz: float, duration_s: float, volume: float = 0.5) -> str:
    sample_rate = 44100
    n_samples   = int(sample_rate * duration_s)
    wav_path    = tempfile.mktemp(suffix=".wav")
    with wave.open(wav_path, "w") as wf:
        wf.setnchannels(1); wf.setsampwidth(2); wf.setframerate(sample_rate)
        frames = []
        for i in range(n_samples):
            t = i / sample_rate
            env = 1.0
            if t < 0.01: env = t / 0.01
            elif t > duration_s - 0.05: env = (duration_s - t) / 0.05
            sample = int(32767 * volume * env * math.sin(2 * math.pi * freq_hz * t))
            frames.append(struct.pack("<h", max(-32768, min(32767, sample))))
        wf.writeframes(b"".join(frames))
    return wav_path


_WAV_BLE_ALERT   = _generate_wav(880.0, 0.18)
_WAV_SDR_ALERT   = _generate_wav(440.0, 0.35)
_WAV_NEW_DEV     = _generate_wav(660.0, 0.12)
_WAV_ANOMALY     = _generate_wav(520.0, 0.50)   # tono especial para anomalías de aprendizaje
_WAV_LEARN_DONE  = _generate_wav(880.0, 0.12)   # doble pitido al terminar aprendizaje


def play_sound(wav_path: str):
    def _play():
        try:
            subprocess.Popen(["aplay", "-q", wav_path],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            pass
    threading.Thread(target=_play, daemon=True).start()


def play_double_beep():
    """Doble pitido: aprendizaje completado."""
    def _seq():
        play_sound(_WAV_LEARN_DONE)
        time.sleep(0.2)
        play_sound(_WAV_LEARN_DONE)
    threading.Thread(target=_seq, daemon=True).start()


# ─────────────────────────────────────────────────────────────────
# CACHÉ OUI ONLINE
# ─────────────────────────────────────────────────────────────────
class OUICache:
    def __init__(self):
        self._cache = {}; self._pending = set()
        self._lock = threading.Lock(); self._last_req = 0.0
        self._min_interval = 1.1

    def lookup(self, mac: str, callback):
        prefix = mac.lower()[:8]
        with self._lock:
            if prefix in self._cache:
                callback(mac, self._cache[prefix]); return
            if prefix in self._pending: return
            self._pending.add(prefix)
        threading.Thread(target=self._fetch, args=(mac, prefix, callback), daemon=True).start()

    def _fetch(self, mac: str, prefix: str, callback):
        wait = self._min_interval - (time.monotonic() - self._last_req)
        if wait > 0: time.sleep(wait)
        self._last_req = time.monotonic()
        vendor = "OUI No Registrado (IEEE)"
        try:
            url = OUI_API_URL + urllib.parse.quote(mac[:8])
            req = urllib.request.Request(url, headers={"User-Agent": "HackRadar/2.0"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                text = resp.read().decode("utf-8").strip()
                if text and "errors" not in text.lower():
                    vendor = text
        except Exception:
            pass
        with self._lock:
            self._cache[prefix] = vendor; self._pending.discard(prefix)
        callback(mac, vendor)


# ─────────────────────────────────────────────────────────────────
# MOTOR DE APRENDIZAJE
# ─────────────────────────────────────────────────────────────────
class LearningEngine:
    """
    Fase APRENDIZAJE: observa X segundos y guarda línea base.
    Fase VIGILANCIA:  compara cada nueva lectura contra la base.
    """
    IDLE      = "idle"
    LEARNING  = "learning"
    WATCHING  = "watching"

    def __init__(self):
        self.state           = self.IDLE
        self.duration_s      = 60
        self._start_ts       = 0.0

        # Línea base aprendida
        # BLE:  mac → True  (simplemente "existía")
        # SDR:  label → potencia media durante aprendizaje
        self.baseline_macs   = set()
        self.baseline_sdr    = {}          # label → avg_power
        self._sdr_accum      = {}          # label → [potencias] durante aprendizaje

        # Anomalías detectadas en vigilancia (para no repetir alerta)
        self.anomaly_macs    = set()       # MACs nuevas ya alertadas
        self.anomaly_bands   = set()       # Bandas ya alertadas

        self._lock           = threading.Lock()

    def start(self, duration_s: int):
        with self._lock:
            self.state        = self.LEARNING
            self.duration_s   = duration_s
            self._start_ts    = time.monotonic()
            self.baseline_macs.clear()
            self.baseline_sdr.clear()
            self._sdr_accum.clear()
            self.anomaly_macs.clear()
            self.anomaly_bands.clear()

    def finish(self):
        with self._lock:
            # Calcular medias SDR
            for label, powers in self._sdr_accum.items():
                if powers:
                    self.baseline_sdr[label] = sum(powers) / len(powers)
            self.state = self.WATCHING

    def elapsed_pct(self) -> float:
        if self.state != self.LEARNING:
            return 1.0
        elapsed = time.monotonic() - self._start_ts
        return min(1.0, elapsed / self.duration_s)

    def remaining_s(self) -> int:
        if self.state != self.LEARNING:
            return 0
        return max(0, int(self.duration_s - (time.monotonic() - self._start_ts)))

    def is_learning_done(self) -> bool:
        return self.state == self.LEARNING and time.monotonic() - self._start_ts >= self.duration_s

    # ── Registro durante aprendizaje ──────────────────────────────
    def record_ble(self, mac: str):
        if self.state == self.LEARNING:
            with self._lock:
                self.baseline_macs.add(mac)

    def record_sdr(self, label: str, power: float):
        if self.state == self.LEARNING:
            with self._lock:
                self._sdr_accum.setdefault(label, []).append(power)

    # ── Evaluación en vigilancia ──────────────────────────────────
    def check_ble(self, mac: str) -> tuple[bool, str]:
        """Devuelve (es_anomalia, mensaje)"""
        if self.state != self.WATCHING:
            return False, ""
        if mac not in self.baseline_macs and mac not in self.anomaly_macs:
            with self._lock:
                self.anomaly_macs.add(mac)
            return True, "⚡ ANOMALÍA: [MAC NO VISTA EN APRENDIZAJE]"
        return False, ""

    def check_sdr(self, label: str, power: float) -> tuple[bool, str]:
        """Devuelve (es_anomalia, mensaje)"""
        if self.state != self.WATCHING:
            return False, ""
        if label not in self.baseline_sdr:
            # Banda completamente nueva
            if label not in self.anomaly_bands:
                with self._lock:
                    self.anomaly_bands.add(label)
                return True, "⚡ ANOMALÍA: [BANDA NUEVA NO APRENDIDA]"
        else:
            baseline = self.baseline_sdr[label]
            if power > baseline + ANOMALY_MARGIN_DBM and label not in self.anomaly_bands:
                with self._lock:
                    self.anomaly_bands.add(label)
                return True, f"⚡ ANOMALÍA: [+{power - baseline:.1f} dBm SOBRE LÍNEA BASE]"
        return False, ""

    def reset(self):
        with self._lock:
            self.state = self.IDLE
            self.baseline_macs.clear()
            self.baseline_sdr.clear()
            self._sdr_accum.clear()
            self.anomaly_macs.clear()
            self.anomaly_bands.clear()


# ═════════════════════════════════════════════════════════════════
#  APLICACIÓN PRINCIPAL
# ═════════════════════════════════════════════════════════════════
class HackRadarApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("🛰️ HackRadar Suite v2.0 — TSCM + Motor de Aprendizaje")
        self.geometry("1440x880")

        # ── Estado BLE ──
        self.ble_scanning      = False
        self.ble_loop          = None
        self.ble_thread        = None
        self.ble_devices       = {}
        self.ble_tracking_mac  = ""
        self._ble_last_refresh = 0.0
        self._ble_pending      = False

        # ── Estado SDR ──
        self.sdr_scanning          = False
        self.sdr_process           = None
        self.sdr_thread            = None
        self.sdr_bands             = {}
        self._sdr_last_refresh     = 0.0
        self.sdr_tracking_freq_mhz = None

        # ── Sesión anterior ──
        self.prev_session_macs  = set()
        self.session_start_time = None

        # ── Sonido ──
        self.sound_enabled = True
        self._alerted_macs = set()
        self._alerted_sdrs = set()

        # ── OUI online ──
        self.oui_cache = OUICache()

        # ── Whitelist ──
        self.whitelist: set = set()

        # ── Motor de aprendizaje ──
        self.learner = LearningEngine()
        self._learn_timer_id = None

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.root_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.root_frame.grid(row=0, column=0, sticky="nsew")
        self.root_frame.grid_columnconfigure(1, weight=1)
        self.root_frame.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_tabs()

        # Tick del motor de aprendizaje cada 500ms
        self._learning_tick()

    # ─────────────────────────────────────────────────────────────
    # SIDEBAR
    # ─────────────────────────────────────────────────────────────
    def _build_sidebar(self):
        sb = ctk.CTkFrame(self.root_frame, width=230, corner_radius=0)
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_rowconfigure(16, weight=1)

        ctk.CTkLabel(sb, text="HACKRADAR", font=ctk.CTkFont(size=20, weight="bold")).grid(
            row=0, column=0, padx=20, pady=(20, 2))
        ctk.CTkLabel(sb, text="v2.0 — TSCM + Aprendizaje",
                     font=ctk.CTkFont(size=9), text_color="gray50").grid(row=1, column=0, padx=20, pady=(0, 10))

        self.status_label = ctk.CTkLabel(sb, text="Estado: Listo", text_color="cyan",
                                          font=ctk.CTkFont(size=13, weight="bold"))
        self.status_label.grid(row=2, column=0, padx=20, pady=6)

        # ── BLE ──
        ctk.CTkLabel(sb, text="── MÓDULO BLE ──", font=ctk.CTkFont(size=10), text_color="gray50").grid(row=3, column=0, pady=(8,0))
        self.btn_ble_start = ctk.CTkButton(sb, text="▶ Iniciar BLE", command=self.ble_start)
        self.btn_ble_start.grid(row=4, column=0, padx=20, pady=3)
        self.btn_ble_stop = ctk.CTkButton(sb, text="🛑 Detener BLE", fg_color="coral", hover_color="crimson", command=self.ble_stop)
        self.btn_ble_stop.grid(row=5, column=0, padx=20, pady=3)

        # ── SDR ──
        ctk.CTkLabel(sb, text="── MÓDULO SDR ──", font=ctk.CTkFont(size=10), text_color="gray50").grid(row=6, column=0, pady=(8,0))
        self.btn_sdr_start = ctk.CTkButton(sb, text="▶ Iniciar SDR", fg_color="#1a5276", hover_color="#2980b9", command=self.sdr_start)
        self.btn_sdr_start.grid(row=7, column=0, padx=20, pady=3)
        self.btn_sdr_stop = ctk.CTkButton(sb, text="🛑 Detener SDR", fg_color="coral", hover_color="crimson", command=self.sdr_stop)
        self.btn_sdr_stop.grid(row=8, column=0, padx=20, pady=3)

        # ── APRENDIZAJE ──
        ctk.CTkLabel(sb, text="── APRENDIZAJE ──", font=ctk.CTkFont(size=10), text_color="gray50").grid(row=9, column=0, pady=(8,0))

        dur_frame = ctk.CTkFrame(sb, fg_color="transparent")
        dur_frame.grid(row=10, column=0, padx=20, pady=2)
        ctk.CTkLabel(dur_frame, text="Duración:", font=ctk.CTkFont(size=11)).grid(row=0, column=0, padx=(0,6))
        self.learn_dur_var = ctk.StringVar(value="60")
        ctk.CTkEntry(dur_frame, textvariable=self.learn_dur_var, width=50,
                     font=ctk.CTkFont(family="Courier", size=12)).grid(row=0, column=1)
        ctk.CTkLabel(dur_frame, text="seg", font=ctk.CTkFont(size=11)).grid(row=0, column=2, padx=(4,0))

        self.btn_learn = ctk.CTkButton(sb, text="🎓 Iniciar Aprendizaje",
                                        fg_color="#1a4a1a", hover_color="#2d7a2d",
                                        command=self.toggle_learning)
        self.btn_learn.grid(row=11, column=0, padx=20, pady=3)

        self.learn_progress = ctk.CTkProgressBar(sb, height=10)
        self.learn_progress.grid(row=12, column=0, padx=20, pady=(2,0), sticky="ew")
        self.learn_progress.set(0)

        self.lbl_learn_status = ctk.CTkLabel(sb, text="Estado: Sin calibrar",
                                              font=ctk.CTkFont(size=10), text_color="gray50")
        self.lbl_learn_status.grid(row=13, column=0, padx=20, pady=(2,4))

        # ── ACCIONES ──
        ctk.CTkLabel(sb, text="── ACCIONES ──", font=ctk.CTkFont(size=10), text_color="gray50").grid(row=14, column=0, pady=(8,0))
        ctk.CTkButton(sb, text="💾 Guardar Informe TSCM", fg_color="darkgreen", hover_color="green",
                      command=self.generate_report).grid(row=15, column=0, padx=20, pady=3)
        ctk.CTkButton(sb, text="📸 Guardar Sesión Actual", fg_color="#4a235a", hover_color="#6c3483",
                      command=self.save_session).grid(row=16, column=0, padx=20, pady=3)
        ctk.CTkButton(sb, text="🗑 Limpiar Todo", fg_color="gray25", hover_color="gray35",
                      command=self.clear_all).grid(row=17, column=0, padx=20, pady=3)
        self.btn_mute = ctk.CTkButton(sb, text="🔔 Sonido: ON", fg_color="gray30", hover_color="gray40",
                                       font=ctk.CTkFont(size=11), command=self.toggle_sound)
        self.btn_mute.grid(row=18, column=0, padx=20, pady=3)

        # ── Stats ──
        stats = ctk.CTkFrame(sb, fg_color="transparent")
        stats.grid(row=16, column=0, padx=10, pady=12, sticky="s")
        self.lbl_ble_total  = ctk.CTkLabel(stats, text="BLE Dispositivos: 0", font=ctk.CTkFont(size=11))
        self.lbl_ble_total.grid(row=0, column=0, sticky="w", pady=1)
        self.lbl_ble_alerts = ctk.CTkLabel(stats, text="BLE Alertas: 0", text_color="white", font=ctk.CTkFont(size=11))
        self.lbl_ble_alerts.grid(row=1, column=0, sticky="w", pady=1)
        self.lbl_ble_anomaly = ctk.CTkLabel(stats, text="⚡ Anomalías BLE: 0", text_color="yellow", font=ctk.CTkFont(size=11))
        self.lbl_ble_anomaly.grid(row=2, column=0, sticky="w", pady=1)
        self.lbl_ble_new    = ctk.CTkLabel(stats, text="🆕 Nuevos vs sesión: 0", text_color="cyan", font=ctk.CTkFont(size=11))
        self.lbl_ble_new.grid(row=3, column=0, sticky="w", pady=1)
        self.lbl_sdr_bands  = ctk.CTkLabel(stats, text="SDR Bandas activas: 0", font=ctk.CTkFont(size=11))
        self.lbl_sdr_bands.grid(row=4, column=0, sticky="w", pady=1)
        self.lbl_sdr_alerts = ctk.CTkLabel(stats, text="SDR Alertas: 0", text_color="white", font=ctk.CTkFont(size=11))
        self.lbl_sdr_alerts.grid(row=5, column=0, sticky="w", pady=1)
        self.lbl_sdr_anomaly = ctk.CTkLabel(stats, text="⚡ Anomalías SDR: 0", text_color="yellow", font=ctk.CTkFont(size=11))
        self.lbl_sdr_anomaly.grid(row=6, column=0, sticky="w", pady=1)

        ctk.CTkButton(sb, text="Salir", fg_color="gray20", hover_color="gray30",
                      command=self.close_app).grid(row=19, column=0, padx=20, pady=16, sticky="s")

    # ─────────────────────────────────────────────────────────────
    # PESTAÑAS
    # ─────────────────────────────────────────────────────────────
    def _build_tabs(self):
        self.tabs = ctk.CTkTabview(self.root_frame, corner_radius=12)
        self.tabs.grid(row=0, column=1, sticky="nsew", padx=16, pady=16)
        self.tabs.add("📡 BLE / Bluetooth")
        self.tabs.add("🛰️ SDR Spectrum")
        self._build_ble_tab()
        self._build_sdr_tab()

    def _build_ble_tab(self):
        tab = self.tabs.tab("📡 BLE / Bluetooth")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        hdr = ctk.CTkFrame(tab, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", pady=(8, 4))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(hdr, text="🔎 Detección BLE/Bluetooth — Análisis TSCM + Aprendizaje",
                     font=ctk.CTkFont(size=14, weight="bold")).grid(row=0, column=0, sticky="w")

        btn_frame = ctk.CTkFrame(hdr, fg_color="transparent")
        btn_frame.grid(row=0, column=1, sticky="e")
        self.ble_filter_var = ctk.StringVar()
        self.ble_filter_var.trace_add("write", lambda *_: self.ble_update_display())
        ctk.CTkEntry(btn_frame, textvariable=self.ble_filter_var,
                     placeholder_text="🔍 Filtrar...", width=180,
                     font=ctk.CTkFont(family="Courier", size=12)).grid(row=0, column=0, padx=(0, 8))
        self.entry_wl = ctk.CTkEntry(btn_frame, placeholder_text="MAC → Whitelist", width=170,
                                      font=ctk.CTkFont(family="Courier", size=12))
        self.entry_wl.grid(row=0, column=1, padx=(0, 4))
        ctk.CTkButton(btn_frame, text="✅ Marcar Seguro", width=120, fg_color="#145a32", hover_color="#1e8449",
                      command=self.add_to_whitelist).grid(row=0, column=2)

        self.ble_textbox = ctk.CTkTextbox(tab, font=ctk.CTkFont(family="Courier", size=12), wrap="none")
        self.ble_textbox.grid(row=1, column=0, sticky="nsew", pady=(4, 0))
        self.ble_textbox.insert("0.0", "Esperando inicio de escaneo BLE...\n")
        self.ble_textbox.configure(state="disabled")

        gonio = ctk.CTkFrame(tab, height=140, border_width=1, border_color="gray30")
        gonio.grid(row=2, column=0, sticky="ew", pady=(10, 8))
        gonio.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(gonio, text="📡 GONIÓMETRO DE PROXIMIDAD BLE",
                     font=ctk.CTkFont(size=12, weight="bold")).grid(
            row=0, column=0, columnspan=4, padx=15, pady=(8, 2), sticky="w")
        ctk.CTkLabel(gonio, text="MAC Objetivo:").grid(row=1, column=0, padx=(15, 5), pady=5, sticky="w")
        self.ble_entry_mac = ctk.CTkEntry(gonio, placeholder_text="AA:BB:CC:DD:EE:FF",
                                           width=210, font=ctk.CTkFont(family="Courier"))
        self.ble_entry_mac.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        self.btn_ble_track = ctk.CTkButton(gonio, text="Fijar Objetivo", width=130,
                                            fg_color="purple", hover_color="indigo",
                                            command=self.ble_toggle_tracking)
        self.btn_ble_track.grid(row=1, column=2, padx=10, pady=5)
        self.lbl_ble_rssi_inst = ctk.CTkLabel(gonio, text="Inst: — dBm",
                                               font=ctk.CTkFont(size=11), text_color="gray60")
        self.lbl_ble_rssi_inst.grid(row=1, column=3, padx=(5, 15), pady=5, sticky="e")
        self.ble_progress = ctk.CTkProgressBar(gonio, height=16)
        self.ble_progress.grid(row=2, column=0, columnspan=3, padx=(15, 10), pady=8, sticky="ew")
        self.ble_progress.set(0)
        self.lbl_ble_proximity = ctk.CTkLabel(gonio, text="Rastreador: En espera",
                                               font=ctk.CTkFont(size=12, weight="bold"), text_color="gray")
        self.lbl_ble_proximity.grid(row=2, column=3, padx=(5, 15), pady=8, sticky="e")

    def _build_sdr_tab(self):
        tab = self.tabs.tab("🛰️ SDR Spectrum")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, sticky="ew", pady=(8, 4))
        ctrl.grid_columnconfigure(6, weight=1)
        ctk.CTkLabel(ctrl, text="Rango MHz:", font=ctk.CTkFont(size=12)).grid(row=0, column=0, padx=(0, 4))
        self.sdr_min_var = ctk.StringVar(value="300")
        self.sdr_max_var = ctk.StringVar(value="6000")
        ctk.CTkEntry(ctrl, textvariable=self.sdr_min_var, width=80,
                     font=ctk.CTkFont(family="Courier", size=12)).grid(row=0, column=1, padx=4)
        ctk.CTkLabel(ctrl, text="→").grid(row=0, column=2, padx=2)
        ctk.CTkEntry(ctrl, textvariable=self.sdr_max_var, width=80,
                     font=ctk.CTkFont(family="Courier", size=12)).grid(row=0, column=3, padx=4)
        ctk.CTkLabel(ctrl, text="  Umbral (dBm):", font=ctk.CTkFont(size=12)).grid(row=0, column=4, padx=(16, 4))
        self.sdr_threshold_var = ctk.StringVar(value="-80")
        ctk.CTkEntry(ctrl, textvariable=self.sdr_threshold_var, width=64,
                     font=ctk.CTkFont(family="Courier", size=12)).grid(row=0, column=5, padx=4)
        self.sdr_filter_var = ctk.StringVar()
        self.sdr_filter_var.trace_add("write", lambda *_: self.sdr_update_display())
        ctk.CTkEntry(ctrl, textvariable=self.sdr_filter_var,
                     placeholder_text="🔍 Filtrar banda...", width=200,
                     font=ctk.CTkFont(family="Courier", size=12)).grid(row=0, column=6, padx=(16, 0), sticky="e")

        self.sdr_textbox = ctk.CTkTextbox(tab, font=ctk.CTkFont(family="Courier", size=12), wrap="none")
        self.sdr_textbox.grid(row=1, column=0, sticky="nsew", pady=(4, 0))
        self.sdr_textbox.insert("0.0", "Esperando inicio de barrido SDR (HackRF)...\n")
        self.sdr_textbox.configure(state="disabled")

        gonio_sdr = ctk.CTkFrame(tab, height=110, border_width=1, border_color="gray30")
        gonio_sdr.grid(row=2, column=0, sticky="ew", pady=(10, 8))
        gonio_sdr.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(gonio_sdr, text="🛰️ GONIÓMETRO SDR — Seguimiento de frecuencia fijada",
                     font=ctk.CTkFont(size=12, weight="bold")).grid(
            row=0, column=0, columnspan=4, padx=15, pady=(8, 2), sticky="w")
        ctk.CTkLabel(gonio_sdr, text="Frecuencia (MHz):").grid(row=1, column=0, padx=(15, 5), pady=5, sticky="w")
        self.sdr_entry_freq = ctk.CTkEntry(gonio_sdr, placeholder_text="ej: 433.92",
                                            width=140, font=ctk.CTkFont(family="Courier"))
        self.sdr_entry_freq.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        self.btn_sdr_track = ctk.CTkButton(gonio_sdr, text="Fijar Frecuencia", width=140,
                                            fg_color="#6e2fa0", hover_color="#4a1f6e",
                                            command=self.sdr_toggle_tracking)
        self.btn_sdr_track.grid(row=1, column=2, padx=10, pady=5)
        self.lbl_sdr_power_inst = ctk.CTkLabel(gonio_sdr, text="Potencia: — dBm",
                                                font=ctk.CTkFont(size=11), text_color="gray60")
        self.lbl_sdr_power_inst.grid(row=1, column=3, padx=(5, 15), pady=5, sticky="e")
        self.sdr_progress = ctk.CTkProgressBar(gonio_sdr, height=16)
        self.sdr_progress.grid(row=2, column=0, columnspan=3, padx=(15, 10), pady=8, sticky="ew")
        self.sdr_progress.set(0)
        self.lbl_sdr_proximity = ctk.CTkLabel(gonio_sdr, text="Rastreador SDR: En espera",
                                               font=ctk.CTkFont(size=12, weight="bold"), text_color="gray")
        self.lbl_sdr_proximity.grid(row=2, column=3, padx=(5, 15), pady=8, sticky="e")

    # ─────────────────────────────────────────────────────────────
    # MOTOR DE APRENDIZAJE — TICK Y CONTROL
    # ─────────────────────────────────────────────────────────────
    def _learning_tick(self):
        """Actualiza la barra de progreso y detecta fin de aprendizaje."""
        if self.learner.state == LearningEngine.LEARNING:
            pct = self.learner.elapsed_pct()
            self.learn_progress.set(pct)
            rem = self.learner.remaining_s()
            self.lbl_learn_status.configure(
                text=f"⏳ Aprendiendo... {rem}s restantes", text_color="yellow")
            if self.learner.is_learning_done():
                self.learner.finish()
                self._on_learning_complete()
        self.after(500, self._learning_tick)

    def _on_learning_complete(self):
        n_macs  = len(self.learner.baseline_macs)
        n_bands = len(self.learner.baseline_sdr)
        self.learn_progress.set(1.0)
        self.learn_progress.configure(progress_color="lime")
        self.lbl_learn_status.configure(
            text=f"✅ Vigilancia activa — {n_macs} MACs, {n_bands} bandas",
            text_color="lime")
        self.btn_learn.configure(text="🔄 Reaprender", fg_color="#1a4a1a", hover_color="#2d7a2d")
        play_double_beep()
        # Log en ambas pestañas
        msg = (f"\n[🎓] Aprendizaje completado. Línea base: "
               f"{n_macs} MACs BLE + {n_bands} bandas SDR\n"
               f"[👁] Modo VIGILANCIA activo — alertando anomalías nuevas\n")
        for tb in (self.ble_textbox, self.sdr_textbox):
            tb.configure(state="normal")
            tb.insert("end", msg)
            tb.configure(state="disabled")

    def toggle_learning(self):
        if self.learner.state == LearningEngine.LEARNING:
            # Cancelar aprendizaje
            self.learner.reset()
            self.learn_progress.set(0)
            self.learn_progress.configure(progress_color="#1f538d")
            self.lbl_learn_status.configure(text="Estado: Cancelado", text_color="coral")
            self.btn_learn.configure(text="🎓 Iniciar Aprendizaje")
            return
        try:
            dur = int(self.learn_dur_var.get())
        except ValueError:
            dur = 60
        self.learner.start(dur)
        self.learn_progress.configure(progress_color="yellow")
        self.btn_learn.configure(text="⏹ Cancelar", fg_color="coral", hover_color="crimson")
        msg = f"\n[🎓] Aprendizaje iniciado — {dur} segundos observando el entorno...\n"
        for tb in (self.ble_textbox, self.sdr_textbox):
            tb.configure(state="normal")
            tb.insert("end", msg)
            tb.configure(state="disabled")

    # ─────────────────────────────────────────────────────────────
    # SONIDO Y WHITELIST
    # ─────────────────────────────────────────────────────────────
    def toggle_sound(self):
        self.sound_enabled = not self.sound_enabled
        self.btn_mute.configure(
            text="🔔 Sonido: ON" if self.sound_enabled else "🔇 Sonido: OFF",
            fg_color="gray30" if self.sound_enabled else "gray20")

    def add_to_whitelist(self):
        mac = self.entry_wl.get().strip().upper()
        if len(mac) >= 12:
            self.whitelist.add(mac)
            self.entry_wl.delete(0, "end")
            self.ble_update_display()

    # ─────────────────────────────────────────────────────────────
    # SESIONES
    # ─────────────────────────────────────────────────────────────
    def save_session(self):
        self.prev_session_macs = set(self.ble_devices.keys())
        self.session_start_time = datetime.now().strftime("%H:%M:%S")
        self._alerted_macs.clear()
        self.ble_update_display()

    def _is_new_device(self, mac: str) -> bool:
        return bool(self.prev_session_macs) and mac not in self.prev_session_macs

    # ─────────────────────────────────────────────────────────────
    # LÓGICA BLE
    # ─────────────────────────────────────────────────────────────
    def _ble_get_vendor(self, mac: str):
        if is_random_mac(mac):
            return "MAC Aleatorizada (Dispositivo Privado)"
        return MAC_VENDORS.get(mac.lower()[:8], None)

    def ble_device_detected(self, device, adv):
        if not self.ble_scanning:
            return
        mac    = device.address
        nombre = device.name if device.name else "Dispositivo Oculto"
        rssi   = adv.rssi
        now    = datetime.now().strftime("%H:%M:%S")

        # Registrar en motor de aprendizaje
        self.learner.record_ble(mac)

        if mac not in self.ble_devices:
            vendor_local = self._ble_get_vendor(mac)
            fabricante   = vendor_local if vendor_local else "Consultando OUI..."
            self.ble_devices[mac] = {
                "name": nombre, "rssi": rssi, "vendor": fabricante,
                "is_threat": False, "reason": "OK", "anomaly": False,
                "first_seen": now, "last_seen": now,
                "rssi_history": collections.deque(maxlen=RSSI_HISTORY_SIZE),
                "oui_resolved": vendor_local is not None,
            }
            if not vendor_local and not is_random_mac(mac):
                self.oui_cache.lookup(mac, self._oui_callback)
            if self._is_new_device(mac) and self.sound_enabled:
                play_sound(_WAV_NEW_DEV)

        e = self.ble_devices[mac]
        e["rssi"] = rssi; e["last_seen"] = now; e["rssi_history"].append(rssi)
        if nombre != "Dispositivo Oculto":
            e["name"] = nombre

        avg = sum(e["rssi_history"]) / len(e["rssi_history"])
        vl  = e["vendor"].lower()

        # ── Reglas clásicas ──
        thr = False; raz = "OK"
        if mac.upper() in self.whitelist:
            thr = False; raz = "✅ VERIFICADO"
        elif any(x in vl for x in BLACKLIST_VENDORS) and avg >= -70:
            thr = True; raz = "⚠️ ALERT: [SOSPECHA IOT/RASTREADOR]"
        elif avg >= -65:
            thr = True; raz = "⚠️ ALERT: [PROXIMIDAD CRÍTICA]"
        elif "aleatorizada" in vl and avg >= -68:
            thr = True; raz = "⚠️ ALERT: [RÁFAGAS MÓVIL ANÓNIMO]"
        e["is_threat"] = thr; e["reason"] = raz

        # ── Reglas de aprendizaje (sobreescriben si hay anomalía) ──
        is_anomaly, anomaly_msg = self.learner.check_ble(mac)
        if is_anomaly and mac.upper() not in self.whitelist:
            e["anomaly"] = True
            e["reason"]  = anomaly_msg
            if self.sound_enabled:
                play_sound(_WAV_ANOMALY)
        else:
            e["anomaly"] = e.get("anomaly", False)

        if thr and mac not in self._alerted_macs and self.sound_enabled:
            self._alerted_macs.add(mac)
            play_sound(_WAV_BLE_ALERT)

        if self.ble_tracking_mac and mac.lower() == self.ble_tracking_mac.lower():
            self.after(0, lambda r=avg, ri=rssi: self.ble_update_tracker(r, ri))

        now_ts = time.monotonic()
        if now_ts - self._ble_last_refresh >= DISPLAY_REFRESH_INTERVAL:
            self._ble_last_refresh = now_ts
            self.after(0, self.ble_update_display)
        elif not self._ble_pending:
            self._ble_pending = True
            self.after(int(DISPLAY_REFRESH_INTERVAL * 1000), self._ble_deferred_refresh)

    def _oui_callback(self, mac: str, vendor: str):
        if mac in self.ble_devices:
            self.ble_devices[mac]["vendor"]       = vendor
            self.ble_devices[mac]["oui_resolved"] = True
            self.after(0, self.ble_update_display)

    def _ble_deferred_refresh(self):
        self._ble_pending = False
        self._ble_last_refresh = time.monotonic()
        self.ble_update_display()

    def ble_toggle_tracking(self):
        if not self.ble_tracking_mac:
            t = self.ble_entry_mac.get().strip()
            if len(t) >= 12:
                self.ble_tracking_mac = t
                self.btn_ble_track.configure(text="Liberar", fg_color="crimson", hover_color="darkred")
                self.ble_entry_mac.configure(state="disabled")
                self.lbl_ble_proximity.configure(text="Buscando señal...", text_color="yellow")
            else:
                self.lbl_ble_proximity.configure(text="❌ MAC inválida", text_color="red")
        else:
            self.ble_tracking_mac = ""
            self.btn_ble_track.configure(text="Fijar Objetivo", fg_color="purple", hover_color="indigo")
            self.ble_entry_mac.configure(state="normal")
            self.ble_progress.set(0)
            self.lbl_ble_rssi_inst.configure(text="Inst: — dBm", text_color="gray60")
            self.lbl_ble_proximity.configure(text="Rastreador: En espera", text_color="gray")

    def ble_update_tracker(self, avg: float, inst: int):
        pct = (max(-90, min(-40, avg)) + 90) / 50.0
        self.ble_progress.set(pct)
        self.lbl_ble_rssi_inst.configure(text=f"Inst: {inst} dBm", text_color="white")
        if avg >= -55:
            self.lbl_ble_proximity.configure(text=f"🔥 MÁXIMA PROXIMIDAD ({avg:.1f} dBm) <0.5m", text_color="red")
            self.ble_progress.configure(progress_color="red")
        elif avg >= -65:
            self.lbl_ble_proximity.configure(text=f"🟠 CALIENTE ({avg:.1f} dBm)", text_color="orange")
            self.ble_progress.configure(progress_color="orange")
        elif avg >= -75:
            self.lbl_ble_proximity.configure(text=f"🟡 TEMPLADO ({avg:.1f} dBm)", text_color="yellow")
            self.ble_progress.configure(progress_color="yellow")
        else:
            self.lbl_ble_proximity.configure(text=f"❄️ FRÍO ({avg:.1f} dBm)", text_color="cyan")
            self.ble_progress.configure(progress_color="cyan")

    def ble_update_display(self):
        self.ble_textbox.configure(state="normal")
        self.ble_textbox.delete("1.0", "end")
        filtro = self.ble_filter_var.get().lower().strip()
        HDR = (f"{'Nº':<4} | {'F':<3} | {'MAC':<21} | {'FABRICANTE (OUI)':<36} | "
               f"{'DISPOSITIVO':<22} | {'RSSI avg':>9} | {'VISTO':<8} | ALERTA\n")
        self.ble_textbox.insert("end", HDR)
        self.ble_textbox.insert("end", "─" * 150 + "\n")

        alertas = 0; nuevos = 0; anomalias = 0
        for idx, (mac, i) in enumerate(
            sorted(self.ble_devices.items(), key=lambda x: x[1]["rssi"], reverse=True), 1
        ):
            if filtro and filtro not in mac.lower() and filtro not in i["vendor"].lower() and filtro not in i["name"].lower():
                continue
            if i["is_threat"]: alertas += 1
            if i.get("anomaly"): anomalias += 1
            is_new = self._is_new_device(mac)
            if is_new: nuevos += 1
            avg = sum(i["rssi_history"]) / len(i["rssi_history"]) if i["rssi_history"] else i["rssi"]
            f_track  = "🎯" if self.ble_tracking_mac and mac.lower() == self.ble_tracking_mac.lower() else " "
            f_new    = "🆕" if is_new else " "
            f_safe   = "✅" if mac.upper() in self.whitelist else " "
            flags    = f"{f_track}{f_new}{f_safe}"
            self.ble_textbox.insert("end",
                f"{idx:<4} | {flags:<3} | {mac:<21} | {i['vendor']:<36} | "
                f"{i['name']:<22} | {avg:>6.1f} dBm | {i['last_seen']:<8} | {i['reason']}\n")

        self.lbl_ble_total.configure(text=f"BLE Dispositivos: {len(self.ble_devices)}")
        self.lbl_ble_new.configure(text=f"🆕 Nuevos vs sesión: {nuevos}")
        self.lbl_ble_anomaly.configure(
            text=f"⚡ Anomalías BLE: {anomalias}",
            text_color="yellow" if anomalias else "gray50")
        if alertas:
            self.lbl_ble_alerts.configure(text=f"🚨 BLE Alertas: {alertas}", text_color="red")
            self.status_label.configure(text="⚠️ AMENAZA BLE", text_color="red")
        else:
            self.lbl_ble_alerts.configure(text="BLE Alertas: 0", text_color="white")
            if self.ble_scanning and self.learner.state != LearningEngine.WATCHING:
                self.status_label.configure(text="BLE: Escaneando...", text_color="lime")
            elif self.ble_scanning:
                self.status_label.configure(text="👁 VIGILANCIA ACTIVA", text_color="lime")
        self.ble_textbox.configure(state="disabled")

    def _ble_async_loop(self):
        self.ble_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.ble_loop)
        scanner = BleakScanner(detection_callback=self.ble_device_detected)
        self.ble_loop.run_until_complete(scanner.start())
        self.ble_loop.run_forever()

    def ble_start(self):
        if self.ble_scanning: return
        self.ble_scanning = True
        self._ble_last_refresh = 0.0
        self.status_label.configure(text="BLE: Escaneando...", text_color="lime")
        self.ble_textbox.configure(state="normal")
        self.ble_textbox.delete("1.0", "end")
        self.ble_textbox.insert("end", "[+] HackRadar v2.0 — BLE activo. Usa 🎓 Aprendizaje para modo vigilancia.\n")
        self.ble_textbox.configure(state="disabled")
        self.ble_thread = threading.Thread(target=self._ble_async_loop, daemon=True)
        self.ble_thread.start()

    def ble_stop(self):
        if not self.ble_scanning: return
        self.ble_scanning = False
        self.status_label.configure(text="BLE: Detenido", text_color="coral")
        if self.ble_loop:
            self.ble_loop.call_soon_threadsafe(self.ble_loop.stop)
        amenazas = sum(1 for x in self.ble_devices.values() if x["is_threat"])
        self.ble_textbox.configure(state="normal")
        self.ble_textbox.insert("end", f"\n[-] BLE pausado. Amenazas: {amenazas}\n")
        self.ble_textbox.configure(state="disabled")

    # ─────────────────────────────────────────────────────────────
    # LÓGICA SDR
    # ─────────────────────────────────────────────────────────────
    def _sdr_parse_line(self, line: str):
        try:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 7: return
            hz_low  = float(parts[2])
            hz_high = float(parts[3])
            powers  = [float(x) for x in parts[6:] if x]
            if not powers: return
            freq_center = (hz_low + hz_high) / 2.0
            max_power   = max(powers)
            try:
                threshold = float(self.sdr_threshold_var.get())
            except ValueError:
                threshold = ACTIVE_SIGNAL_THRESHOLD
            if max_power < threshold: return

            label, desc = classify_band(freq_center)

            # Registrar en aprendizaje
            self.learner.record_sdr(label, max_power)

            is_thr, reason = assess_sdr_threat(freq_center, max_power)

            # Comprobar anomalía de aprendizaje
            is_anomaly, anomaly_msg = self.learner.check_sdr(label, max_power)
            if is_anomaly:
                is_thr = True
                reason = anomaly_msg
                if self.sound_enabled:
                    play_sound(_WAV_ANOMALY)

            now_str = datetime.now().strftime("%H:%M:%S")
            if label not in self.sdr_bands:
                self.sdr_bands[label] = {
                    "freq_hz": freq_center, "desc": desc,
                    "power": max_power, "is_threat": is_thr, "reason": reason,
                    "first_seen": now_str, "last_seen": now_str,
                    "history": collections.deque(maxlen=RSSI_HISTORY_SIZE),
                    "anomaly": is_anomaly,
                }
            b = self.sdr_bands[label]
            if max_power > b["power"]: b["power"] = max_power
            b["history"].append(max_power)
            b["last_seen"] = now_str
            b["is_threat"] = is_thr; b["reason"] = reason
            if is_anomaly: b["anomaly"] = True

            if is_thr and label not in self._alerted_sdrs and self.sound_enabled and not is_anomaly:
                self._alerted_sdrs.add(label)
                play_sound(_WAV_SDR_ALERT)

            if self.sdr_tracking_freq_mhz is not None:
                if abs(freq_center/1e6 - self.sdr_tracking_freq_mhz) <= 5.0:
                    avg_p = sum(b["history"]) / len(b["history"])
                    self.after(0, lambda p=avg_p, pi=max_power: self.sdr_update_tracker(p, pi))

            now_ts = time.monotonic()
            if now_ts - self._sdr_last_refresh >= DISPLAY_REFRESH_INTERVAL:
                self._sdr_last_refresh = now_ts
                self.after(0, self.sdr_update_display)
        except Exception:
            pass

    def _sdr_log(self, msg: str):
        self.sdr_textbox.configure(state="normal")
        self.sdr_textbox.insert("end", msg)
        self.sdr_textbox.configure(state="disabled")

    def _sdr_reader_thread(self):
        try:
            f_min = int(self.sdr_min_var.get())
            f_max = int(self.sdr_max_var.get())
        except ValueError:
            f_min, f_max = 300, 6000
        cmd = ["hackrf_sweep", "-f", f"{f_min}:{f_max}", "-w", "500000", "-l", "32", "-g", "40"]
        try:
            self.sdr_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            self.after(0, lambda: self._sdr_log("✅ hackrf_sweep iniciado.\n"))
            for line in self.sdr_process.stdout:
                if not self.sdr_scanning: break
                self._sdr_parse_line(line.strip())
        except FileNotFoundError:
            self.after(0, lambda: self._sdr_log("❌ hackrf_sweep no encontrado. sudo apt install hackrf\n"))
        except Exception as ex:
            self.after(0, lambda e=ex: self._sdr_log(f"❌ Error SDR: {e}\n"))

    def sdr_toggle_tracking(self):
        if self.sdr_tracking_freq_mhz is None:
            try:
                f = float(self.sdr_entry_freq.get().strip())
                self.sdr_tracking_freq_mhz = f
                self.btn_sdr_track.configure(text="Liberar Frecuencia", fg_color="crimson", hover_color="darkred")
                self.sdr_entry_freq.configure(state="disabled")
                self.lbl_sdr_proximity.configure(text=f"Buscando {f} MHz...", text_color="yellow")
            except ValueError:
                self.lbl_sdr_proximity.configure(text="❌ Frecuencia inválida", text_color="red")
        else:
            self.sdr_tracking_freq_mhz = None
            self.btn_sdr_track.configure(text="Fijar Frecuencia", fg_color="#6e2fa0", hover_color="#4a1f6e")
            self.sdr_entry_freq.configure(state="normal")
            self.sdr_progress.set(0)
            self.lbl_sdr_power_inst.configure(text="Potencia: — dBm", text_color="gray60")
            self.lbl_sdr_proximity.configure(text="Rastreador SDR: En espera", text_color="gray")

    def sdr_update_tracker(self, avg: float, inst: float):
        pct = (max(-90, min(-40, avg)) + 90) / 50.0
        self.sdr_progress.set(pct)
        self.lbl_sdr_power_inst.configure(text=f"Potencia: {inst:.1f} dBm", text_color="white")
        if avg >= -55:
            self.lbl_sdr_proximity.configure(text=f"🔥 EMISOR MUY CERCANO ({avg:.1f} dBm)", text_color="red")
            self.sdr_progress.configure(progress_color="red")
        elif avg >= -65:
            self.lbl_sdr_proximity.configure(text=f"🟠 SEÑAL FUERTE ({avg:.1f} dBm)", text_color="orange")
            self.sdr_progress.configure(progress_color="orange")
        elif avg >= -75:
            self.lbl_sdr_proximity.configure(text=f"🟡 EN RANGO ({avg:.1f} dBm)", text_color="yellow")
            self.sdr_progress.configure(progress_color="yellow")
        else:
            self.lbl_sdr_proximity.configure(text=f"❄️ SEÑAL LEJANA ({avg:.1f} dBm)", text_color="cyan")
            self.sdr_progress.configure(progress_color="cyan")

    def sdr_update_display(self):
        self.sdr_textbox.configure(state="normal")
        self.sdr_textbox.delete("1.0", "end")
        filtro = self.sdr_filter_var.get().lower().strip()
        HDR = (f"{'F':<2} | {'BANDA':<22} | {'DESCRIPCIÓN':<30} | {'FREQ. CENTRO':>14} | "
               f"{'POT. MAX':>9} | {'POT. AVG':>9} | {'VISTO':<8} | ALERTA\n")
        self.sdr_textbox.insert("end", HDR)
        self.sdr_textbox.insert("end", "─" * 138 + "\n")

        alertas = 0; activas = 0; anomalias = 0
        for label, b in sorted(self.sdr_bands.items(), key=lambda x: x[1]["power"], reverse=True):
            if filtro and filtro not in label.lower() and filtro not in b["desc"].lower(): continue
            activas += 1
            if b["is_threat"]: alertas += 1
            if b.get("anomaly"): anomalias += 1
            avg_p = sum(b["history"]) / len(b["history"]) if b["history"] else b["power"]
            f_track = "🎯" if (self.sdr_tracking_freq_mhz is not None and
                               abs(b["freq_hz"]/1e6 - self.sdr_tracking_freq_mhz) <= 5.0) else " "
            f_anom  = "⚡" if b.get("anomaly") else " "
            flags   = f"{f_track}{f_anom}"
            freq_str = f"{b['freq_hz']/1e6:>10.2f} MHz"
            self.sdr_textbox.insert("end",
                f"{flags:<2} | {label:<22} | {b['desc']:<30} | {freq_str} | "
                f"{b['power']:>6.1f} dBm | {avg_p:>6.1f} dBm | {b['last_seen']:<8} | {b['reason']}\n")

        self.lbl_sdr_bands.configure(text=f"SDR Bandas activas: {activas}")
        self.lbl_sdr_anomaly.configure(
            text=f"⚡ Anomalías SDR: {anomalias}",
            text_color="yellow" if anomalias else "gray50")
        if alertas:
            self.lbl_sdr_alerts.configure(text=f"🚨 SDR Alertas: {alertas}", text_color="red")
            self.status_label.configure(text="⚠️ AMENAZA SDR", text_color="red")
        else:
            self.lbl_sdr_alerts.configure(text="SDR Alertas: 0", text_color="white")
            if self.sdr_scanning:
                lbl = "👁 VIGILANCIA ACTIVA" if self.learner.state == LearningEngine.WATCHING else "SDR: Barriendo..."
                col = "lime" if self.learner.state == LearningEngine.WATCHING else "#2980b9"
                self.status_label.configure(text=lbl, text_color=col)
        self.sdr_textbox.configure(state="disabled")

    def sdr_start(self):
        if self.sdr_scanning: return
        self.sdr_scanning = True
        self._sdr_last_refresh = 0.0
        self.sdr_bands.clear()
        self._alerted_sdrs.clear()
        self.status_label.configure(text="SDR: Iniciando...", text_color="#2980b9")
        self.sdr_textbox.configure(state="normal")
        self.sdr_textbox.delete("1.0", "end")
        self.sdr_textbox.insert("end", "[+] HackRF One — hackrf_sweep iniciando...\n")
        self.sdr_textbox.configure(state="disabled")
        self.sdr_thread = threading.Thread(target=self._sdr_reader_thread, daemon=True)
        self.sdr_thread.start()

    def sdr_stop(self):
        if not self.sdr_scanning: return
        self.sdr_scanning = False
        if self.sdr_process:
            self.sdr_process.terminate(); self.sdr_process = None
        amenazas = sum(1 for x in self.sdr_bands.values() if x["is_threat"])
        self.status_label.configure(text="SDR: Detenido", text_color="coral")
        self.sdr_textbox.configure(state="normal")
        self.sdr_textbox.insert("end", f"\n[-] SDR pausado. Bandas con alerta: {amenazas}\n")
        self.sdr_textbox.configure(state="disabled")

    # ─────────────────────────────────────────────────────────────
    # INFORME FORENSE
    # ─────────────────────────────────────────────────────────────
    def generate_report(self):
        filename = f"TSCM_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("=" * 72 + "\n")
                f.write("     INFORME FORENSE TSCM — HackRadar Suite v2.0\n")
                f.write("     BLE/Bluetooth  +  SDR Spectrum (HackRF One)\n")
                f.write("     Motor de Aprendizaje Activo\n")
                f.write("=" * 72 + "\n")
                f.write(f"Fecha/Hora : {datetime.now().strftime('%d/%m/%Y — %H:%M:%S')}\n")
                estado_learn = {
                    LearningEngine.IDLE: "Sin calibrar",
                    LearningEngine.LEARNING: "En aprendizaje",
                    LearningEngine.WATCHING: f"Vigilancia activa — {len(self.learner.baseline_macs)} MACs / {len(self.learner.baseline_sdr)} bandas"
                }.get(self.learner.state, "—")
                f.write(f"Aprendizaje: {estado_learn}\n\n")

                # BLE
                anomalias_ble = sum(1 for x in self.ble_devices.values() if x.get("anomaly"))
                f.write("━━━ SECCIÓN 1: BLE/BLUETOOTH ━━━\n")
                f.write(f"Total: {len(self.ble_devices)}  "
                        f"Alertas: {sum(1 for x in self.ble_devices.values() if x['is_threat'])}  "
                        f"Anomalías: {anomalias_ble}  "
                        f"Nuevos: {sum(1 for m in self.ble_devices if self._is_new_device(m))}\n")
                f.write("-" * 72 + "\n")
                f.write(f"{'MAC':<20} | {'FABRICANTE':<32} | {'DISPOSITIVO':<20} | "
                        f"{'RSSI avg':>8} | {'1ª VEZ':>8} | {'ÚLT':>8} | ESTADO\n")
                f.write("-" * 120 + "\n")
                for mac, i in sorted(self.ble_devices.items(), key=lambda x: x[1]["rssi"], reverse=True):
                    avg = sum(i["rssi_history"]) / len(i["rssi_history"]) if i["rssi_history"] else i["rssi"]
                    tags = ""
                    if self._is_new_device(mac): tags += " [NUEVO]"
                    if mac.upper() in self.whitelist: tags += " [WHITELIST]"
                    if i.get("anomaly"): tags += " [ANOMALÍA]"
                    f.write(f"{mac:<20} | {i['vendor']:<32} | {i['name']:<20} | "
                            f"{avg:>6.1f} dBm | {i['first_seen']:>8} | {i['last_seen']:>8} | "
                            f"{i['reason']}{tags}\n")

                # SDR
                anomalias_sdr = sum(1 for x in self.sdr_bands.values() if x.get("anomaly"))
                f.write("\n━━━ SECCIÓN 2: SDR SPECTRUM (HackRF One) ━━━\n")
                f.write(f"Bandas activas: {len(self.sdr_bands)}  "
                        f"Alertas: {sum(1 for x in self.sdr_bands.values() if x['is_threat'])}  "
                        f"Anomalías: {anomalias_sdr}\n")
                f.write("-" * 72 + "\n")
                f.write(f"{'BANDA':<22} | {'DESCRIPCIÓN':<28} | {'FREQ. CENTRO':>14} | "
                        f"{'POT. MAX':>8} | {'POT. AVG':>8} | {'VISTO':>8} | ESTADO\n")
                f.write("-" * 120 + "\n")
                for label, b in sorted(self.sdr_bands.items(), key=lambda x: x[1]["power"], reverse=True):
                    avg_p = sum(b["history"]) / len(b["history"]) if b["history"] else b["power"]
                    anom_tag = " [ANOMALÍA]" if b.get("anomaly") else ""
                    f.write(f"{label:<22} | {b['desc']:<28} | {b['freq_hz']/1e6:>12.2f} MHz | "
                            f"{b['power']:>6.1f} dBm | {avg_p:>6.1f} dBm | {b['last_seen']:>8} | "
                            f"{b['reason']}{anom_tag}\n")

                # Línea base aprendida
                if self.learner.state == LearningEngine.WATCHING:
                    f.write("\n━━━ SECCIÓN 3: LÍNEA BASE APRENDIDA ━━━\n")
                    f.write(f"MACs en línea base: {len(self.learner.baseline_macs)}\n")
                    for mac in sorted(self.learner.baseline_macs):
                        f.write(f"  {mac}\n")
                    f.write(f"\nBandas SDR en línea base: {len(self.learner.baseline_sdr)}\n")
                    for label, power in sorted(self.learner.baseline_sdr.items(), key=lambda x: x[1], reverse=True):
                        f.write(f"  {label:<22} → {power:>6.1f} dBm (media)\n")

                f.write("\n" + "=" * 72 + "\n")
                f.write("Fin del informe. Generado con HackRadar Suite v2.0.\n")

            self.ble_textbox.configure(state="normal")
            self.ble_textbox.insert("end", f"\n💾 Informe guardado: '{filename}'\n")
            self.ble_textbox.configure(state="disabled")
        except Exception as e:
            self.ble_textbox.configure(state="normal")
            self.ble_textbox.insert("end", f"\n❌ Error al guardar: {e}\n")
            self.ble_textbox.configure(state="disabled")

    def clear_all(self):
        self.ble_devices.clear()
        self.sdr_bands.clear()
        self._alerted_macs.clear()
        self._alerted_sdrs.clear()
        self.learner.reset()
        self.learn_progress.set(0)
        self.learn_progress.configure(progress_color="#1f538d")
        self.lbl_learn_status.configure(text="Estado: Sin calibrar", text_color="gray50")
        self.btn_learn.configure(text="🎓 Iniciar Aprendizaje", fg_color="#1a4a1a", hover_color="#2d7a2d")
        for tb in (self.ble_textbox, self.sdr_textbox):
            tb.configure(state="normal")
            tb.delete("1.0", "end")
            tb.insert("end", "[+] Tabla limpiada. Aprendizaje reseteado.\n")
            tb.configure(state="disabled")

    def close_app(self):
        self.ble_stop(); self.sdr_stop(); self.destroy()


if __name__ == "__main__":
    app = HackRadarApp()
    app.mainloop()