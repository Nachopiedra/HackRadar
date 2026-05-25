import customtkinter as ctk
import asyncio
import threading
from bleak import BleakScanner
from datetime import datetime
import os
import collections
import time

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# ─────────────────────────────────────────────────────────────────
# 🏢 BASE DE DATOS LOCAL DE FABRICANTES (Prefijos MAC / 24 bits OUI)
# ─────────────────────────────────────────────────────────────────
MAC_VENDORS = {
    # Routers y Dispositivos de Operadoras
    "e0:41:36": "MitraStar (Movistar Router)",
    "a0:f3:c1": "MitraStar Technology",
    "70:9f:2d": "Askey Computer (Movistar HGU)",
    "00:03:c7": "Askey Computer Corp.",
    "00:90:4c": "ZTE Corporation",
    "fc:3f:db": "Huawei Technologies",
    "b0:b8:67": "Sagemcom",
    # Gigantes Tecnológicos
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
    # IoT / Domótica
    "11:95:0d": "Tuya Smart / Espressif",
    "24:0a:c4": "Espressif Systems (IoT)",
    "30:ae:a4": "Espressif Systems (IoT)",
    "0c:8b:95": "Hyundai Motor Co. (Manos Libres)",
    # Wearables y audio oculto
    "d4:f5:47": "Tile Inc. (Rastreador)",
    "ac:37:43": "HTC Corporation",
    "00:1b:dc": "Sony Ericsson",
    "20:cd:39": "Micro-Star Intl. (MSI)",
    "b4:e6:2d": "Liteon Technology",
    "00:1f:3a": "AzureWave (Cámaras IP)",
    "00:e0:36": "D-Link (Cámara IoT)",
}

# 🎯 CRITERIOS DE LISTA NEGRA
BLACKLIST_VENDORS = ["espressif", "tuya", "unknown", "genérico", "desconocido", "tile", "azurewave", "d-link"]

# Tamaño del buffer de historial RSSI por dispositivo (suavizado)
RSSI_HISTORY_SIZE = 8
# Mínimo tiempo en segundos entre refresco del display (throttle)
DISPLAY_REFRESH_INTERVAL = 0.5


def is_random_mac(mac: str) -> bool:
    """
    Detecta MAC aleatoria/privada evaluando el bit U/L (bit 1 del primer octeto).
    Una MAC local (aleatorizada) tiene ese bit a 1, dando valores pares del segundo nibble:
    x2, x6, xA, xE en el primer octeto.
    """
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


class HackRadarApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("🛰️ HackRadar Suite v1.7 - Módulo TSCM Completo")
        self.geometry("1360x780")

        self.is_scanning = False
        self.loop = None
        self.scan_thread = None

        # dict principal: mac → {name, rssi, vendor, is_threat, reason, first_seen, last_seen, rssi_history}
        self.detected_devices = {}
        self.tracking_mac = ""
        self._last_display_refresh = 0.0
        self._pending_refresh = False

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ─────────────────────────────
        # PANEL LATERAL
        # ─────────────────────────────
        self.sidebar_frame = ctk.CTkFrame(self, width=210, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(8, weight=1)

        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame, text="HACKRADAR", font=ctk.CTkFont(size=20, weight="bold")
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 4))

        self.version_label = ctk.CTkLabel(
            self.sidebar_frame, text="v1.7 — TSCM Suite", font=ctk.CTkFont(size=10), text_color="gray50"
        )
        self.version_label.grid(row=1, column=0, padx=20, pady=(0, 10))

        self.status_label = ctk.CTkLabel(
            self.sidebar_frame, text="Estado: Listo", text_color="cyan", font=ctk.CTkFont(size=13, weight="bold")
        )
        self.status_label.grid(row=2, column=0, padx=20, pady=6)

        self.btn_start = ctk.CTkButton(self.sidebar_frame, text="▶ Iniciar Escáner", command=self.start_scan)
        self.btn_start.grid(row=3, column=0, padx=20, pady=6)

        self.btn_stop = ctk.CTkButton(
            self.sidebar_frame, text="🛑 Detener", fg_color="coral", hover_color="crimson", command=self.stop_scan
        )
        self.btn_stop.grid(row=4, column=0, padx=20, pady=6)

        self.btn_report = ctk.CTkButton(
            self.sidebar_frame, text="💾 Guardar Log TSCM",
            fg_color="darkgreen", hover_color="green", command=self.generate_report
        )
        self.btn_report.grid(row=5, column=0, padx=20, pady=6)

        self.btn_clear = ctk.CTkButton(
            self.sidebar_frame, text="🗑 Limpiar Tabla",
            fg_color="gray25", hover_color="gray35", command=self.clear_devices
        )
        self.btn_clear.grid(row=6, column=0, padx=20, pady=6)

        # Estadísticas
        self.stats_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        self.stats_frame.grid(row=7, column=0, padx=10, pady=15, sticky="n")

        self.lbl_total = ctk.CTkLabel(self.stats_frame, text="Dispositivos: 0", font=ctk.CTkFont(size=12))
        self.lbl_total.grid(row=0, column=0, sticky="w", pady=2)

        self.lbl_alerts = ctk.CTkLabel(
            self.stats_frame, text="Alertas Críticas: 0", text_color="white", font=ctk.CTkFont(size=12, weight="bold")
        )
        self.lbl_alerts.grid(row=1, column=0, sticky="w", pady=2)

        self.lbl_random = ctk.CTkLabel(
            self.stats_frame, text="MACs Aleatorizadas: 0", text_color="gray60", font=ctk.CTkFont(size=11)
        )
        self.lbl_random.grid(row=2, column=0, sticky="w", pady=2)

        self.btn_exit = ctk.CTkButton(
            self.sidebar_frame, text="Salir", fg_color="gray20", hover_color="gray30", command=self.close_app
        )
        self.btn_exit.grid(row=9, column=0, padx=20, pady=20, sticky="s")

        # ─────────────────────────────
        # PANEL CENTRAL
        # ─────────────────────────────
        self.main_frame = ctk.CTkFrame(self, corner_radius=15)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        # Barra de título + filtro en la misma fila
        self.header_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(15, 0))
        self.header_frame.grid_columnconfigure(0, weight=1)

        self.main_title = ctk.CTkLabel(
            self.header_frame,
            text="🔎 Monitorización TSCM: Detección de Amenazas Ocultas",
            font=ctk.CTkFont(size=15, weight="bold")
        )
        self.main_title.grid(row=0, column=0, sticky="w")

        # Filtro de búsqueda rápida
        self.filter_var = ctk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.update_radar_display())
        self.entry_filter = ctk.CTkEntry(
            self.header_frame, textvariable=self.filter_var,
            placeholder_text="🔍 Filtrar MAC / Fabricante...", width=260,
            font=ctk.CTkFont(family="Courier", size=12)
        )
        self.entry_filter.grid(row=0, column=1, sticky="e")

        # Tabla radar principal
        self.textbox_radar = ctk.CTkTextbox(
            self.main_frame, font=ctk.CTkFont(family="Courier", size=12), wrap="none"
        )
        self.textbox_radar.grid(row=1, column=0, sticky="nsew", padx=20, pady=(10, 0))
        self.textbox_radar.insert("0.0", "Esperando inicio de escaneo táctico...\n")
        self.textbox_radar.configure(state="disabled")

        # ─────────────────────────────────────────────────────────
        # 📡 PANEL GONIÓMETRO DE PROXIMIDAD
        # ─────────────────────────────────────────────────────────
        self.tracker_frame = ctk.CTkFrame(self.main_frame, height=140, border_width=1, border_color="gray30")
        self.tracker_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(10, 20))
        self.tracker_frame.grid_columnconfigure(1, weight=1)

        self.lbl_track_title = ctk.CTkLabel(
            self.tracker_frame,
            text="📡 GONIÓMETRO DE PROXIMIDAD  —  Rastreo por RSSI en tiempo real",
            font=ctk.CTkFont(size=12, weight="bold")
        )
        self.lbl_track_title.grid(row=0, column=0, columnspan=4, padx=15, pady=(8, 2), sticky="w")

        self.lbl_mac_input = ctk.CTkLabel(self.tracker_frame, text="MAC Objetivo:")
        self.lbl_mac_input.grid(row=1, column=0, padx=(15, 5), pady=5, sticky="w")

        self.entry_mac = ctk.CTkEntry(
            self.tracker_frame, placeholder_text="AA:BB:CC:DD:EE:FF", width=210,
            font=ctk.CTkFont(family="Courier")
        )
        self.entry_mac.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        self.btn_track = ctk.CTkButton(
            self.tracker_frame, text="Fijar Objetivo", width=130,
            fg_color="purple", hover_color="indigo", command=self.toggle_tracking
        )
        self.btn_track.grid(row=1, column=2, padx=10, pady=5)

        # Indicador RSSI instantáneo + media
        self.lbl_rssi_instant = ctk.CTkLabel(
            self.tracker_frame, text="Inst: — dBm", font=ctk.CTkFont(size=11), text_color="gray60"
        )
        self.lbl_rssi_instant.grid(row=1, column=3, padx=(5, 15), pady=5, sticky="e")

        self.progress_bar = ctk.CTkProgressBar(self.tracker_frame, height=16)
        self.progress_bar.grid(row=2, column=0, columnspan=3, padx=(15, 10), pady=8, sticky="ew")
        self.progress_bar.set(0)

        self.lbl_proximity = ctk.CTkLabel(
            self.tracker_frame, text="Rastreador: En espera",
            font=ctk.CTkFont(size=12, weight="bold"), text_color="gray"
        )
        self.lbl_proximity.grid(row=2, column=3, padx=(5, 15), pady=8, sticky="e")

    # ─────────────────────────────────────────────────────────────
    # LÓGICA DE FABRICANTE (con detección correcta de MAC aleatoria)
    # ─────────────────────────────────────────────────────────────
    def get_vendor_by_mac(self, mac: str) -> str:
        if is_random_mac(mac):
            return "MAC Aleatorizada (Dispositivo Privado)"
        mac_prefix = mac.lower()[:8]
        return MAC_VENDORS.get(mac_prefix, "Fabricante Desconocido")

    # ─────────────────────────────────────────────────────────────
    # CALLBACK BLE (llamado desde hilo asíncrono)
    # ─────────────────────────────────────────────────────────────
    def device_detected(self, device, advertisement_data):
        if not self.is_scanning:
            return

        mac = device.address
        nombre = device.name if device.name else "Dispositivo Oculto"
        rssi = advertisement_data.rssi
        fabricante = self.get_vendor_by_mac(mac)
        now_str = datetime.now().strftime("%H:%M:%S")

        # ── Actualizar o crear entrada ──
        if mac not in self.detected_devices:
            self.detected_devices[mac] = {
                "name": nombre,
                "rssi": rssi,
                "vendor": fabricante,
                "is_threat": False,
                "reason": "OK",
                "first_seen": now_str,
                "last_seen": now_str,
                "rssi_history": collections.deque(maxlen=RSSI_HISTORY_SIZE),
            }
        entry = self.detected_devices[mac]
        entry["rssi"] = rssi
        entry["last_seen"] = now_str
        entry["rssi_history"].append(rssi)
        # Si el nombre llega vacío la primera vez, actualizamos cuando aparezca
        if nombre != "Dispositivo Oculto":
            entry["name"] = nombre

        # ── Reglas de sospecha (sobre la media suavizada) ──
        rssi_avg = sum(entry["rssi_history"]) / len(entry["rssi_history"])
        vendor_lower = fabricante.lower()

        es_sospechoso = False
        razon = "OK"

        if any(x in vendor_lower for x in BLACKLIST_VENDORS) and rssi_avg >= -70:
            es_sospechoso = True
            razon = "⚠️ ALERT: [SOSPECHA IOT/RASTREADOR]"
        elif rssi_avg >= -65:
            es_sospechoso = True
            razon = "⚠️ ALERT: [PROXIMIDAD CRÍTICA]"
        elif "aleatorizada" in vendor_lower and rssi_avg >= -68:
            es_sospechoso = True
            razon = "⚠️ ALERT: [RÁFAGAS MÓVIL ANÓNIMO]"

        entry["is_threat"] = es_sospechoso
        entry["reason"] = razon

        # ── Goniómetro: actualizar si es el objetivo fijado ──
        if self.tracking_mac and mac.lower() == self.tracking_mac.lower():
            rssi_smooth = rssi_avg
            self.after(0, lambda r=rssi_smooth, ri=rssi: self.update_tracker_module(r, ri))

        # ── Throttle de refresco visual ──
        now_ts = time.monotonic()
        if now_ts - self._last_display_refresh >= DISPLAY_REFRESH_INTERVAL:
            self._last_display_refresh = now_ts
            self.after(0, self.update_radar_display)
        elif not self._pending_refresh:
            self._pending_refresh = True
            self.after(int(DISPLAY_REFRESH_INTERVAL * 1000), self._deferred_refresh)

    def _deferred_refresh(self):
        self._pending_refresh = False
        self._last_display_refresh = time.monotonic()
        self.update_radar_display()

    # ─────────────────────────────────────────────────────────────
    # GONIÓMETRO
    # ─────────────────────────────────────────────────────────────
    def toggle_tracking(self):
        if not self.tracking_mac:
            target = self.entry_mac.get().strip()
            if len(target) >= 12:
                self.tracking_mac = target
                self.btn_track.configure(text="Liberar Objetivo", fg_color="crimson", hover_color="darkred")
                self.entry_mac.configure(state="disabled")
                self.lbl_proximity.configure(text="Buscando señal...", text_color="yellow")
            else:
                self.lbl_proximity.configure(text="❌ MAC Inválida (mín. 12 chars)", text_color="red")
        else:
            self.tracking_mac = ""
            self.btn_track.configure(text="Fijar Objetivo", fg_color="purple", hover_color="indigo")
            self.entry_mac.configure(state="normal")
            self.progress_bar.set(0)
            self.lbl_rssi_instant.configure(text="Inst: — dBm", text_color="gray60")
            self.lbl_proximity.configure(text="Rastreador: En espera", text_color="gray")

    def update_tracker_module(self, rssi_avg: float, rssi_inst: int):
        clamped = max(-90, min(-40, rssi_avg))
        pct = (clamped - (-90)) / 50.0
        self.progress_bar.set(pct)
        self.lbl_rssi_instant.configure(text=f"Inst: {rssi_inst} dBm", text_color="white")

        if rssi_avg >= -55:
            self.lbl_proximity.configure(text=f"🔥 ¡MÁXIMA PROXIMIDAD! ({rssi_avg:.1f} dBm) < 0.5 m", text_color="red")
            self.progress_bar.configure(progress_color="red")
        elif rssi_avg >= -65:
            self.lbl_proximity.configure(text=f"🟠 CALIENTE — SECTOR CERCANO ({rssi_avg:.1f} dBm)", text_color="orange")
            self.progress_bar.configure(progress_color="orange")
        elif rssi_avg >= -75:
            self.lbl_proximity.configure(text=f"🟡 TEMPLADO — EN RANGO ({rssi_avg:.1f} dBm)", text_color="yellow")
            self.progress_bar.configure(progress_color="yellow")
        else:
            self.lbl_proximity.configure(text=f"❄️ FRÍO — SEÑAL LEJANA ({rssi_avg:.1f} dBm)", text_color="cyan")
            self.progress_bar.configure(progress_color="cyan")

    # ─────────────────────────────────────────────────────────────
    # ACTUALIZACIÓN DEL DISPLAY PRINCIPAL
    # ─────────────────────────────────────────────────────────────
    def update_radar_display(self):
        self.textbox_radar.configure(state="normal")
        self.textbox_radar.delete("1.0", "end")

        filtro = self.filter_var.get().lower().strip()

        HDR = (
            f"{'Nº':<4} | {'DIRECCIÓN MAC':<21} | {'FABRICANTE PROBABLE':<36} | "
            f"{'ID DISPOSITIVO':<22} | {'RSSI (avg)':<11} | {'VISTO':<10} | {'ALERTA TSCM'}\n"
        )
        self.textbox_radar.insert("end", HDR)
        self.textbox_radar.insert("end", "─" * 140 + "\n")

        sorted_devs = sorted(self.detected_devices.items(), key=lambda x: x[1]["rssi"], reverse=True)

        contador_alertas = 0
        contador_random = 0

        for idx, (mac, info) in enumerate(sorted_devs, start=1):
            # Aplicar filtro de búsqueda
            if filtro and filtro not in mac.lower() and filtro not in info["vendor"].lower() and filtro not in info["name"].lower():
                continue

            if info["is_threat"]:
                contador_alertas += 1
            if "aleatorizada" in info["vendor"].lower():
                contador_random += 1

            rssi_avg = (
                sum(info["rssi_history"]) / len(info["rssi_history"])
                if info["rssi_history"] else info["rssi"]
            )

            prefix = "🎯 " if self.tracking_mac and mac.lower() == self.tracking_mac.lower() else "   "
            mac_display = f"{prefix}{mac}"

            linea = (
                f"{idx:<4} | {mac_display:<21} | {info['vendor']:<36} | "
                f"{info['name']:<22} | {rssi_avg:>6.1f} dBm | {info['last_seen']:<10} | {info['reason']}\n"
            )
            self.textbox_radar.insert("end", linea)

        # Estadísticas panel lateral
        self.lbl_total.configure(text=f"Dispositivos: {len(self.detected_devices)}")
        self.lbl_random.configure(text=f"MACs Aleatorizadas: {contador_random}")

        if contador_alertas > 0:
            self.lbl_alerts.configure(text=f"🚨 ALERTAS: {contador_alertas}", text_color="red")
            self.status_label.configure(text="⚠️ AMENAZA EN AIRE", text_color="red")
        else:
            self.lbl_alerts.configure(text="Alertas Críticas: 0", text_color="white")
            if self.is_scanning:
                self.status_label.configure(text="Estado: Escaneando...", text_color="lime")

        self.textbox_radar.configure(state="disabled")

    # ─────────────────────────────────────────────────────────────
    # INFORME FORENSE MEJORADO
    # ─────────────────────────────────────────────────────────────
    def generate_report(self):
        if not self.detected_devices:
            return

        filename = f"TSCM_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("=" * 70 + "\n")
                f.write("       INFORME FORENSE DE INSPECCIÓN ELECTRÓNICA TSCM\n")
                f.write("                  HackRadar Suite v1.7\n")
                f.write("=" * 70 + "\n")
                f.write(f"Fecha/Hora del Reporte   : {datetime.now().strftime('%d/%m/%Y — %H:%M:%S')}\n")
                f.write(f"Total de Dispositivos    : {len(self.detected_devices)}\n")
                amenazas = sum(1 for x in self.detected_devices.values() if x["is_threat"])
                aleatorias = sum(1 for x in self.detected_devices.values() if "aleatorizada" in x["vendor"].lower())
                f.write(f"Alertas Alta Sospecha    : {amenazas}\n")
                f.write(f"MACs Aleatorizadas       : {aleatorias}\n")
                f.write("-" * 70 + "\n\n")

                f.write(
                    f"{'MAC':<20} | {'FABRICANTE':<34} | {'DISPOSITIVO':<22} | "
                    f"{'RSSI Avg':>8} | {'1ª VEZ':>8} | {'ÚLT. VEZ':>8} | ESTADO\n"
                )
                f.write("-" * 120 + "\n")

                for mac, info in sorted(self.detected_devices.items(), key=lambda x: x[1]["rssi"], reverse=True):
                    rssi_avg = (
                        sum(info["rssi_history"]) / len(info["rssi_history"])
                        if info["rssi_history"] else info["rssi"]
                    )
                    f.write(
                        f"{mac:<20} | {info['vendor']:<34} | {info['name']:<22} | "
                        f"{rssi_avg:>6.1f} dBm | {info['first_seen']:>8} | {info['last_seen']:>8} | {info['reason']}\n"
                    )

                f.write("\n" + "=" * 70 + "\n")
                f.write("Fin del informe. Generado con HackRadar Suite v1.7.\n")

            self.textbox_radar.configure(state="normal")
            self.textbox_radar.insert("end", f"\n💾 [OK] Informe forense guardado: '{filename}'\n")
            self.textbox_radar.configure(state="disabled")
        except Exception as e:
            self.textbox_radar.configure(state="normal")
            self.textbox_radar.insert("end", f"\n❌ Error al guardar el reporte: {str(e)}\n")
            self.textbox_radar.configure(state="disabled")

    # ─────────────────────────────────────────────────────────────
    # LIMPIAR TABLA
    # ─────────────────────────────────────────────────────────────
    def clear_devices(self):
        self.detected_devices.clear()
        self.textbox_radar.configure(state="normal")
        self.textbox_radar.delete("1.0", "end")
        self.textbox_radar.insert("end", "[+] Tabla limpiada. Esperando nuevas detecciones...\n")
        self.textbox_radar.configure(state="disabled")
        self.lbl_total.configure(text="Dispositivos: 0")
        self.lbl_alerts.configure(text="Alertas Críticas: 0", text_color="white")
        self.lbl_random.configure(text="MACs Aleatorizadas: 0")

    # ─────────────────────────────────────────────────────────────
    # MOTOR ASÍNCRONO BLE
    # ─────────────────────────────────────────────────────────────
    def run_async_loop(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        scanner = BleakScanner(detection_callback=self.device_detected)
        self.loop.run_until_complete(scanner.start())
        self.loop.run_forever()

    def start_scan(self):
        if self.is_scanning:
            return
        self.is_scanning = True
        self._last_display_refresh = 0.0
        self.status_label.configure(text="Estado: Escaneando...", text_color="lime")

        self.textbox_radar.configure(state="normal")
        self.textbox_radar.delete("1.0", "end")
        self.textbox_radar.insert("end", "[+] Inicializando HackRadar v1.7 — Aplicando reglas TSCM y Lista Negra...\n")
        self.textbox_radar.configure(state="disabled")

        self.scan_thread = threading.Thread(target=self.run_async_loop, daemon=True)
        self.scan_thread.start()

    def stop_scan(self):
        if not self.is_scanning:
            return
        self.is_scanning = False
        self.status_label.configure(text="Estado: Detenido", text_color="coral")
        if self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)
        amenazas = sum(1 for x in self.detected_devices.values() if x["is_threat"])
        self.textbox_radar.configure(state="normal")
        self.textbox_radar.insert(
            "end", f"\n[-] Análisis pausado. Amenazas detectadas en sesión: {amenazas}\n"
        )
        self.textbox_radar.configure(state="disabled")

    def close_app(self):
        self.stop_scan()
        self.destroy()


if __name__ == "__main__":
    app = HackRadarApp()
    app.mainloop()