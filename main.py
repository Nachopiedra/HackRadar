import customtkinter as ctk
import asyncio
import threading
from bleak import BleakScanner
from datetime import datetime
import os

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# 🏢 BASE DE DATOS LOCAL DE FABRICANTES
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
    "0c:8b:95": "Hyundai Motor Co. (Manos Libres)",
}

# 🎯 CRITERIOS DE LISTA NEGRA
BLACKList_VENDORS = ["espressif", "tuya", "unknown", "genérico", "desconocido"]

class HackRadarApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("🛰️ HackRadar Suite v1.6 - Módulo TSCM Completo")
        self.geometry("1280x720") # Altura expandida para el módulo rastreador

        self.is_scanning = False
        self.loop = None
        self.scan_thread = None
        
        self.detected_devices = {}
        self.tracking_mac = ""

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ---------------------------------------------------------
        # PANEL LATERAL (CONTROLES)
        # ---------------------------------------------------------
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(6, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="HACKRADAR", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="Estado: Listo", text_color="cyan", font=ctk.CTkFont(size=13, weight="bold"))
        self.status_label.grid(row=1, column=0, padx=20, pady=10)

        self.btn_start = ctk.CTkButton(self.sidebar_frame, text="▶ Iniciar Escáner", command=self.start_scan)
        self.btn_start.grid(row=2, column=0, padx=20, pady=10)

        self.btn_stop = ctk.CTkButton(self.sidebar_frame, text="🛑 Detener", fg_color="coral", hover_color="crimson", command=self.stop_scan)
        self.btn_stop.grid(row=3, column=0, padx=20, pady=10)

        # 💾 BOTÓN REPORTE TSCM
        self.btn_report = ctk.CTkButton(self.sidebar_frame, text="💾 Guardar Log TSCM", fg_color="darkgreen", hover_color="green", command=self.generate_report)
        self.btn_report.grid(row=4, column=0, padx=20, pady=10)

        self.stats_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        self.stats_frame.grid(row=5, column=0, padx=10, pady=15, sticky="n")
        
        self.lbl_total = ctk.CTkLabel(self.stats_frame, text="Dispositivos: 0", font=ctk.CTkFont(size=12))
        self.lbl_total.grid(row=0, column=0, sticky="w", pady=2)
        
        self.lbl_alerts = ctk.CTkLabel(self.stats_frame, text="Alertas Críticas: 0", text_color="white", font=ctk.CTkFont(size=12, weight="bold"))
        self.lbl_alerts.grid(row=1, column=0, sticky="w", pady=2)

        self.btn_exit = ctk.CTkButton(self.sidebar_frame, text="Salir", fg_color="gray20", hover_color="gray30", command=self.close_app)
        self.btn_exit.grid(row=7, column=0, padx=20, pady=20)

        # ---------------------------------------------------------
        # PANEL CENTRAL (VISUALIZADOR Y RASTREADOR)
        # ---------------------------------------------------------
        self.main_frame = ctk.CTkFrame(self, corner_radius=15)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        self.main_title = ctk.CTkLabel(self.main_frame, text="🔎 Monitorización en Aula: Detección de Amenazas Ocultas (TSCM)", font=ctk.CTkFont(size=15, weight="bold"))
        self.main_title.grid(row=0, column=0, sticky="w", padx=20, pady=15)

        self.textbox_radar = ctk.CTkTextbox(self.main_frame, font=ctk.CTkFont(family="Courier", size=13), wrap="none")
        self.textbox_radar.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 15))
        
        self.textbox_radar.insert("0.0", "Esperando inicio de escaneo táctico...\n")
        self.textbox_radar.configure(state="disabled")

        # ---------------------------------------------------------
        # 📡 SUBPANEL DE RASTREO ACTIVO DE OBJETIVO (GONIO)
        # ---------------------------------------------------------
        self.tracker_frame = ctk.CTkFrame(self.main_frame, height=130, border_width=1, border_color="gray30")
        self.tracker_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 20))
        self.tracker_frame.grid_columnconfigure(1, weight=1)

        self.lbl_track_title = ctk.CTkLabel(self.tracker_frame, text="📡 LOCALIZADOR DE DIRECCIÓN POR PROXIMIDAD", font=ctk.CTkFont(size=12, weight="bold"))
        self.lbl_track_title.grid(row=0, column=0, columnspan=3, padx=15, pady=5, sticky="w")

        self.lbl_mac_input = ctk.CTkLabel(self.tracker_frame, text="MAC Objetivo:")
        self.lbl_mac_input.grid(row=1, column=0, padx=(15, 5), pady=5, sticky="w")

        self.entry_mac = ctk.CTkEntry(self.tracker_frame, placeholder_text="AA:BB:CC:DD:EE:FF", width=200, font=ctk.CTkFont(family="Courier"))
        self.entry_mac.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        self.btn_track = ctk.CTkButton(self.tracker_frame, text="Fijar Objetivo", width=120, fg_color="purple", hover_color="indigo", command=self.toggle_tracking)
        self.btn_track.grid(row=1, column=2, padx=15, pady=5, sticky="e")

        self.progress_bar = ctk.CTkProgressBar(self.tracker_frame, height=15)
        self.progress_bar.grid(row=2, column=0, columnspan=2, padx=(15, 15), pady=10, sticky="ew")
        self.progress_bar.set(0)

        self.lbl_proximity = ctk.CTkLabel(self.tracker_frame, text="Rastreador: En espera", font=ctk.CTkFont(size=12, weight="bold"), text_color="gray")
        self.lbl_proximity.grid(row=2, column=2, padx=15, pady=10, sticky="w")

    def get_vendor_by_mac(self, mac):
        mac_prefix = mac.lower()[:8]
        if len(mac_prefix) > 1 and mac_prefix[1] in ['2', '6', 'a', 'e']:
            return "MAC Aleatoria (Móvil Privado)"
        return MAC_VENDORS.get(mac_prefix, "Fabricante Genérico")

    def device_detected(self, device, advertisement_data):
        if not self.is_scanning:
            return
            
        mac = device.address
        nombre = device.name if device.name else "Dispositivo Oculto"
        rssi = advertisement_data.rssi
        fabricante = self.get_vendor_by_mac(mac)
        
        es_sospechoso = False
        razon = "OK"
        
        vendor_lower = fabricante.lower()
        if any(x in vendor_lower for x in BLACKList_VENDORS) and rssi >= -70:
            es_sospechoso = True
            razon = "🔥 ALERT: [SOSPECHA IOT]"
        elif rssi >= -65:
            es_sospechoso = True
            razon = "🔥 ALERT: [PROXIMIDAD CRÍTICA]"
        elif "aleatoria" in vendor_lower and rssi >= -68:
            es_sospechoso = True
            razon = "🔥 ALERT: [RÁFAGAS MÓVIL]"

        self.detected_devices[mac] = {
            "name": nombre, 
            "rssi": rssi, 
            "vendor": fabricante, 
            "is_threat": es_sospechoso,
            "reason": razon,
            "last_seen": datetime.now().strftime("%H:%M:%S")
        }
        
        if self.tracking_mac and mac.lower() == self.tracking_mac.lower():
            self.update_tracker_module(rssi)

        self.update_radar_display()

    def toggle_tracking(self):
        if not self.tracking_mac:
            target = self.entry_mac.get().strip()
            if len(target) >= 12:
                self.tracking_mac = target
                self.btn_track.configure(text="Liberar", fg_color="crimson", hover_color="darkred")
                self.entry_mac.configure(state="disabled")
                self.lbl_proximity.configure(text="Buscando señal...", text_color="yellow")
            else:
                self.lbl_proximity.configure(text="❌ MAC Inválida", text_color="red")
        else:
            self.tracking_mac = ""
            self.btn_track.configure(text="Fijar Objetivo", fg_color="purple", hover_color="indigo")
            self.entry_mac.configure(state="normal")
            self.progress_bar.set(0)
            self.lbl_proximity.configure(text="Rastreador: En espera", text_color="gray")

    def update_tracker_module(self, rssi):
        clamped_rssi = max(-90, min(-40, rssi))
        percentage = (clamped_rssi - (-90)) / (-40 - (-90))
        self.progress_bar.set(percentage)

        if rssi >= -60:
            self.lbl_proximity.configure(text=f"🔥 ¡PROXIMIDAD MÁXIMA! ({rssi} dBm) < 1 metro", text_color="red")
            self.progress_bar.configure(progress_color="red")
        elif rssi >= -70:
            self.lbl_proximity.configure(text=f"⚠️ CALIENTE - SECTOR CERCANO ({rssi} dBm)", text_color="orange")
            self.progress_bar.configure(progress_color="orange")
        elif rssi >= -80:
            self.lbl_proximity.configure(text=f"⏳ TEMPLADO - EN RANGO ({rssi} dBm)", text_color="yellow")
            self.progress_bar.configure(progress_color="yellow")
        else:
            self.lbl_proximity.configure(text=f"❄️ FRÍO - SEÑAL LEJANA ({rssi} dBm)", text_color="cyan")
            self.progress_bar.configure(progress_color="cyan")

    def update_radar_display(self):
        self.textbox_radar.configure(state="normal")
        self.textbox_radar.delete("1.0", "end")
        
        self.textbox_radar.insert("end", f"{'Nº':<5} | {'DIRECCIÓN MAC':<20} | {'FABRICANTE PROBABLE':<35} | {'ID DISPOSITIVO':<23} | {'POTENCIA':<10} | {'ALERTA TSCM'}\n")
        self.textbox_radar.insert("end", "-" * 125 + "\n")
        
        sorted_devices = sorted(self.detected_devices.items(), key=lambda x: x[1]['rssi'], reverse=True)
        
        contador_alertas = 0
        for indice, (mac, info) in enumerate(sorted_devices, start=1):
            if info['is_threat']:
                contador_alertas += 1
            
            prefix = "🎯 " if self.tracking_mac and mac.lower() == self.tracking_mac.lower() else ""
            mac_display = f"{prefix}{mac}"
                
            linea = f"{indice:<5} | {mac_display:<20} | {info['vendor']:<35} | {info['name']:<23} | {info['rssi']:>4} dBm | {info['reason']}\n"
            self.textbox_radar.insert("end", linea)
            
        self.lbl_total.configure(text=f"Dispositivos: {len(self.detected_devices)}")
        if contador_alertas > 0:
            self.lbl_alerts.configure(text=f"🚨 ALERTAS: {contador_alertas}", text_color="red")
            self.status_label.configure(text="⚠️ AMENAZA EN AIRE", text_color="red")
        else:
            self.lbl_alerts.configure(text="Alertas Críticas: 0", text_color="white")
            self.status_label.configure(text="Estado: Escaneando...", text_color="lime")
            
        self.textbox_radar.configure(state="disabled")

    def generate_report(self):
        if not self.detected_devices:
            return

        filename = f"TSCM_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("==================================================================\n")
                f.write("        INFORME FORENSE DE INSPECCIÓN ELECTRÓNICA DE AULA (TSCM)\n")
                f.write("==================================================================\n")
                f.write(f"Fecha/Hora del Reporte : {datetime.now().strftime('%d/%m/%Y - %H:%M:%S')}\n")
                f.write(f"Dispositivos en Canal  : {len(self.detected_devices)}\n")
                amenazas = sum(1 for x in self.detected_devices.values() if x['is_threat'])
                f.write(f"Alertas de Alta Sospecha: {amenazas}\n")
                f.write("------------------------------------------------------------------\n\n")
                
                f.write(f"{'DIRECCIÓN MAC':<20} | {'FABRICANTE':<35} | {'ID DISPOSITIVO':<23} | {'RSSI':<8} | {'ESTADO TSCM'}\n")
                f.write("-" * 105 + "\n")
                
                sorted_devices = sorted(self.detected_devices.items(), key=lambda x: x[1]['rssi'], reverse=True)
                for mac, info in sorted_devices:
                    f.write(f"{mac:<20} | {info['vendor']:<35} | {info['name']:<23} | {info['rssi']:>4} dBm | {info['reason']}\n")
                    
                f.write("\n==================================================================\n")
                f.write("Fin del informe. Registro obtenido mediante HackRadar Suite v1.6.\n")
            
            self.textbox_radar.configure(state="normal")
            self.textbox_radar.insert("end", f"\n💾 [SUCCES] Registro Forense guardado con éxito como: '{filename}'\n")
            self.textbox_radar.configure(state="disabled")
        except Exception as e:
            self.textbox_radar.configure(state="normal")
            self.textbox_radar.insert("end", f"\n❌ Error al guardar el reporte: {str(e)}\n")
            self.textbox_radar.configure(state="disabled")

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
        self.status_label.configure(text="Estado: Escaneando...", text_color="lime")
        self.detected_devices.clear()
        
        self.textbox_radar.configure(state="normal")
        self.textbox_radar.delete("1.0", "end")
        self.textbox_radar.insert("end", "[+] Inicializando contramedidas y aplicando reglas de Lista Negra TSCM...\n")
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
        self.textbox_radar.configure(state="normal")
        
        amenazas = sum(1 for x in self.detected_devices.values() if x['is_threat'])
        self.textbox_radar.insert("end", f"\n[-] Análisis pausado. Objetos congelados. Amenazas críticas detectadas: {amenazas}\n")
        self.textbox_radar.configure(state="disabled")

    def close_app(self):
        self.stop_scan()
        self.destroy()

if __name__ == "__main__":
    app = HackRadarApp()
    app.mainloop()