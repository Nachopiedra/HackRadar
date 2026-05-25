import customtkinter as ctk
import asyncio
import threading
from bleak import BleakScanner

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

# 🎯 CRITERIOS DE LISTA NEGRA (Palabras clave de fabricantes sospechosos de espionaje/IoT)
BLACKList_VENDORS = ["espressif", "tuya", "unknown", "genérico", "desconocido"]

class HackRadarApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("🛰️ HackRadar Suite v1.4 - Analizador TSCM / Lista Negra")
        self.geometry("1200x630") 

        self.is_scanning = False
        self.loop = None
        self.scan_thread = None
        
        self.detected_devices = {}

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ---------------------------------------------------------
        # PANEL LATERAL (CONTROLES)
        # ---------------------------------------------------------
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="HACKRADAR", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="Estado: Listo", text_color="cyan", font=ctk.CTkFont(size=13, weight="bold"))
        self.status_label.grid(row=1, column=0, padx=20, pady=10)

        self.btn_start = ctk.CTkButton(self.sidebar_frame, text="▶ Iniciar Escáner", command=self.start_scan)
        self.btn_start.grid(row=2, column=0, padx=20, pady=10)

        self.btn_stop = ctk.CTkButton(self.sidebar_frame, text="🛑 Detener", fg_color="coral", hover_color="crimson", command=self.stop_scan)
        self.btn_stop.grid(row=3, column=0, padx=20, pady=10)

        # Panel de estadísticas tácticas rápido
        self.stats_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        self.stats_frame.grid(row=4, column=0, padx=10, pady=20, sticky="n")
        
        self.lbl_total = ctk.CTkLabel(self.stats_frame, text="Dispositivos: 0", font=ctk.CTkFont(size=12))
        self.lbl_total.grid(row=0, column=0, sticky="w", pady=2)
        
        self.lbl_alerts = ctk.CTkLabel(self.stats_frame, text="Alertas Críticas: 0", text_color="white", font=ctk.CTkFont(size=12, weight="bold"))
        self.lbl_alerts.grid(row=1, column=0, sticky="w", pady=2)

        self.btn_exit = ctk.CTkButton(self.sidebar_frame, text="Salir", fg_color="gray20", hover_color="gray30", command=self.close_app)
        self.btn_exit.grid(row=5, column=0, padx=20, pady=20)

        # ---------------------------------------------------------
        # PANEL CENTRAL (VISUALIZADOR DE DATOS)
        # ---------------------------------------------------------
        self.main_frame = ctk.CTkFrame(self, corner_radius=15)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        self.main_title = ctk.CTkLabel(self.main_frame, text="🔎 Monitorización en Aula: Detección de Amenazas Ocultas (TSCM)", font=ctk.CTkFont(size=15, weight="bold"))
        self.main_title.grid(row=0, column=0, sticky="w", padx=20, pady=15)

        self.textbox_radar = ctk.CTkTextbox(self.main_frame, font=ctk.CTkFont(family="Courier", size=13))
        self.textbox_radar.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        
        self.textbox_radar.insert("0.0", "Esperando inicio de escaneo táctico...\n")
        self.textbox_radar.configure(state="disabled")

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
        
        # ⚠️ MOTOR DE EVALUACIÓN DE LISTA NEGRA / SOSPECHA
        # Criterio 1: Fabricante sospechoso de IoT/Microcámaras o genérico muy próximo.
        # Criterio 2: Señal críticamente alta (>-65 dBm) que denota que está dentro de la sala del examen.
        es_sospechoso = False
        razon = ""
        
        vendor_lower = fabricante.lower()
        if any(x in vendor_lower for x in BLACKList_VENDORS) and rssi >= -70:
            es_sospechoso = True
            razon = "[PROPÓSITO IOT/ALTA SOSPECHA]"
        elif rssi >= -65: # Umbral físico de proximidad extrema en aula
            es_sospechoso = True
            razon = "[PROXIMIDAD CRÍTICA EN AULA]"
        elif "aleatoria" in vendor_lower and rssi >= -68:
            es_sospechoso = True
            razon = "[MÓVIL EMITIENDO RÁFAGAS]"

        self.detected_devices[mac] = {
            "name": nombre, 
            "rssi": rssi, 
            "vendor": fabricante, 
            "is_threat": es_sospechoso,
            "reason": razon
        }
        self.update_radar_display()

    def update_radar_display(self):
        self.textbox_radar.configure(state="normal")
        self.textbox_radar.delete("1.0", "end")
        
        self.textbox_radar.insert("end", f"{'Nº':<4} | {'DIRECCIÓN MAC':<20} | {'FABRICANTE PROBABLE':<30} | {'ID DISPOSITIVO':<20} | {'POTENCIA':<10} | {'ALERTA TSCM':<25}\n")
        self.textbox_radar.insert("end", "-" * 115 + "\n")
        
        sorted_devices = sorted(self.detected_devices.items(), key=lambda x: x[1]['rssi'], reverse=True)
        
        contador_alertas = 0
        
        for indice, (mac, info) in enumerate(sorted_devices, start=1):
            if info['is_threat']:
                contador_alertas += 1
                # Formato visual de alerta roja de peligro inminente en la tabla
                linea = f"{indice:<4} | {mac:<20} | {info['vendor']:<30} | {info['name']:<20} | {info['rssi']:>4} dBm | 🔥 ALERT: {info['reason']}\n"
            else:
                linea = f"{indice:<4} | {mac:<20} | {info['vendor']:<30} | {info['name']:<20} | {info['rssi']:>4} dBm | OK\n"
                
            self.textbox_radar.insert("end", linea)
            
        # Actualizar los paneles informativos de la izquierda en tiempo real
        self.lbl_total.configure(text=f"Dispositivos: {len(self.detected_devices)}")
        if contador_alertas > 0:
            self.lbl_alerts.configure(text=f"🚨 ALERTAS: {contador_alertas}", text_color="red")
            self.status_label.configure(text="⚠️ AMENAZA EN AIRE", text_color="red")
        else:
            self.lbl_alerts.configure(text="Alertas Críticas: 0", text_color="white")
            self.status_label.configure(text="Estado: Escaneando...", text_color="lime")
            
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
        self.textbox_radar.insert("end", "[+] Inicializando contramedidas y aplicando reglas de Lista Negra...\n")
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