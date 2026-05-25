import customtkinter as ctk
import asyncio
import threading
from bleak import BleakScanner

# Configuración del estilo general
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class HackRadarApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Configurar ventana principal
        self.title("🛰️ HackRadar Suite v1.0")
        self.geometry("1000x600")

        # Variables de control para el escáner
        self.is_scanning = False
        self.loop = None
        self.scan_thread = None

        # Sistema de rejilla (Grid) 1x2
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

        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="Estado: Listo", text_color="cyan")
        self.status_label.grid(row=1, column=0, padx=20, pady=10)

        self.btn_start = ctk.CTkButton(self.sidebar_frame, text="▶ Iniciar Escáner", command=self.start_scan)
        self.btn_start.grid(row=2, column=0, padx=20, pady=10)

        self.btn_stop = ctk.CTkButton(self.sidebar_frame, text="🛑 Detener", fg_color="coral", hover_color="crimson", command=self.stop_scan)
        self.btn_stop.grid(row=3, column=0, padx=20, pady=10)

        self.btn_exit = ctk.CTkButton(self.sidebar_frame, text="Salir", fg_color="gray20", hover_color="gray30", command=self.close_app)
        self.btn_exit.grid(row=5, column=0, padx=20, py=20)

        # ---------------------------------------------------------
        # PANEL CENTRAL (VISUALIZADOR DE DATOS)
        # ---------------------------------------------------------
        self.main_frame = ctk.CTkFrame(self, corner_radius=15)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, py=20)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        self.main_title = ctk.CTkLabel(self.main_frame, text="🔎 Dispositivos en el Radar (Solo Imprescindible)", font=ctk.CTkFont(size=16, weight="bold"))
        self.main_title.grid(row=0, column=0, sticky="w", padx=20, pady=15)

        self.textbox_radar = ctk.CTkTextbox(self.main_frame, font=ctk.CTkFont(family="Courier", size=13))
        self.textbox_radar.grid(row=1, column=0, sticky="nsew", px=20, pady=(0, 20))
        
        self.textbox_radar.insert("0.0", "Esperando inicio de escaneo táctico...\n")
        self.textbox_radar.configure(state="disabled")

    # callback que se ejecuta CADA VEZ que la radio caza un paquete en el aire
    def device_detected(self, device, advertisement_data):
        if not self.is_scanning:
            return
            
        nombre = device.name if device.name else "Dispositivo Oculto"
        mac = device.address
        rssi = advertisement_data.rssi
        
        # Formatear la línea limpia con los datos sagrados
        linea_datos = f"📍 MAC: {mac} | 🏷️ Aparato: {nombre:<25} | 📶 Potencia: {rssi} dBm\n"
        
        # Insertar en la interfaz gráfica de forma segura
        self.textbox_radar.configure(state="normal")
        self.textbox_radar.insert("end", linea_datos)
        self.textbox_radar.see("end") # Auto-scroll hacia abajo
        self.textbox_radar.configure(state="disabled")

    # Bucle asíncrono que corre en el hilo secundario
    def run_async_loop(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        # Configuramos el scanner para que llame a nuestra función cada vez que detecte algo
        scanner = BleakScanner(detection_callback=self.device_detected)
        
        self.loop.run_until_complete(scanner.start())
        self.loop.run_forever()

    def start_scan(self):
        if self.is_scanning:
            return
            
        self.is_scanning = True
        self.status_label.configure(text="Estado: Escaneando...", text_color="lime")
        
        self.textbox_radar.configure(state="normal")
        self.textbox_radar.delete("1.0", "end") # Limpiar pantalla anterior
        self.textbox_radar.insert("end", "[+] Abriendo puerto de radio y buscando ráfagas...\n")
        self.textbox_radar.configure(state="disabled")

        # Lanzar el motor de radio en un hilo de fondo para no congelar las ventanas
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
        self.textbox_radar.insert("end", "[-] Captura pausada.\n")
        self.textbox_radar.configure(state="disabled")

    def close_app(self):
        self.stop_scan()
        self.destroy()

if __name__ == "__main__":
    app = HackRadarApp()
    app.mainloop()