import customtkinter as ctk

# Configuración del estilo general (Modo Oscuro y tema Azul Táctico)
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class HackRadarApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Configurar ventana principal
        self.title("🛰️ HackRadar Suite v1.0")
        self.geometry("1000x600")

        # Configurar el sistema de rejilla (Grid) 1x2 (Panel lateral y Panel principal)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ---------------------------------------------------------
        # PANEL LATERAL (CONTROLES)
        # ---------------------------------------------------------
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1) # Espaciador para empujar el botón de salida abajo

        # Título de la Suite
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="HACKRADAR", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # Subtítulo descriptivo
        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="Estado: Listo", text_color="cyan")
        self.status_label.grid(row=1, column=0, padx=20, pady=10)

        # Botón Iniciar Escáner
        self.btn_start = ctk.CTkButton(self.sidebar_frame, text="▶ Iniciar Escáner", command=self.start_scan)
        self.btn_start.grid(row=2, column=0, padx=20, pady=10)

        # Botón Detener Escáner
        self.btn_stop = ctk.CTkButton(self.sidebar_frame, text="🛑 Detener", fg_color="coral", hover_color="crimson", command=self.stop_scan)
        self.btn_stop.grid(row=3, column=0, padx=20, pady=10)

        # Botón Salir (Abajo del todo)
        self.btn_exit = ctk.CTkButton(self.sidebar_frame, text="Salir", fg_color="gray20", hover_color="gray30", command=self.destroy)
        self.btn_exit.grid(row=5, column=0, padx=20, pady=20)

        # ---------------------------------------------------------
        # PANEL CENTRAL (VISUALIZADOR DE DATOS)
        # ---------------------------------------------------------
        self.main_frame = ctk.CTkFrame(self, corner_radius=15)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        # Encabezado del panel de datos
        self.main_title = ctk.CTkLabel(self.main_frame, text="🔎 Dispositivos en el Radar (Solo Imprescindible)", font=ctk.CTkFont(size=16, weight="bold"))
        self.main_title.grid(row=0, column=0, sticky="w", padx=20, pady=15)

        # Caja de texto grande simulando la tabla limpia de dispositivos detectados
        self.textbox_radar = ctk.CTkTextbox(self.main_frame, font=ctk.CTkFont(family="Courier", size=13))
        self.textbox_radar.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        
        # Mensaje de bienvenida en el radar
        self.textbox_radar.insert("0.0", "Esperando inicio de escaneo táctico...\n")
        self.textbox_radar.configure(state="disabled")

    # Acciones de los botones
    def start_scan(self):
        self.status_label.configure(text="Estado: Escaneando...", text_color="lime")
        self.textbox_radar.configure(state="normal")
        self.textbox_radar.insert("end", "[+] Inicializando interfaz de captura... Simulando radar en Windows.\n")
        self.textbox_radar.configure(state="disabled")

    def stop_scan(self):
        self.status_label.configure(text="Estado: Detenido", text_color="coral")
        self.textbox_radar.configure(state="normal")
        self.textbox_radar.insert("end", "[-] Captura pausada.\n")
        self.textbox_radar.configure(state="disabled")

if __name__ == "__main__":
    app = HackRadarApp()
    app.mainloop()