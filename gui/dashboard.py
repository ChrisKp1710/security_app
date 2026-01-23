import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import datetime
from logic.password_gen import genera_password
from logic.hash_checker import calcola_hash_file
from logic.port_scanner import scansione_porte, ottieni_ip
from logic.dir_finder import cerca_directory_nascoste

# --- CONFIGURAZIONE UI/UX THEME ---
ctk.set_appearance_mode("Dark")  # Forza Dark Mode
ctk.set_default_color_theme("blue")  # Tema base blu professionale

class Dashboard(ctk.CTk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.title("Security Toolkit Pro")
        self.geometry("950x850")
        
        # Grid layout configurazione principale (1x1 full expand)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # --- HEADER SECTION ---
        self.create_header()

        # --- NAVIGATION TABS ---
        # Creiamo un Tabview moderno (non il vecchio Notebook)
        self.tabview = ctk.CTkTabview(self, width=900, height=700, corner_radius=15)
        self.tabview.grid(row=1, column=0, padx=20, pady=(10, 20), sticky="nsew")
        
        # Aggiunta Tabs
        self.tab_scan = self.tabview.add("Network Operations")
        self.tab_tools = self.tabview.add("Crypto Lab")

        # Configurazione layout interno tabs
        self.tab_scan.grid_columnconfigure(0, weight=1)
        self.tab_tools.grid_columnconfigure(0, weight=1)

        # Build delle interfacce
        self.setup_network_ui()
        self.setup_crypto_ui()

    def create_header(self):
        """Header minimalista e pulito"""
        header_frame = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        header_frame.grid(row=0, column=0, sticky="ew", padx=25, pady=(25, 10))
        
        title = ctk.CTkLabel(header_frame, text="Security Toolkit", 
                             font=ctk.CTkFont(family="Roboto", size=24, weight="bold"))
        title.pack(side="left")
        
        version = ctk.CTkLabel(header_frame, text="v2.0 Enterprise", 
                               text_color="gray",
                               font=ctk.CTkFont(family="Roboto", size=12))
        version.pack(side="left", padx=10, pady=(10, 0))

    # =========================================================================
    # 🌍 NETWORK SCANNER UI
    # =========================================================================
    def setup_network_ui(self):
        # 1. Target Configuration Card
        self.frame_target = ctk.CTkFrame(self.tab_scan, corner_radius=10)
        self.frame_target.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        self.frame_target.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(self.frame_target, text="Target Host:", font=("Roboto", 14)).grid(row=0, column=0, padx=20, pady=20)
        
        self.entry_ip = ctk.CTkEntry(self.frame_target, placeholder_text="e.g. scanme.nmap.org", 
                                     height=40, font=("Menlo", 13), border_width=1)
        self.entry_ip.grid(row=0, column=1, sticky="ew", padx=(0, 20), pady=20)
        self.entry_ip.insert(0, "scanme.nmap.org")

        # 2. Controls & Options
        self.frame_controls = ctk.CTkFrame(self.tab_scan, fg_color="transparent")
        self.frame_controls.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        
        self.scan_mode = ctk.CTkSegmentedButton(self.frame_controls, values=["Quick Scan", "Full Range"], 
                                                font=("Roboto", 12, "bold"))
        self.scan_mode.set("Quick Scan")
        self.scan_mode.pack(side="left")

        self.btn_scan = ctk.CTkButton(self.frame_controls, text="START SCAN", height=40, width=150,
                                      font=("Roboto", 13, "bold"), fg_color="#3B8ED0", hover_color="#1E40AF",
                                      command=self.avvia_scan)
        self.btn_scan.pack(side="right", padx=10)
        
        self.btn_dir = ctk.CTkButton(self.frame_controls, text="DIR BUST", height=40, width=120,
                                     font=("Roboto", 13, "bold"), fg_color="#4B5563", hover_color="#374151",
                                     command=self.avvia_dir)
        self.btn_dir.pack(side="right")

        # 3. Progress Bar
        self.progress_bar = ctk.CTkProgressBar(self.tab_scan, height=8)
        self.progress_bar.set(0)
        self.progress_bar.grid(row=2, column=0, sticky="ew", padx=15, pady=(5, 15))
        
        self.lbl_status = ctk.CTkLabel(self.tab_scan, text="Ready to scan.", text_color="gray", font=("Roboto", 11))
        self.lbl_status.grid(row=3, column=0, sticky="w", padx=20)

        # 4. Console Log (Modernizzata)
        self.console = ctk.CTkTextbox(self.tab_scan, font=("Menlo", 12), fg_color="#0F172A", text_color="#E2E8F0",
                                      activate_scrollbars=True, corner_radius=10)
        self.console.grid(row=4, column=0, sticky="nsew", padx=10, pady=10)
        self.tab_scan.grid_rowconfigure(4, weight=1) # Espande console

        # Configurazione Tag Colori Console (usando insert con tag non supportato nativamente da CTkTextbox come Tkinter standard,
        # quindi useremo un workaround o formatting semplice per ora, o useremo tk.Text wrappato se necessario colori specifici.
        # CTkTextbox non supporta tag_config complessi come tk.Text. 
        # SOLUZIONE PRO: Useremo un widget tk.Text 'wrappato' dentro un frame CTk per avere i colori,
        # oppure accettiamo testo monocromatico ma pulito.
        # DECISIONE: Per ora monocromatico pulito per coerenza UI, oppure custom implementation.)
        
        # Export Button
        btn_save = ctk.CTkButton(self.tab_scan, text="Export Report", height=30, fg_color="transparent", 
                                 border_width=1, border_color="gray", text_color="gray", hover_color="#1E293B",
                                 command=self.salva_report)
        btn_save.grid(row=5, column=0, sticky="e", padx=20, pady=10)


    # =========================================================================
    # 🔐 CRYPTO LAB UI
    # =========================================================================
    def setup_crypto_ui(self):
        # Container centrale
        center_frame = ctk.CTkFrame(self.tab_tools, fg_color="transparent")
        center_frame.pack(fill="both", expand=True, padx=40, pady=20)

        # -- Password Gen --
        card_pwd = ctk.CTkFrame(center_frame, corner_radius=15)
        card_pwd.pack(fill="x", pady=20)
        
        ctk.CTkLabel(card_pwd, text="Secure Password Generator", font=("Roboto", 16, "bold")).pack(pady=(20, 10))
        
        self.btn_pwd = ctk.CTkButton(card_pwd, text="Generate & Copy", height=50, font=("Roboto", 14, "bold"),
                                     fg_color="#10B981", hover_color="#059669", # Smeraldo
                                     command=self.gestisci_password)
        self.btn_pwd.pack(pady=10)
        
        self.lbl_pwd_res = ctk.CTkEntry(card_pwd, placeholder_text="---", justify="center",
                                        font=("Menlo", 20), height=50, border_width=0, fg_color="#1E293B")
        self.lbl_pwd_res.pack(fill="x", padx=40, pady=(10, 30))

        # -- Hash Checker --
        card_hash = ctk.CTkFrame(center_frame, corner_radius=15)
        card_hash.pack(fill="x", pady=20)
        
        ctk.CTkLabel(card_hash, text="File Integrity Checker (SHA-256)", font=("Roboto", 16, "bold")).pack(pady=(20, 10))
        
        self.btn_hash = ctk.CTkButton(card_hash, text="Select File...", height=40, font=("Roboto", 13),
                                      fg_color="#6366F1", hover_color="#4F46E5", # Indaco
                                      command=self.gestisci_hash)
        self.btn_hash.pack(pady=10)
        
        self.lbl_hash_res = ctk.CTkLabel(card_hash, text="No file selected", font=("Menlo", 12), text_color="gray", wraplength=600)
        self.lbl_hash_res.pack(pady=(10, 30))

    # =========================================================================
    # 🧠 LOGIC & HELPERS
    # =========================================================================
    
    def log(self, text, type="INFO"):
        """Scrive sulla console con timestamp"""
        now = datetime.datetime.now().strftime('%H:%M:%S')
        prefix = f"[{now}] [{type}] "
        full_msg = f"{prefix}{text}\n"
        self.console.insert("end", full_msg)
        self.console.see("end")

    def validate_target(self, target):
        if not target or len(target) < 3:
            return False
        return True

    def avvia_scan(self):
        target = self.entry_ip.get().strip()
        if not self.validate_target(target):
            self.log("Invalid target specified.", "ERROR")
            return

        self.btn_scan.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"Starting DNS resolution for {target}...", "INFO")
        
        threading.Thread(target=self._pre_scan_resolve, args=(target,)).start()

    def _pre_scan_resolve(self, target):
        ip = ottieni_ip(target)
        if not ip:
            self.after(0, lambda: self.log("DNS Resolution Failed.", "ERROR"))
            self.after(0, lambda: self.btn_scan.configure(state="normal"))
            return
        
        self.after(0, lambda: self.log(f"Target Resolved: {ip}", "SUCCESS"))
        self.after(0, lambda: self.start_scan_thread(target, ip))

    def start_scan_thread(self, target, ip):
        self.after(0, lambda: self.log(f"Starting port scan on {ip}...", "INFO"))
        mode = self.scan_mode.get()
        # Logica porte
        porte = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 8080, 8443] if mode == "Quick Scan" else (1, 1000)
        
        threading.Thread(target=self.thread_scan, args=(target, porte)).start()

    def thread_scan(self, target, porte):
        risultati = scansione_porte(target, porte, callback_progress=self.aggiorna_progresso)
        self.after(0, self.mostra_risultati_scan, risultati)

    def aggiorna_progresso(self, corrente, totale, porta_attuale):
        perc = corrente / totale
        self.after(0, lambda: self.progress_bar.set(perc))
        self.after(0, lambda: self.lbl_status.configure(text=f"Scanning port {porta_attuale} ({int(perc*100)}%)"))

    def mostra_risultati_scan(self, risultati):
        self.btn_scan.configure(state="normal")
        self.lbl_status.configure(text="Scan completed.")
        self.progress_bar.set(1.0)
        
        self.log("--- SCAN REPORT ---", "INFO")
        if not risultati: 
            self.log("No open ports found.", "WARNING")
        
        for porta, colore, banner in risultati:
            # Usiamo icone unicode per compensare la mancanza di colori nel testo
            icon = "🔴" if colore == "ROSSO" else ("🟡" if colore == "GIALLO" else "🟢")
            self.log(f"{icon} Port {porta}: {banner}", "OPEN")
        
        self.log("-------------------", "INFO")

    def avvia_dir(self):
        target = self.entry_ip.get().strip()
        if not self.validate_target(target): return
        
        self.log(f"Starting directory brute-force on {target}...", "INFO")
        self.btn_dir.configure(state="disabled")
        threading.Thread(target=lambda: self.after(0, self.mostra_dir, cerca_directory_nascoste(target))).start()

    def mostra_dir(self, res):
        self.btn_dir.configure(state="normal")
        
        if res is None:
            self.log("Connection Error: Could not reach the target (Check URL/Internet).", "ERROR")
            return

        if not res: 
            self.log("No hidden directories found.", "WARNING")
        else:
            self.log(f"Found {len(res)} directories:", "SUCCESS")
            for r in res: self.log(f"  📂 {r}", "FOUND")

    def gestisci_password(self):
        pwd = genera_password(24)
        self.lbl_pwd_res.delete(0, "end")
        self.lbl_pwd_res.insert(0, pwd)
        
        self.clipboard_clear()
        self.clipboard_append(pwd)
        
        # Feedback su bottone
        self.btn_pwd.configure(text="Copied!", fg_color="#065F46")
        self.after(2000, lambda: self.btn_pwd.configure(text="Generate & Copy", fg_color="#10B981"))

    def gestisci_hash(self):
        f = filedialog.askopenfilename()
        if f:
            h = calcola_hash_file(f)
            self.lbl_hash_res.configure(text=f"SHA256: {h}", text_color="#E2E8F0")
            self.log(f"Hashed file: {f.split('/')[-1]}", "INFO")

    def salva_report(self):
        contenuto = self.console.get("1.0", "end")
        f = filedialog.asksaveasfilename(defaultextension=".txt")
        if f:
            with open(f, "w") as file: file.write(contenuto)
            messagebox.showinfo("Export", "Log exported successfully!")