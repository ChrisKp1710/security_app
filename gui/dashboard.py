import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import datetime
from logic.password_gen import genera_password
from logic.hash_checker import calcola_hash_file
from logic.port_scanner import scansione_porte, ottieni_ip
from logic.dir_finder import cerca_directory_nascoste
from logic.web_recon import analizza_headers, analizza_robots
from logic.password_strength import calcola_robustezza

# --- CONFIGURAZIONE UI/UX THEME ---
ctk.set_appearance_mode("Dark")  # Forza Dark Mode
ctk.set_default_color_theme("blue")  # Tema base blu professionale

class Dashboard(ctk.CTk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.title("Security Toolkit Pro")
        self.geometry("1000x850") # Leggermente più larga per il layout a 2 colonne
        
        # Grid layout configurazione principale
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # --- HEADER SECTION ---
        self.create_header()

        # --- NAVIGATION TABS ---
        self.tabview = ctk.CTkTabview(self, corner_radius=15)
        self.tabview.grid(row=1, column=0, padx=20, pady=(10, 20), sticky="nsew")
        
        self.tab_scan = self.tabview.add("Network Operations")
        self.tab_tools = self.tabview.add("Crypto Lab")

        self.tab_scan.grid_columnconfigure(0, weight=1)
        self.tab_scan.grid_rowconfigure(4, weight=1)
        
        # Build delle interfacce
        self.setup_network_ui()
        self.setup_crypto_ui()

    def create_header(self):
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", padx=25, pady=(25, 10))
        
        title = ctk.CTkLabel(header_frame, text="Security Toolkit", 
                             font=ctk.CTkFont(family="Roboto", size=26, weight="bold"))
        title.pack(side="left")
        
        version = ctk.CTkLabel(header_frame, text="v4.5 Enterprise", 
                               text_color="#38BDF8",
                               font=ctk.CTkFont(family="Roboto", size=12, weight="bold"))
        version.pack(side="left", padx=15, pady=(10, 0))

    def setup_network_ui(self):
        # Configurazione Target Card
        self.frame_target = ctk.CTkFrame(self.tab_scan, corner_radius=12)
        self.frame_target.grid(row=0, column=0, sticky="ew", padx=15, pady=15)
        self.frame_target.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(self.frame_target, text="Target Host:", font=("Roboto", 14, "bold")).grid(row=0, column=0, padx=20, pady=20)
        
        self.entry_ip = ctk.CTkEntry(self.frame_target, placeholder_text="e.g. scanme.nmap.org", 
                                     height=45, font=("Menlo", 13), border_width=1)
        self.entry_ip.grid(row=0, column=1, sticky="ew", padx=(0, 20), pady=20)
        self.entry_ip.insert(0, "scanme.nmap.org")

        # Controls Frame
        self.frame_controls = ctk.CTkFrame(self.tab_scan, fg_color="transparent")
        self.frame_controls.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 10))
        
        self.scan_mode = ctk.CTkSegmentedButton(self.frame_controls, values=["Quick Scan", "Full Range"], 
                                                font=("Roboto", 12, "bold"), height=35)
        self.scan_mode.set("Quick Scan")
        self.scan_mode.pack(side="left")

        self.btn_scan = ctk.CTkButton(self.frame_controls, text="START SCAN", height=40, width=140,
                                      font=("Roboto", 13, "bold"), fg_color="#3B8ED0", hover_color="#1E40AF",
                                      command=self.avvia_scan)
        self.btn_scan.pack(side="right", padx=5)
        
        self.btn_dir = ctk.CTkButton(self.frame_controls, text="DIR BUST", height=40, width=110,
                                     font=("Roboto", 13, "bold"), fg_color="#4B5563", hover_color="#374151",
                                     command=self.avvia_dir)
        self.btn_dir.pack(side="right", padx=5)

        self.btn_recon = ctk.CTkButton(self.frame_controls, text="🛡️ RECON", height=40, width=110,
                                     font=("Roboto", 13, "bold"), fg_color="#7C3AED", hover_color="#6D28D9",
                                     command=self.avvia_recon)
        self.btn_recon.pack(side="right", padx=5)

        # Progress & Status
        self.progress_bar = ctk.CTkProgressBar(self.tab_scan, height=10)
        self.progress_bar.set(0)
        self.progress_bar.grid(row=2, column=0, sticky="ew", padx=15, pady=(5, 10))
        
        self.lbl_status = ctk.CTkLabel(self.tab_scan, text="Ready for operations.", text_color="gray", font=("Roboto", 11))
        self.lbl_status.grid(row=3, column=0, sticky="w", padx=20)

        # Console
        self.console = ctk.CTkTextbox(self.tab_scan, font=("Menlo", 12), fg_color="#0F172A", text_color="#E2E8F0",
                                      activate_scrollbars=True, corner_radius=12, border_width=1, border_color="#1E293B")
        self.console.grid(row=4, column=0, sticky="nsew", padx=15, pady=15)

        btn_save = ctk.CTkButton(self.tab_scan, text="Export Analysis Report", height=30, fg_color="transparent", 
                                 border_width=1, border_color="#4B5563", text_color="gray", hover_color="#1E293B",
                                 command=self.salva_report)
        btn_save.grid(row=5, column=0, sticky="e", padx=20, pady=(0, 10))

    def setup_crypto_ui(self):
        """Restyling Crypto Lab: Layout a due colonne (Dashboard Style)"""
        self.tab_tools.grid_columnconfigure(0, weight=3) # Colonna principale (Password)
        self.tab_tools.grid_columnconfigure(1, weight=2) # Colonna laterale (Hash)
        self.tab_tools.grid_rowconfigure(0, weight=1)

        # --- COLONNA SINISTRA: PASSWORD INTELLIGENCE ---
        left_column = ctk.CTkFrame(self.tab_tools, fg_color="transparent")
        left_column.grid(row=0, column=0, sticky="nsew", padx=(20, 10), pady=20)
        
        # 1. Password Strength Analyzer Card
        card_strength = ctk.CTkFrame(left_column, corner_radius=15, border_width=1, border_color="#1E293B")
        card_strength.pack(fill="both", expand=True, pady=(0, 20))
        
        ctk.CTkLabel(card_strength, text="Password Intelligence", font=("Roboto", 18, "bold"), text_color="#38BDF8").pack(pady=(20, 5))
        ctk.CTkLabel(card_strength, text="Analyze entropy and estimated cracking time", font=("Roboto", 12), text_color="gray").pack(pady=(0, 20))

        self.entry_test_pwd = ctk.CTkEntry(card_strength, placeholder_text="Enter password to analyze...", 
                                            height=50, font=("Menlo", 14), border_width=1, show="*")
        self.entry_test_pwd.pack(fill="x", padx=30, pady=10)
        self.entry_test_pwd.bind("<KeyRelease>", self.update_strength_meter)

        self.strength_bar = ctk.CTkProgressBar(card_strength, height=12, corner_radius=5)
        self.strength_bar.set(0)
        self.strength_bar.pack(fill="x", padx=30, pady=15)

        stats_frame = ctk.CTkFrame(card_strength, fg_color="transparent")
        stats_frame.pack(fill="x", padx=30, pady=(0, 20))
        
        self.lbl_strength_score = ctk.CTkLabel(stats_frame, text="SCORE: ---", font=("Roboto", 13, "bold"))
        self.lbl_strength_score.pack(side="left")
        
        self.lbl_strength_bits = ctk.CTkLabel(stats_frame, text="0 bits", font=("Menlo", 12), text_color="gray")
        self.lbl_strength_bits.pack(side="left", padx=20)

        self.lbl_crack_time = ctk.CTkLabel(stats_frame, text="Time: N/A", font=("Roboto", 12, "italic"), text_color="#94A3B8")
        self.lbl_crack_time.pack(side="right")

        # 2. Generator Card (Integrata nella colonna sinistra)
        card_gen = ctk.CTkFrame(left_column, corner_radius=15, fg_color="#1E293B")
        card_gen.pack(fill="x")
        
        gen_layout = ctk.CTkFrame(card_gen, fg_color="transparent")
        gen_layout.pack(fill="x", padx=20, pady=20)

        self.btn_pwd = ctk.CTkButton(gen_layout, text="Generate Secure Key", height=45, width=180,
                                     font=("Roboto", 13, "bold"), fg_color="#10B981", hover_color="#059669",
                                     command=self.gestisci_password)
        self.btn_pwd.pack(side="left")
        
        self.lbl_pwd_res = ctk.CTkEntry(gen_layout, placeholder_text="Result...", justify="center",
                                        font=("Menlo", 16), height=45, border_width=0, fg_color="#0F172A")
        self.lbl_pwd_res.pack(side="left", fill="x", expand=True, padx=(15, 0))

        # --- COLONNA DESTRA: UTILITIES ---
        right_column = ctk.CTkFrame(self.tab_tools, fg_color="transparent")
        right_column.grid(row=0, column=1, sticky="nsew", padx=(10, 20), pady=20)

        # 1. Hash Integrity Card
        card_hash = ctk.CTkFrame(right_column, corner_radius=15, border_width=1, border_color="#1E293B")
        card_hash.pack(fill="both", expand=True)

        ctk.CTkLabel(card_hash, text="File Integrity", font=("Roboto", 18, "bold"), text_color="#38BDF8").pack(pady=(20, 5))
        ctk.CTkLabel(card_hash, text="Verify SHA-256 Checksum", font=("Roboto", 12), text_color="gray").pack(pady=(0, 20))

        self.btn_hash = ctk.CTkButton(card_hash, text="Select File", height=45, font=("Roboto", 13, "bold"),
                                      fg_color="#6366F1", hover_color="#4F46E5",
                                      command=self.gestisci_hash)
        self.btn_hash.pack(pady=10, padx=30, fill="x")
        
        self.lbl_hash_res = ctk.CTkLabel(card_hash, text="Ready to hash file...", font=("Menlo", 11), 
                                         text_color="gray", wraplength=250, justify="center")
        self.lbl_hash_res.pack(pady=20, padx=20, fill="both", expand=True)

    def update_strength_meter(self, event=None):
        pwd = self.entry_test_pwd.get()
        if not pwd:
            self.strength_bar.set(0)
            self.lbl_strength_score.configure(text="SCORE: ---", text_color="gray")
            self.lbl_strength_bits.configure(text="0 bits")
            self.lbl_crack_time.configure(text="Time: N/A")
            return

        bits, time_str, score, color, progress_val = calcola_robustezza(pwd)
        self.strength_bar.configure(progress_color=color)
        self.strength_bar.set(progress_val)
        self.lbl_strength_score.configure(text=f"SCORE: {score.upper()}", text_color=color)
        self.lbl_strength_bits.configure(text=f"{bits} bits")
        self.lbl_crack_time.configure(text=f"Time: {time_str}")

    def log(self, text, type="INFO"):
        now = datetime.datetime.now().strftime('%H:%M:%S')
        prefix = f"[{now}] [{type}] "
        self.console.insert("end", prefix, "gray")
        self.console.insert("end", f"{text}\n")
        self.console.see("end")

    def validate_target(self, target):
        if not target or len(target) < 3:
            messagebox.showwarning("Input Error", "Please enter a valid target host.")
            return False
        return True

    def avvia_scan(self):
        target = self.entry_ip.get().strip()
        if not self.validate_target(target): return
        self.btn_scan.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"Resolving host: {target}...", "INFO")
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
        mode = self.scan_mode.get()
        porte = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 8080, 8443] if mode == "Quick Scan" else (1, 1000)
        threading.Thread(target=self.thread_scan, args=(target, porte)).start()

    def thread_scan(self, target, porte):
        risultati = scansione_porte(target, porte, callback_progress=self.aggiorna_progresso)
        self.after(0, self.mostra_risultati_scan, risultati)

    def aggiorna_progresso(self, corrente, totale, porta_attuale):
        perc = corrente / totale
        self.after(0, lambda: self.progress_bar.set(perc))
        self.after(0, lambda: self.lbl_status.configure(text=f"Probing port {porta_attuale}... ({int(perc*100)}%)"))

    def mostra_risultati_scan(self, risultati):
        self.btn_scan.configure(state="normal")
        self.lbl_status.configure(text="Scan completed.")
        self.log("--- SCAN REPORT ---", "INFO")
        if not risultati: self.log("No open ports found.", "WARNING")
        for porta, colore, banner in risultati:
            icon = "🔴" if colore == "ROSSO" else ("🟡" if colore == "GIALLO" else "🟢")
            self.log(f"{icon} Port {porta}: {banner}")

    def avvia_dir(self):
        target = self.entry_ip.get().strip()
        if not self.validate_target(target): return
        self.log(f"Starting directory discovery on {target}...", "INFO")
        self.btn_dir.configure(state="disabled")
        threading.Thread(target=lambda: self.after(0, self.mostra_dir, cerca_directory_nascoste(target))).start()

    def mostra_dir(self, res):
        self.btn_dir.configure(state="normal")
        if res is None: self.log("Connection Error in Directory Scanner.", "ERROR")
        elif not res: self.log("No hidden directories found.", "WARNING")
        else:
            self.log(f"Found {len(res)} resources:", "SUCCESS")
            for r in res: self.log(f"  📂 {r}")

    def avvia_recon(self):
        target = self.entry_ip.get().strip()
        if not self.validate_target(target): return
        self.log(f"Starting Deep Recon on {target}...", "INFO")
        self.btn_recon.configure(state="disabled")
        threading.Thread(target=self.thread_recon, args=(target,)).start()

    def thread_recon(self, target):
        score, report = analizza_headers(target)
        self.after(0, lambda: self.log("--- SECURITY HEADERS ---", "INFO"))
        self.after(0, lambda: self.log(f"Score: {score}/6", "SUCCESS" if score >= 4 else "DANGER"))
        for line in report: self.after(0, lambda l=line: self.log(l))
        self.after(0, lambda: self.log("--- ROBOTS.TXT ---", "INFO"))
        robots = analizza_robots(target)
        if robots:
            for path in robots: self.after(0, lambda p=path: self.log(f"  🤖 Disallow: {path}"))
        else: self.after(0, lambda: self.log("No entries found."))
        self.after(0, lambda: self.btn_recon.configure(state="normal"))

    def gestisci_password(self):
        pwd = genera_password(24)
        self.lbl_pwd_res.delete(0, "end")
        self.lbl_pwd_res.insert(0, pwd)
        self.clipboard_clear()
        self.clipboard_append(pwd)
        self.btn_pwd.configure(text="Copied!", fg_color="#065F46")
        self.after(2000, lambda: self.btn_pwd.configure(text="Generate Secure Key", fg_color="#10B981"))

    def gestisci_hash(self):
        f = filedialog.askopenfilename()
        if f:
            h = calcola_hash_file(f)
            self.lbl_hash_res.configure(text=f"SHA-256 Checksum:\n{h}", text_color="#E2E8F0")
            self.log(f"Hashed file: {f.split('/')[-1]}")

    def salva_report(self):
        contenuto = self.console.get("1.0", "end")
        f = filedialog.asksaveasfilename(defaultextension=".txt")
        if f:
            with open(f, "w") as file: file.write(contenuto)
            messagebox.showinfo("Export", "Analysis saved.")
