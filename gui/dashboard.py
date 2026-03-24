import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import datetime
import json
import os
from logic.crypto.password_generator import genera_password
from logic.crypto.hash_verifier import calcola_hash_file
from logic.network.port_scanner import scansione_porte, ottieni_ip
from logic.network.directory_buster import cerca_directory_nascoste
from logic.network.http_recon import analizza_headers, analizza_robots
from logic.crypto.password_analyzer import calcola_robustezza
from logic.crypto.hash_identifier import identifica_hash
from logic.crypto.data_encoders import encode_data, decode_data
from logic.cracking.zip_bruteforcer import BruteForceManager
from logic.cracking.hashcat_gpu_bridge import generate_gpu_package, check_tools, crack_with_hashcat
from logic.network.ssl_inspector import get_ssl_details
import queue
import time

# --- CONFIGURAZIONE UI/UX THEME ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# Colori per i tag della console
COLOR_SUCCESS = "#4ADE80"
COLOR_WARNING = "#FACC15"
COLOR_DANGER = "#F87171"
COLOR_INFO = "#38BDF8"
COLOR_MUTED = "#94A3B8"

class Dashboard(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Security Toolkit Pro v5.1 - Cyber Ops Edition")
        self.geometry("1100x900")
        
        # --- CRACKER MANAGER ---
        self.cracker_mgr = BruteForceManager()
        self.cracking_active = False
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- DATA STORAGE PER REPORT ---
        self.reset_results()
        self.wordlist_path = None

        # --- SIDEBAR ---
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="🛡️ SECURITY\nTOOLKIT", 
                                       font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 30))

        self.btn_home = ctk.CTkButton(self.sidebar_frame, text=" Dashboard", 
                                       anchor="w", fg_color="transparent",
                                       hover_color=('#3B8ED0', '#1E293B'), command=self.show_home)
        self.btn_home.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        self.btn_nav_scan = ctk.CTkButton(self.sidebar_frame, text=" Network Ops", 
                                           anchor="w", fg_color="transparent",
                                           hover_color=('#3B8ED0', '#1E293B'), command=self.show_network)
        self.btn_nav_scan.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

        self.btn_nav_crypto = ctk.CTkButton(self.sidebar_frame, text=" Crypto Lab", 
                                             anchor="w", fg_color="transparent",
                                             hover_color=('#3B8ED0', '#1E293B'), command=self.show_crypto)
        self.btn_nav_crypto.grid(row=3, column=0, padx=20, pady=10, sticky="ew")

        self.info_label = ctk.CTkLabel(self.sidebar_frame, text="Enterprise v5.0\nStatus: Online", 
                                       font=ctk.CTkFont(size=10), text_color="gray")
        self.info_label.grid(row=5, column=0, padx=20, pady=20)

        # --- CONTENUTI ---
        self.home_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.network_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.crypto_frame = ctk.CTkFrame(self, fg_color="transparent")

        self.setup_home_ui()
        self.setup_network_ui()
        self.setup_crypto_ui()

        self.last_target = ""
        self.show_home()

    def reset_results(self):
        """Inizializza o resetta la struttura dati dei risultati."""
        self.report_data = {
            "target": "N/A",
            "timestamp": "",
            "scans": [],
            "recon": {"score": 0, "headers": [], "robots": []},
            "directories": []
        }

    def select_frame(self, name):
        self.btn_home.configure(fg_color="transparent" if name != "home" else "#3B8ED0")
        self.btn_nav_scan.configure(fg_color="transparent" if name != "network" else "#3B8ED0")
        self.btn_nav_crypto.configure(fg_color="transparent" if name != "crypto" else "#3B8ED0")

        self.home_frame.grid_forget()
        self.network_frame.grid_forget()
        self.crypto_frame.grid_forget()

        if name == "home": self.home_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        if name == "network": self.network_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        if name == "crypto": self.crypto_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)

    def show_home(self): self.select_frame("home")
    def show_network(self): self.select_frame("network")
    def show_crypto(self): self.select_frame("crypto")

    def setup_home_ui(self):
        self.home_frame.grid_columnconfigure(0, weight=1)
        lbl_welcome = ctk.CTkLabel(self.home_frame, text="Welcome, Operator", font=ctk.CTkFont(size=28, weight="bold"))
        lbl_welcome.pack(pady=(40, 10), anchor="w", padx=40)
        
        cards_container = ctk.CTkFrame(self.home_frame, fg_color="transparent")
        cards_container.pack(fill="x", padx=40)
        
        card1 = ctk.CTkFrame(cards_container, width=250, height=150, corner_radius=15)
        card1.pack(side="left", padx=(0, 20))
        card1.pack_propagate(False)
        ctk.CTkLabel(card1, text="Total Scans", font=("Roboto", 12), text_color="gray").pack(pady=(20, 5))
        self.lbl_stat_scans = ctk.CTkLabel(card1, text="0", font=("Roboto", 32, "bold"))
        self.lbl_stat_scans.pack()

        card2 = ctk.CTkFrame(cards_container, width=250, height=150, corner_radius=15)
        card2.pack(side="left", padx=20)
        card2.pack_propagate(False)
        ctk.CTkLabel(card2, text="Latest Security Status", font=("Roboto", 12), text_color="gray").pack(pady=(20, 5))
        self.lbl_stat_pwd = ctk.CTkLabel(card2, text="Ready", font=("Roboto", 24, "bold"), text_color=COLOR_SUCCESS)
        self.lbl_stat_pwd.pack(pady=10)

    def setup_network_ui(self):
        self.network_frame.grid_columnconfigure(0, weight=1)
        self.network_frame.grid_rowconfigure(4, weight=1)

        card_target = ctk.CTkFrame(self.network_frame, corner_radius=15)
        card_target.grid(row=0, column=0, sticky="ew", padx=0, pady=(0, 20))
        card_target.grid_columnconfigure(1, weight=1)
        
        ctk.CTkLabel(card_target, text="Target Host:", font=("Roboto", 14, "bold")).grid(row=0, column=0, padx=20, pady=25)
        self.entry_ip = ctk.CTkEntry(card_target, placeholder_text="e.g. epicode.com", height=45, font=("Menlo", 13))
        self.entry_ip.grid(row=0, column=1, sticky="ew", padx=(0, 20), pady=25)
        self.entry_ip.insert(0, "epicode.com")

        ctrl_frame = ctk.CTkFrame(self.network_frame, fg_color="transparent")
        ctrl_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        
        self.scan_mode = ctk.CTkSegmentedButton(ctrl_frame, values=["Quick Scan", "Full Range"], height=35)
        self.scan_mode.set("Quick Scan")
        self.scan_mode.pack(side="left")

        self.btn_scan = ctk.CTkButton(ctrl_frame, text="SCAN PORTS", height=40, fg_color="#3B8ED0", command=self.avvia_scan)
        self.btn_scan.pack(side="right", padx=5)
        self.btn_dir = ctk.CTkButton(ctrl_frame, text="DIR BUST", height=40, fg_color="#4B5563", command=self.avvia_dir)
        self.btn_dir.pack(side="right", padx=5)
        
        self.btn_wordlist = ctk.CTkButton(ctrl_frame, text="📂 List", width=50, height=40, fg_color="#4B5563", command=self.load_wordlist)
        self.btn_wordlist.pack(side="right", padx=(5, 0))
        self.btn_recon = ctk.CTkButton(ctrl_frame, text="🛡️ RECON", height=40, fg_color="#7C3AED", command=self.avvia_recon)
        self.btn_recon.pack(side="right", padx=5)
        self.btn_ssl = ctk.CTkButton(ctrl_frame, text="🔒 SSL", width=60, height=40, fg_color="#059669", command=self.avvia_ssl)
        self.btn_ssl.pack(side="right", padx=5)

        self.progress_bar = ctk.CTkProgressBar(self.network_frame, height=10)
        self.progress_bar.set(0)
        self.progress_bar.grid(row=2, column=0, sticky="ew", pady=(10, 5))
        self.lbl_status = ctk.CTkLabel(self.network_frame, text="System Ready.", text_color="gray", font=("Roboto", 11))
        self.lbl_status.grid(row=3, column=0, sticky="w")

        self.console = ctk.CTkTextbox(self.network_frame, font=("Menlo", 12), fg_color="#0F172A", corner_radius=12)
        self.console.grid(row=4, column=0, sticky="nsew", pady=15)
        
        self.console_widget = self.console._textbox
        self.console_widget.tag_config("SUCCESS", foreground=COLOR_SUCCESS)
        self.console_widget.tag_config("WARNING", foreground=COLOR_WARNING)
        self.console_widget.tag_config("DANGER", foreground=COLOR_DANGER)
        self.console_widget.tag_config("INFO", foreground=COLOR_INFO)
        self.console_widget.tag_config("MUTED", foreground=COLOR_MUTED)

        self.btn_export = ctk.CTkButton(self.network_frame, text="EXPORT REPORT", height=30, fg_color="transparent", 
                                        border_width=1, text_color="gray", command=self.salva_report, state="disabled")
        self.btn_export.grid(row=5, column=0, sticky="e")

        self.btn_clear = ctk.CTkButton(self.network_frame, text="CLEAR", height=30, width=80, fg_color="transparent", 
                                       border_width=1, text_color="#EF4444", border_color="#EF4444", 
                                       hover_color="#450a0a", command=self.clear_console)
        self.btn_clear.grid(row=5, column=0, sticky="w")

    def setup_crypto_ui(self):
        self.crypto_frame.grid_columnconfigure(0, weight=1)
        
        # Creiamo il TabView principale
        self.crypto_tabs = ctk.CTkTabview(self.crypto_frame)
        self.crypto_tabs.pack(fill="both", expand=True, padx=20, pady=20)
        
        # --- TAB 1: IDENTITY & ACCESS (Password) ---
        tab_identity = self.crypto_tabs.add("🔑 Identity")
        
        # Password Strength
        strength_frame = ctk.CTkFrame(tab_identity, fg_color="transparent")
        strength_frame.pack(fill="x", pady=10)
        ctk.CTkLabel(strength_frame, text="Password Strength Meter", font=("Roboto", 16, "bold"), text_color=COLOR_INFO).pack()
        
        self.entry_test_pwd = ctk.CTkEntry(strength_frame, placeholder_text="Type a password to test...", height=40, show="*")
        self.entry_test_pwd.pack(fill="x", padx=50, pady=10)
        self.entry_test_pwd.bind("<KeyRelease>", self.update_strength_meter)
        
        self.strength_bar = ctk.CTkProgressBar(strength_frame, height=15)
        self.strength_bar.set(0)
        self.strength_bar.pack(fill="x", padx=50, pady=5)
        
        stat_frame = ctk.CTkFrame(strength_frame, fg_color="transparent")
        stat_frame.pack(pady=5)
        self.lbl_strength_score = ctk.CTkLabel(stat_frame, text="SCORE: ---", font=("Roboto", 14, "bold"))
        self.lbl_strength_score.pack(side="left", padx=20)
        self.lbl_crack_time = ctk.CTkLabel(stat_frame, text="Time to crack: N/A", font=("Roboto", 12, "italic"))
        self.lbl_crack_time.pack(side="left", padx=20)

        ctk.CTkFrame(tab_identity, height=2, fg_color="gray").pack(fill="x", padx=20, pady=20) # Divider

        # Password Generator
        gen_frame = ctk.CTkFrame(tab_identity, fg_color="transparent")
        gen_frame.pack(fill="x", pady=10)
        ctk.CTkLabel(gen_frame, text="Secure Key Generator (CSPRNG)", font=("Roboto", 16, "bold"), text_color=COLOR_SUCCESS).pack()
        
        gen_ctrl = ctk.CTkFrame(gen_frame, fg_color="transparent")
        gen_ctrl.pack(pady=10)
        self.btn_pwd = ctk.CTkButton(gen_ctrl, text="GENERATE KEYS", height=45, fg_color=COLOR_SUCCESS, command=self.gestisci_password)
        self.btn_pwd.pack(side="left", padx=10)
        
        self.lbl_pwd_res = ctk.CTkEntry(gen_ctrl, width=400, height=45, font=("Menlo", 14), fg_color="#1E293B", border_width=0)
        self.lbl_pwd_res.pack(side="left", padx=10)

        # --- TAB 2: INTEGRITY LAB (Hashing) ---
        tab_integrity = self.crypto_tabs.add("🛡️ Integrity")
        
        ctk.CTkLabel(tab_integrity, text="File Integrity Verifier", font=("Roboto", 18, "bold")).pack(pady=20)
        
        self.btn_hash = ctk.CTkButton(tab_integrity, text="📂 Select File to Hash", height=50, width=200, command=self.gestisci_hash)
        self.btn_hash.pack(pady=10)
        
        self.entry_expected_hash = ctk.CTkEntry(tab_integrity, placeholder_text="Paste Expected Hash here for comparison (Optional)", width=500, height=40)
        self.entry_expected_hash.pack(pady=20)
        
        self.lbl_hash_res = ctk.CTkLabel(tab_integrity, text="No file selected.", font=("Menlo", 13), wraplength=600, justify="center")
        self.lbl_hash_res.pack(pady=10)

        # --- TAB 3: ANALYST WORKBENCH (Tools) ---
        tab_analyst = self.crypto_tabs.add("🕵️ Analyst")
        
        # Sub-Tabs per Analyst (Hash ID / Encoders)
        analyst_tabs = ctk.CTkTabview(tab_analyst, height=300)
        analyst_tabs.pack(fill="both", expand=True, padx=10, pady=0)
        
        # Sub-Tab: Hash ID
        sub_hash = analyst_tabs.add("Hash Identifier")
        ctk.CTkLabel(sub_hash, text="Identify Unknown Hash Formats", font=("Roboto", 14)).pack(pady=10)
        
        id_frame = ctk.CTkFrame(sub_hash, fg_color="transparent")
        id_frame.pack(fill="x", padx=20)
        self.entry_hash_id = ctk.CTkEntry(id_frame, placeholder_text="Paste hash string here...", height=40)
        self.entry_hash_id.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(id_frame, text="ANALYZE", width=100, height=40, command=self.run_hash_id, fg_color="#F59E0B", text_color="black").pack(side="left")
        
        self.lbl_hash_id_res = ctk.CTkLabel(sub_hash, text="Ready.", font=("Menlo", 12), text_color="gray")
        self.lbl_hash_id_res.pack(pady=20)
        
        # Sub-Tab: Encoders
        sub_enc = analyst_tabs.add("Encoders / Decoders")
        
        self.txt_enc_in = ctk.CTkTextbox(sub_enc, height=60)
        self.txt_enc_in.pack(fill="x", padx=10, pady=5)
        self.txt_enc_in.insert("0.0", "Type here...")
        
        ctrl_enc = ctk.CTkFrame(sub_enc, fg_color="transparent")
        ctrl_enc.pack(pady=5)
        self.opt_algo = ctk.CTkOptionMenu(ctrl_enc, values=["Base64", "URL", "Hex", "Binary"])
        self.opt_algo.pack(side="left", padx=5)
        ctk.CTkButton(ctrl_enc, text="ENCODE ⬇️", width=80, command=self.do_encode).pack(side="left", padx=5)
        ctk.CTkButton(ctrl_enc, text="DECODE ⬆️", width=80, command=self.do_decode, fg_color="#4B5563").pack(side="left", padx=5)
        
        self.txt_enc_out = ctk.CTkTextbox(sub_enc, height=60, fg_color="#0F172A")
        self.txt_enc_out.pack(fill="x", padx=10, pady=5)
        
        # Sub-Tab: Recovery (The Breacher)
        sub_rec = analyst_tabs.add("🔓 Recovery (ZIP)")
        
        rec_frame = ctk.CTkFrame(sub_rec, fg_color="transparent")
        rec_frame.pack(fill="x", padx=10, pady=5)
        
        self.btn_zip = ctk.CTkButton(rec_frame, text="Select Protected ZIP", command=self.select_zip)
        self.btn_zip.pack(side="left", padx=5)
        self.lbl_zip = ctk.CTkLabel(rec_frame, text="No file selected", text_color="gray")
        self.lbl_zip.pack(side="left", padx=5)
        
        opts_frame = ctk.CTkFrame(sub_rec, fg_color="transparent")
        opts_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(opts_frame, text="Charset:").pack(side="left", padx=5)
        self.opt_charset = ctk.CTkOptionMenu(opts_frame, values=["Numeric (0-9)", "Alpha Lower (a-z)", "Alpha Mix (a-zA-Z)", "Full ASCII"])
        self.opt_charset.pack(side="left", padx=5)
        self.opt_charset.set("Alpha Lower (a-z)")
        
        ctk.CTkLabel(opts_frame, text="Max Len:").pack(side="left", padx=5)
        self.slider_len = ctk.CTkSlider(opts_frame, from_=1, to=8, number_of_steps=7, width=150)
        self.slider_len.set(4)
        self.slider_len.pack(side="left", padx=5)
        self.lbl_len_val = ctk.CTkLabel(opts_frame, text="4")
        self.lbl_len_val.pack(side="left", padx=2)
        # Piccolo trick per aggiornare la label dello slider
        self.slider_len.configure(command=lambda v: self.lbl_len_val.configure(text=str(int(v))))
        
        act_frame = ctk.CTkFrame(sub_rec, fg_color="transparent")
        act_frame.pack(fill="x", pady=10)
        
        self.btn_crack = ctk.CTkButton(act_frame, text="🔥 START ATTACK", command=self.toggle_crack, fg_color="#EF4444", hover_color="#B91C1C")
        self.btn_crack.pack(side="left", padx=20, expand=True, fill="x")
        
        self.btn_gpu = ctk.CTkButton(act_frame, text="🚀 GPU ATTACK", width=100, fg_color="#7C3AED", command=self.run_gpu_attack)
        self.btn_gpu.pack(side="right", padx=20)
        
        # Warning se zip2john/hashcat manca
        if not check_tools():
            self.btn_gpu.configure(state="disabled", fg_color="gray", text="GPU (Missing Tools)")
        
        self.lbl_crack_status = ctk.CTkLabel(sub_rec, text="System Idle.", font=("Menlo", 12))
        self.lbl_crack_status.pack(pady=5)
        self.pb_crack = ctk.CTkProgressBar(sub_rec, height=10)
        self.pb_crack.set(0)
        self.pb_crack.pack(fill="x", padx=20)

    def select_zip(self):
        f = filedialog.askopenfilename(filetypes=[("ZIP Files", "*.zip")])
        if f:
            self.target_zip = f
            self.lbl_zip.configure(text=os.path.basename(f), text_color="white")

    def toggle_crack(self):
        if not self.cracking_active:
            if not getattr(self, 'target_zip', None):
                messagebox.showerror("Error", "Select a ZIP file first!")
                return
            
            self.cracking_active = True
            self.btn_crack.configure(text="⛔ STOP ATTACK")
            self.lbl_crack_status.configure(text="Initializing Warhead...")
            self.worker_thread = threading.Thread(target=self.bg_cracker_loop)
            self.worker_thread.start()
        else:
            self.cracking_active = False
            self.cracker_mgr.stop_attack()
            self.btn_crack.configure(text="🔥 START ATTACK")
            self.lbl_crack_status.configure(text="Attack Aborted.")

    def bg_cracker_loop(self):
        charset = self.opt_charset.get()
        max_len = int(self.slider_len.get())
        
        start_time = time.time()
        total_attempts = 0
        
        for length in range(1, max_len + 1):
            if not self.cracking_active: break
            
            # Calcolo combinazioni totali per questa lunghezza (Stima 0-100%)
            if charset == "Numeric (0-9)": c_len = 10
            elif charset == "Alpha Lower (a-z)": c_len = 26
            elif charset == "Alpha Mix (a-zA-Z)": c_len = 52
            else: c_len = 94
            
            total_combinations = c_len ** length
            
            self.after(0, lambda l=length: self.lbl_crack_status.configure(text=f"Brute Forcing Length: {l}..."))
            
            num_workers = self.cracker_mgr.start_length_attack(self.target_zip, charset, length)
            self.after(0, lambda n=num_workers: self.log(f"Deployed {n} workers. Target: {total_combinations:,.0f} combos.", "WARNING"))
            
            batch_attempts = 0
            
            while self.cracking_active:
                try:
                    msg = self.cracker_mgr.queue.get(timeout=0.25)
                    if msg[0] == "progress":
                        n = msg[1]
                        total_attempts += n
                        batch_attempts += n
                        
                        # Speedometer Update
                        now = time.time()
                        elapsed = now - start_time
                        if elapsed > 0.5:
                            speed = total_attempts / elapsed
                            speed_str = f"{speed:.0f} p/s" if speed < 1000 else f"{speed/1000:.1f} kH/s"
                            
                            # Stima tempo
                            remaining = total_combinations - batch_attempts
                            eta_s = remaining / speed if speed > 0 else 0
                            eta_str = f"{int(eta_s)}s" if eta_s < 60 else f"{int(eta_s/60)}m"
                            
                            # Aggiorna UI
                            ui_text = f"Speed: {speed_str} | ETA Cur Level: {eta_str}"
                            self.after(0, lambda t=ui_text: self.lbl_crack_status.configure(text=t))
                            
                            # Progress Bar Logic
                            prog = min(1.0, batch_attempts / total_combinations)
                            self.after(0, lambda p=prog: self.pb_crack.set(p))
                            
                    elif msg[0] == "found":
                        pwd = msg[1]
                        self.after(0, lambda p=pwd: self.crack_success(p))
                        return
                except queue.Empty:
                    if not any(p.is_alive() for p in self.cracker_mgr.processes):
                        break
        
        if self.cracking_active:
            elapsed = time.time() - start_time
            self.after(0, lambda: self.lbl_crack_status.configure(text=f"Exhausted in {elapsed:.1f}s. Password not found."))
            self.after(0, self.toggle_crack)

    def crack_success(self, pwd):
        self.cracking_active = False
        self.cracker_mgr.stop_attack()
        self.btn_crack.configure(text="🔥 START ATTACK")
        self.lbl_crack_status.configure(text=f"PASSWORD FOUND: {pwd}", text_color=COLOR_SUCCESS)
        self.log(f"ARCHIVE UNLOCKED! Password: {pwd}", "SUCCESS")
        messagebox.showinfo("VICTORY", f"Password Found:\n\n{pwd}")

    def run_gpu_attack(self):
        # 1. Preparazione
        if not getattr(self, 'target_zip', None):
            messagebox.showerror("Error", "Select a ZIP file first!")
            return
            
        # 2. Estrazione Hash
        hash_data, cmd, err = generate_gpu_package(self.target_zip)
        if err:
            messagebox.showerror("Extraction Failed", err)
            return
            
        # 3. Conferma e Avvio
        if messagebox.askyesno("GPU Attack", f"Ready to unleash GPU power?\nTarget: {os.path.basename(self.target_zip)}\n\nWARNING: This will run 'hashcat' on your system."):
            self.lbl_crack_status.configure(text="Initializing GPU Warhead...", text_color="#7C3AED")
            self.btn_gpu.configure(state="disabled")
            
            # Parametri maschera (semplicistici per demo)
            # Leggiamo lo slider length per decidere la maschera ?a?a...
            max_len = int(self.slider_len.get())
            charset_code = "?a" # Default alnum
            # Potremmo mappare i charset dello slider a maschere hashcat, ma per ora usiamo ?a (alnum + special)
            
            mask = charset_code * max_len # Es. ?a?a?a?a
            
            # Threading
            threading.Thread(target=self.thread_gpu_attack, args=(hash_data, mask)).start()

    def thread_gpu_attack(self, hash_data, mask):
        def update_log(line):
             # Filtriamo le linee inutili di status
             if "Status" in line or "Speed" in line:
                 self.after(0, lambda: self.lbl_crack_status.configure(text=f"GPU: {line[:50]}..."))
        
        pwd, err = crack_with_hashcat(hash_data, mask, callback_stdout=update_log)
        
        self.after(0, lambda: self.btn_gpu.configure(state="normal"))
        
        if pwd:
            self.after(0, lambda: self.crack_success(pwd))
        else:
            msg = err if err else "Password not found (or driver error)."
            self.after(0, lambda: self.lbl_crack_status.configure(text="GPU Attack Failed."))
            self.after(0, lambda: messagebox.showerror("GPU Result", msg))

    # --- LOGIC INTEGRATION ---
    def log(self, text, tag="INFO"):
        now = datetime.datetime.now().strftime('%H:%M:%S')
        self.console.insert("end", f"[{now}] ", "MUTED")
        self.console.insert("end", f"{text}\n", tag)
        self.console.see("end")
        
        # Abilita export se ci sono dati reali (non solo info di sistema)
        if tag in ["SUCCESS", "WARNING", "DANGER", "OPEN", "FOUND"]:
            self.btn_export.configure(state="normal", text_color="white", border_color=COLOR_MUTED)

    def log_completion(self, task_name):
        self.log("="*45, "MUTED")
        self.log(f"✅ {task_name.upper()} COMPLETED", "SUCCESS")
        self.log("="*45 + "\n", "MUTED")

    def clear_console(self):
        self.console.delete("1.0", "end")
        self.reset_results() # Puliamo anche i dati strutturati
        # FIX BUG border_color: Usiamo un colore solido invece di transparent
        self.btn_export.configure(state="disabled", text_color="gray", border_color="#2D2D2D")

    def check_and_clear_logs(self):
        current_input = self.entry_ip.get().strip()
        current_domain = current_input.replace("https://", "").replace("http://", "").split("/")[0]
        if self.last_target and self.last_target != current_domain:
            self.clear_console()
            self.log(f"New target: {current_domain}. Results reset.", "INFO")
        self.last_target = current_domain
        self.report_data["target"] = current_domain
        self.report_data["timestamp"] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def update_strength_meter(self, event=None):
        pwd = self.entry_test_pwd.get()
        if not pwd:
            self.strength_bar.set(0)
            return
        bits, time_str, score, color, progress_val = calcola_robustezza(pwd)
        self.strength_bar.configure(progress_color=color)
        self.strength_bar.set(progress_val)
        self.lbl_strength_score.configure(text=f"SCORE: {score.upper()}", text_color=color)
        self.lbl_crack_time.configure(text=f"Cracking Time: {time_str}")

    def avvia_scan(self):
        target = self.entry_ip.get().strip()
        if not target: return
        self.check_and_clear_logs()
        self.btn_scan.configure(state="disabled")
        self.progress_bar.set(0)
        self.log(f"Starting DNS resolution for {target}...", "INFO")
        threading.Thread(target=self._pre_scan_resolve, args=(target,)).start()

    def _pre_scan_resolve(self, target):
        ip = ottieni_ip(target)
        if not ip:
            self.after(0, lambda: self.log("DNS Resolution Failed.", "DANGER"))
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
        self.after(0, lambda: self.lbl_status.configure(text=f"Probing port {porta_attuale}..."))

    def mostra_risultati_scan(self, risultati):
        self.btn_scan.configure(state="normal")
        self.log("---" + "-" * 15 + "SCAN REPORT" + "-" * 15 + "---", "INFO")
        self.report_data["scans"] = [] # Reset scans per questo target
        for p, c, b in risultati:
            tag = "DANGER" if c == "ROSSO" else ("WARNING" if c == "GIALLO" else "SUCCESS")
            icon = "🔴" if c == "ROSSO" else ("🟡" if c == "GIALLO" else "🟢")
            self.log(f"{icon} Port {p}: {b}", tag)
            self.report_data["scans"].append({"port": p, "risk": c, "service": b})
        val = int(self.lbl_stat_scans.cget("text")) + 1
        self.lbl_stat_scans.configure(text=str(val))
        self.log_completion("Port Scan")

    def load_wordlist(self):
        f = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if f:
            self.wordlist_path = f
            self.log(f"Custom Wordlist loaded: {os.path.basename(f)}", "INFO")
            self.btn_wordlist.configure(fg_color=COLOR_SUCCESS)

    def avvia_dir(self):
        t = self.entry_ip.get().strip()
        self.check_and_clear_logs()
        self.btn_dir.configure(state="disabled")
        threading.Thread(target=lambda: self.after(0, self.mostra_dir, cerca_directory_nascoste(t, self.wordlist_path))).start()

    def mostra_dir(self, res):
        self.btn_dir.configure(state="normal")
        if res is None:
            self.log("Connection Error: SSL violation or timeout.", "DANGER")
        elif not res:
            self.log("No hidden resources identified.", "WARNING")
        else:
            self.log(f"Identified {len(res)} resources:", "SUCCESS")
            self.report_data["directories"] = res
            for r in res: self.log(f"  📂 {r}", "SUCCESS")
        
        self.log_completion("Directory Busting")

    def avvia_recon(self):
        t = self.entry_ip.get().strip()
        self.check_and_clear_logs()
        self.btn_recon.configure(state="disabled")
        threading.Thread(target=self.thread_recon, args=(t,)).start()

    def thread_recon(self, target):
        score, report = analizza_headers(target)
        self.report_data["recon"]["score"] = score
        self.report_data["recon"]["headers"] = report
        
        self.after(0, lambda: self.log(f"Security Hardening Score: {score}/6", "SUCCESS" if score >= 4 else "DANGER"))
        for l in report:
            tag = "SUCCESS" if "✅" in l else ("WARNING" if "⚠️" in l else "DANGER")
            self.after(0, lambda x=l, t=tag: self.log(x, t))
        
        robots = analizza_robots(target)
        self.report_data["recon"]["robots"] = robots if robots else []
        if robots:
            self.after(0, lambda: self.log("Robots.txt findings:", "WARNING"))
            for path in robots: self.after(0, lambda p=path: self.log(f"  🤖 Disallow: {p}", "SUCCESS"))
        else:
            self.after(0, lambda: self.log("Robots.txt is empty or missing.", "INFO"))
            
        self.after(0, lambda: self.log_completion("Web/OSINT Recon"))
        self.after(0, lambda: self.btn_recon.configure(state="normal"))

    def avvia_ssl(self):
        t = self.entry_ip.get().strip()
        self.check_and_clear_logs()
        self.btn_ssl.configure(state="disabled")
        threading.Thread(target=self.thread_ssl, args=(t,)).start()

    def thread_ssl(self, target):
        self.after(0, lambda: self.log(f"Starting SSL/TLS Handshake with {target}...", "INFO"))
        data = get_ssl_details(target)
        self.after(0, lambda: self.mostra_risultati_ssl(data))

    def mostra_risultati_ssl(self, data):
        self.btn_ssl.configure(state="normal")
        if data["status"] == "error":
            self.log(f"SSL Handshake Failed: {data['message']}", "DANGER")
            return

        self.log("--- SSL/TLS INSPECTION REPORT ---", "INFO")
        self.log(f"Hostname: {data['hostname']}", "SUCCESS")
        self.log(f"Issued By: {data['issuer']}", "INFO")
        self.log(f"Expires On: {data['expiry']} ({data['days_left']} days left)", "WARNING" if data['days_left'] < 30 else "SUCCESS")
        self.log(f"Protocol: {data['protocol']} | Cipher: {data['cipher']}", "MUTED")
        
        if data['sans']:
            self.log(f"SANs (Alt Names) Found: {len(data['sans'])}", "INFO")
            for sub in data['sans']:
                self.log(f"  🔗 {sub}", "SUCCESS")
        else:
            self.log("No Subject Alternative Names found.", "MUTED")
            
        self.log_completion("SSL Inspection")

    def gestisci_password(self):
        pwd = genera_password(24)
        self.lbl_pwd_res.delete(0, "end")
        self.lbl_pwd_res.insert(0, pwd)
        self.clipboard_clear()
        self.clipboard_append(pwd)
        self.btn_pwd.configure(text="Copied!")
        self.after(2000, lambda: self.btn_pwd.configure(text="Generate Key"))

    def gestisci_hash(self):
        f = filedialog.askopenfilename()
        if f:
            h = calcola_hash_file(f)
            expected = self.entry_expected_hash.get().strip()
            
            res_text = f"SHA-256:\n{h}"
            color = "gray"
            
            if expected:
                if h.lower() == expected.lower():
                    res_text += "\n\n✅ HASH MATCH!"
                    color = COLOR_SUCCESS
                else:
                    res_text += "\n\n❌ HASH MISMATCH!"
                    color = COLOR_DANGER
            
            self.lbl_hash_res.configure(text=res_text, text_color=color)

            self.lbl_hash_res.configure(text=res_text, text_color=color)

    def run_hash_id(self):
        s = self.entry_hash_id.get().strip()
        if not s: return
        res = identifica_hash(s)
        text = "\n".join([f"🔹 {r}" for r in res])
        self.lbl_hash_id_res.configure(text=text, text_color=COLOR_INFO)

    def do_encode(self):
        txt = self.txt_enc_in.get("1.0", "end-1c")
        mode = self.opt_algo.get()
        res = encode_data(txt, mode)
        self.txt_enc_out.delete("1.0", "end")
        self.txt_enc_out.insert("0.0", res)

    def do_decode(self):
        txt = self.txt_enc_in.get("1.0", "end-1c") # Usa input box per semplicità, o potremmo usare output box
        # Per UX migliore, decodifichiamo quello che c'è nell'input box
        mode = self.opt_algo.get()
        res = decode_data(txt, mode)
        self.txt_enc_out.delete("1.0", "end")
        self.txt_enc_out.insert("0.0", res)

    def salva_report(self):
        """Apre la finestra di scelta per il Triple Export."""
        # Creiamo una finestra popup moderna
        popup = ctk.CTkToplevel(self) 
        popup.title("Export Configuration")
        popup.geometry("400x350")
        popup.attributes("-topmost", True) # Sempre in primo piano
        
        ctk.CTkLabel(popup, text="Select Export Formats", font=("Roboto", 16, "bold")).pack(pady=20)
        
        var_html = tk.BooleanVar(value=True)
        var_json = tk.BooleanVar(value=False)
        var_txt = tk.BooleanVar(value=False)
        
        ctk.CTkCheckBox(popup, text="Professional Audit (HTML)", variable=var_html).pack(pady=10, padx=50, anchor="w")
        ctk.CTkCheckBox(popup, text="Technical Data (JSON)", variable=var_json).pack(pady=10, padx=50, anchor="w")
        ctk.CTkCheckBox(popup, text="Simple Log (TXT)", variable=var_txt).pack(pady=10, padx=50, anchor="w")
        
        def confirm_export():
            formats = []
            if var_html.get(): formats.append("html")
            if var_json.get(): formats.append("json")
            if var_txt.get(): formats.append("txt")
            
            if not formats:
                messagebox.showwarning("Warning", "Select at least one format!")
                return
            
            # Qui chiameremo il generatore di report
            self.process_export(formats)
            popup.destroy()

        ctk.CTkButton(popup, text="GENERATE REPORTS", command=confirm_export).pack(pady=30)

    def process_export(self, formats):
        from logic.utils.report_exporter import generate_reports
        
        # Chiediamo dove salvare (cartella)
        folder = filedialog.askdirectory(title="Select Output Folder")
        if folder:
            paths = generate_reports(self.report_data, formats, folder)
            messagebox.showinfo("Success", f"Reports generated successfully in:\n{folder}")

if __name__ == "__main__":
    app = Dashboard()
    app.mainloop()