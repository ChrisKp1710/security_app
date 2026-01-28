import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import datetime
import json
import os
from logic.password_gen import genera_password
from logic.hash_checker import calcola_hash_file
from logic.port_scanner import scansione_porte, ottieni_ip
from logic.dir_finder import cerca_directory_nascoste
from logic.web_recon import analizza_headers, analizza_robots
from logic.password_strength import calcola_robustezza
from logic.ssl_inspector import get_ssl_details
from logic.hash_id import identifica_hash
from logic.encoders import encode_data, decode_data

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

        self.title("Security Toolkit Pro v5.0")
        self.geometry("1100x850")
        
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
        self.crypto_frame.grid_columnconfigure(0, weight=3)
        self.crypto_frame.grid_columnconfigure(1, weight=2)
        left_c = ctk.CTkFrame(self.crypto_frame, fg_color="transparent")
        left_c.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        
        card_s = ctk.CTkFrame(left_c, corner_radius=15)
        card_s.pack(fill="both", expand=True, pady=(0, 20))
        ctk.CTkLabel(card_s, text="Password Intelligence", font=("Roboto", 18, "bold"), text_color=COLOR_INFO).pack(pady=20)
        
        self.entry_test_pwd = ctk.CTkEntry(card_s, placeholder_text="Test a password...", height=50, show="*")
        self.entry_test_pwd.pack(fill="x", padx=30, pady=10)
        self.entry_test_pwd.bind("<KeyRelease>", self.update_strength_meter)
        
        self.strength_bar = ctk.CTkProgressBar(card_s, height=12)
        self.strength_bar.set(0)
        self.strength_bar.pack(fill="x", padx=30, pady=10)
        
        self.lbl_strength_score = ctk.CTkLabel(card_s, text="SCORE: ---", font=("Roboto", 13, "bold"))
        self.lbl_strength_score.pack(pady=5)
        self.lbl_crack_time = ctk.CTkLabel(card_s, text="Time to crack: N/A", font=("Roboto", 11, "italic"))
        self.lbl_crack_time.pack()

        card_g = ctk.CTkFrame(left_c, corner_radius=15, fg_color="#1E293B")
        card_g.pack(fill="x")
        self.btn_pwd = ctk.CTkButton(card_g, text="Generate Key", height=45, fg_color=COLOR_SUCCESS, command=self.gestisci_password)
        self.btn_pwd.pack(side="left", padx=20, pady=20)
        self.lbl_pwd_res = ctk.CTkEntry(card_g, height=45, border_width=0, fg_color="#0F172A")
        self.lbl_pwd_res.pack(side="left", fill="x", expand=True, padx=(0, 20))

        card_h = ctk.CTkFrame(self.crypto_frame, corner_radius=15)
        card_h.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        ctk.CTkLabel(card_h, text="File Integrity", font=("Roboto", 18, "bold"), text_color=COLOR_INFO).pack(pady=20)
        self.btn_hash = ctk.CTkButton(card_h, text="Select File", height=45, fg_color="#6366F1", command=self.gestisci_hash)
        self.btn_hash.pack(pady=10, padx=30, fill="x")
        self.lbl_hash_res = ctk.CTkLabel(card_h, text="Waiting for file...", font=("Menlo", 11), wraplength=200)
        self.lbl_hash_res.pack(pady=(20, 10), padx=20)
        
        self.entry_expected_hash = ctk.CTkEntry(card_h, placeholder_text="Expected Hash (Optional)...", height=35)
        self.entry_expected_hash = ctk.CTkEntry(card_h, placeholder_text="Expected Hash (Optional)...", height=35)
        self.entry_expected_hash.pack(fill="x", padx=30, pady=(0, 20))

        # --- ANALYST WORKBENCH (Phase 2.2) ---
        self.workbench = ctk.CTkTabview(self.crypto_frame, height=250)
        self.workbench.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=10, pady=10)
        self.crypto_frame.grid_rowconfigure(1, weight=1)
        
        # TAB 1: Hash Identifier
        tab_id = self.workbench.add("🕵️ Hash ID")
        ctk.CTkLabel(tab_id, text="Unknown Hash Analyzer", font=("Roboto", 14, "bold")).pack(pady=5)
        self.entry_hash_id = ctk.CTkEntry(tab_id, placeholder_text="Paste strange hash here...", width=400)
        self.entry_hash_id.pack(pady=10)
        ctk.CTkButton(tab_id, text="IDENTIFY", command=self.run_hash_id, fg_color="#F59E0B", text_color="black").pack(pady=5)
        self.lbl_hash_id_res = ctk.CTkLabel(tab_id, text="waiting for input...", font=("Menlo", 12))
        self.lbl_hash_id_res.pack(pady=10)
        
        # TAB 2: Encoders
        tab_enc = self.workbench.add("🛠️ Encoders")
        tab_enc.grid_columnconfigure(0, weight=1)
        tab_enc.grid_columnconfigure(1, weight=1)
        
        self.txt_enc_in = ctk.CTkTextbox(tab_enc, height=80)
        self.txt_enc_in.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=5)
        self.txt_enc_in.insert("0.0", "Type here...")
        
        frm_cmds = ctk.CTkFrame(tab_enc, fg_color="transparent")
        frm_cmds.grid(row=1, column=0, columnspan=2, pady=5)
        
        self.opt_algo = ctk.CTkOptionMenu(frm_cmds, values=["Base64", "URL", "Hex", "Binary"])
        self.opt_algo.pack(side="left", padx=5)
        
        ctk.CTkButton(frm_cmds, text="ENCODE ⬇️", width=80, command=self.do_encode).pack(side="left", padx=5)
        ctk.CTkButton(frm_cmds, text="DECODE ⬆️", width=80, command=self.do_decode, fg_color="#4B5563").pack(side="left", padx=5)
        
        self.txt_enc_out = ctk.CTkTextbox(tab_enc, height=80, fg_color="#0F172A")
        self.txt_enc_out.grid(row=2, column=0, columnspan=2, sticky="ew", padx=10, pady=5)

    # --- LOGIC INTEGRATION ---
    def log(self, text, tag="INFO"):
        now = datetime.datetime.now().strftime('%H:%M:%S')
        self.console.insert("end", f"[{now}] ", "MUTED")
        self.console.insert("end", f"{text}\n", tag)
        self.console.see("end")
        
        # Abilita export se ci sono dati reali (non solo info di sistema)
        if tag in ["SUCCESS", "WARNING", "DANGER", "OPEN", "FOUND"]:
            self.btn_export.configure(state="normal", text_color="white", border_color=COLOR_MUTED)

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
        from logic.report_generator import generate_reports
        
        # Chiediamo dove salvare (cartella)
        folder = filedialog.askdirectory(title="Select Output Folder")
        if folder:
            paths = generate_reports(self.report_data, formats, folder)
            messagebox.showinfo("Success", f"Reports generated successfully in:\n{folder}")

if __name__ == "__main__":
    app = Dashboard()
    app.mainloop()