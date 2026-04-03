import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import datetime
import os
from logic.network.port_scanner import scansione_porte, ottieni_ip
from logic.network.directory_buster import cerca_directory_nascoste
from logic.network.http_recon import analizza_headers, analizza_robots, analizza_verbi_http
from logic.network.ssl_inspector import get_ssl_details
from gui.config import COLOR_SUCCESS, COLOR_WARNING, COLOR_DANGER, COLOR_INFO, COLOR_MUTED

class NetworkTab(ctk.CTkFrame):
    def __init__(self, master, dashboard, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.dashboard = dashboard
        self.last_target = ""
        self.wordlist_path = None
        self.setup_ui()

    def setup_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        card_target = ctk.CTkFrame(self, corner_radius=15)
        card_target.grid(row=0, column=0, sticky="ew", padx=0, pady=(0, 20))
        card_target.grid_columnconfigure(1, weight=1)
        
        ctk.CTkLabel(card_target, text="Target Host:", font=("Roboto", 14, "bold")).grid(row=0, column=0, padx=20, pady=25)
        self.entry_ip = ctk.CTkEntry(card_target, placeholder_text="e.g. epicode.com", height=45, font=("Menlo", 13))
        self.entry_ip.grid(row=0, column=1, sticky="ew", padx=(0, 20), pady=25)
        
        default_target = self.dashboard.settings.get("network", "default_target")
        self.entry_ip.insert(0, default_target)

        ctrl_frame = ctk.CTkFrame(self, fg_color="transparent")
        ctrl_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        
        self.scan_mode = ctk.CTkSegmentedButton(ctrl_frame, values=["Quick Scan", "Full Range"], height=35)
        self.scan_mode.set("Quick Scan")
        self.scan_mode.pack(side="left")

        self.btn_scan = ctk.CTkButton(ctrl_frame, text="SCAN PORTS", height=40, fg_color="#3B8ED0", command=self.toggle_scan)
        self.btn_scan.pack(side="right", padx=5)
        self.btn_dir = ctk.CTkButton(ctrl_frame, text="DIR BUST", height=40, fg_color="#4B5563", command=self.avvia_dir)
        self.btn_dir.pack(side="right", padx=5)
        
        self.btn_wordlist = ctk.CTkButton(ctrl_frame, text="📂 List", width=50, height=40, fg_color="#4B5563", command=self.load_wordlist)
        self.btn_wordlist.pack(side="right", padx=(5, 0))
        self.btn_recon = ctk.CTkButton(ctrl_frame, text="🛡️ RECON", height=40, fg_color="#7C3AED", command=self.avvia_recon)
        self.btn_recon.pack(side="right", padx=5)
        self.btn_ssl = ctk.CTkButton(ctrl_frame, text="🔒 SSL", width=60, height=40, fg_color="#059669", command=self.avvia_ssl)
        self.btn_ssl.pack(side="right", padx=5)

        self.progress_bar = ctk.CTkProgressBar(self, height=10)
        self.progress_bar.set(0)
        self.progress_bar.grid(row=2, column=0, sticky="ew", pady=(10, 5))
        self.lbl_status = ctk.CTkLabel(self, text="System Ready.", text_color="gray", font=("Roboto", 11))
        self.lbl_status.grid(row=3, column=0, sticky="w")

        self.console = ctk.CTkTextbox(self, font=("Menlo", 12), fg_color="#0F172A", corner_radius=12)
        self.console.grid(row=4, column=0, sticky="nsew", pady=15)
        
        self.console_widget = self.console._textbox
        self.console_widget.tag_config("SUCCESS", foreground=COLOR_SUCCESS)
        self.console_widget.tag_config("WARNING", foreground=COLOR_WARNING)
        self.console_widget.tag_config("DANGER", foreground=COLOR_DANGER)
        self.console_widget.tag_config("INFO", foreground=COLOR_INFO)
        self.console_widget.tag_config("MUTED", foreground=COLOR_MUTED)

        self.btn_export = ctk.CTkButton(self, text="EXPORT REPORT", height=30, fg_color="transparent", 
                                        border_width=1, text_color="gray", command=self.dashboard.salva_report, state="disabled")
        self.btn_export.grid(row=5, column=0, sticky="e")

        self.btn_clear = ctk.CTkButton(self, text="CLEAR", height=30, width=80, fg_color="transparent", 
                                       border_width=1, text_color="#EF4444", border_color="#EF4444", 
                                       hover_color="#450a0a", command=self.clear_console)
        self.btn_clear.grid(row=5, column=0, sticky="w")

    def log(self, text, tag="INFO"):
        now = datetime.datetime.now().strftime('%H:%M:%S')
        self.console.insert("end", f"[{now}] ", "MUTED")
        self.console.insert("end", f"{text}\n", tag)
        self.console.see("end")
        
        if tag in ["SUCCESS", "WARNING", "DANGER", "OPEN", "FOUND"]:
            self.btn_export.configure(state="normal", text_color="white", border_color=COLOR_MUTED)

    def log_completion(self, task_name):
        self.log("="*45, "MUTED")
        self.log(f"✅ {task_name.upper()} COMPLETED", "SUCCESS")
        self.log("="*45 + "\n", "MUTED")

    def clear_console(self):
        self.console.delete("1.0", "end")
        self.dashboard.reset_results()
        self.btn_export.configure(state="disabled", text_color="gray", border_color="#2D2D2D")

    def check_and_clear_logs(self):
        current_input = self.entry_ip.get().strip()
        current_domain = current_input.replace("https://", "").replace("http://", "").split("/")[0]
        if self.last_target and self.last_target != current_domain:
            self.clear_console()
            self.log(f"New target: {current_domain}. Results reset.", "INFO")
        self.last_target = current_domain
        self.dashboard.report_data["target"] = current_domain
        self.dashboard.report_data["timestamp"] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def toggle_scan(self):
        if self.dashboard.task_manager.is_running("port_scan"):
            self.btn_scan.configure(text="STOPPING...", state="disabled", fg_color="#4B5563")
            self.dashboard.task_manager.stop_task("port_scan")
            self.dashboard.after(200, lambda: self.btn_scan.configure(text="SCAN PORTS", fg_color="#3B8ED0", state="normal"))
            self.log("Scan interruption requested...", "WARNING")
        else:
            self.avvia_scan()

    def avvia_scan(self):
        target = self.entry_ip.get().strip()
        if not target:
            messagebox.showerror("Error", "Insert a valid target host.")
            return

        # Pulizia logica per nuovo scan
        self.btn_scan.configure(text="INITIALIZING...", fg_color="#4B5563", state="disabled")
        self.lbl_status.configure(text="Starting DNS resolution...")
        self.progress_bar.set(0)
        self.check_and_clear_logs()
        
        self.log(f"Starting DNS resolution for {target}...", "INFO")
        
        # Usiamo il TaskManager per gestire tutto il processo
        self.dashboard.task_manager.start_task("port_scan", self._task_full_scan_flow, target)

    def _task_full_scan_flow(self, target, stop_event=None):
        """Workflow completo di scansione gestito come singolo task."""
        ip = ottieni_ip(target)
        if not ip:
            self.dashboard.after(0, lambda: self.log("DNS Resolution Failed.", "DANGER"))
            self.dashboard.after(0, lambda: self.btn_scan.configure(text="SCAN PORTS", fg_color="#3B8ED0"))
            return

        if stop_event and stop_event.is_set(): return
        
        # Ripristiniamo il pulsante in modalità STOP ora che il task è partito
        self.dashboard.after(0, lambda: self.btn_scan.configure(text="STOP SCAN", fg_color="#EF4444", state="normal"))
        
        mode = self.scan_mode.get()
        porte = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 8080, 8443] if mode == "Quick Scan" else (1, 1000)
        
        # Carichiamo i parametri tecnici dai settings
        m_workers = self.dashboard.settings.get("network", "max_workers")
        s_timeout = self.dashboard.settings.get("network", "timeout")
        
        # Chiamata alla logica di scansione parallela con i settings caricati
        try:
            risultati, num_scansionati = scansione_porte(target, porte, callback_progress=self.aggiorna_progresso, 
                                                           stop_event=stop_event, max_workers=m_workers, timeout=s_timeout)
        except Exception as e:
            self.dashboard.after(0, lambda: self.log(f"CRITICAL ERROR in Scanner: {str(e)}", "DANGER"))
            self.dashboard.after(0, lambda: self.btn_scan.configure(text="SCAN PORTS", fg_color="#3B8ED0"))
            return
        
        if stop_event and stop_event.is_set():
            self.dashboard.after(0, lambda: self.btn_scan.configure(text="SCAN PORTS", fg_color="#3B8ED0"))
            return

        self.dashboard.after(0, lambda: self.mostra_risultati_scan(risultati, num_scansionati))

    def aggiorna_progresso(self, corrente, totale, porta_attuale):
        perc = corrente / totale
        self.dashboard.after(0, lambda: self.progress_bar.set(perc))
        self.dashboard.after(0, lambda: self.lbl_status.configure(text=f"Probing port {porta_attuale}..."))

    def mostra_risultati_scan(self, risultati, num_scansionati):
        self.btn_scan.configure(text="SCAN PORTS", fg_color="#3B8ED0")
        self.log("---" + "-" * 15 + "SCAN REPORT" + "-" * 15 + "---", "INFO")
        self.dashboard.report_data["scans"] = [] 
        
        # --- CONFIGURAZIONE ICONE COMPATIBILI (Unicode Standard per Windows) ---
        ICON_MAP = {
            21: "[FTP]", 22: "[SSH]", 23: "[TELNET]", 25: "[SMTP]", 53: "[DNS]", 
            80: "[HTTP]", 110: "[POP3]", 143: "[IMAP]", 443: "[HTTPS]", 445: "[SMB]",
            3306: "[SQL]", 5432: "[SQL]", 3389: "[RDP]", 8080: "[HTTP-ALT]", 8443: "[HTTPS-ALT]"
        }
        
        stats = {"total": num_scansionati, "identified": 0, "unknown": 0, "high_risk": 0}
        is_smart = self.dashboard.settings.get("network", "smart_log")
        unknown_group = [] 
        
        def flush_unknown():
            """Stampa il blocco di porte Unknown accumulato."""
            if not unknown_group: return
            if not is_smart:
                for p in unknown_group:
                    self.log(f"🟡 Port {p}: Unknown Service", "WARNING")
            elif len(unknown_group) == 1:
                p = unknown_group[0]
                self.log(f"🟡 Port {p}: Unknown Service", "WARNING")
            else:
                p_start = unknown_group[0]
                p_end = unknown_group[-1]
                self.log(f"🟡 Ports {p_start}-{p_end}: Multi-Port Silent/Firewall (Unknown)", "WARNING")
            unknown_group.clear()

        for p, c, b in risultati:
            # Salvataggio dati nel report strutturato
            self.dashboard.report_data["scans"].append({"port": p, "risk": c, "service": b})
            
            if b == "Unknown Service":
                stats["unknown"] += 1
                unknown_group.append(p)
            else:
                flush_unknown()
                stats["identified"] += 1
                if c == "ROSSO": stats["high_risk"] += 1
                
                # Selezione Icona / Tag Semplificato per Visibilità
                icon = ICON_MAP.get(p, "[*]")
                tag = "DANGER" if c == "ROSSO" else ("SUCCESS" if c == "VERDE" else "INFO")
                # Pallino colorato + Tag testuale per massimizzare la leggibilità
                bullet = "\u25CF"
                self.log(f"{bullet} {icon} Port {p}: {b}", tag)
        
        flush_unknown()

        # --- EXECUTIVE SUMMARY ---
        self.log("\n" + "="*45, "MUTED")
        self.log("📊 EXECUTIVE SUMMARY & ANALYTICS", "INFO")
        self.log(f"  • Total Scope Checked: {stats['total']} ports", "INFO")
        self.log(f"  • Open & Identified: {stats['identified']}", "SUCCESS" if stats['identified'] > 0 else "INFO")
        self.log(f"  • Open & Silent (Firewalled): {stats['unknown']}", "WARNING")
        
        # WAF/Firewall Detection Logic
        if stats['total'] > 10 and (stats['unknown'] / stats['total']) > 0.4:
            self.log("🛡️ SECURITY POSTURE: Active Firewall/WAF Detected!", "WARNING")
            self.log("  [!] Target is spoofing open ports (LaBrea/Honeyport detected).", "MUTED")
        
        if stats['high_risk'] > 0:
            self.log(f"⚠️ CALIBRATED RISK: {stats['high_risk']} Critical points found!", "DANGER")
        
        self.dashboard.home_tab.increment_scans()
        self.log_completion("Port Scan")

    def load_wordlist(self):
        f = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if f:
            self.wordlist_path = f
            self.log(f"Custom Wordlist loaded: {os.path.basename(f)}", "INFO")
            self.btn_wordlist.configure(fg_color=COLOR_SUCCESS)

    def avvia_dir(self):
        target = self.entry_ip.get().strip()
        if not target: return
        self.check_and_clear_logs()
        self.btn_dir.configure(state="disabled")
        self.dashboard.task_manager.start_task("dir_bust", self._task_dir_bust, target)

    def _task_dir_bust(self, target, stop_event=None):
        res = cerca_directory_nascoste(target, self.wordlist_path)
        if stop_event and stop_event.is_set(): return
        self.dashboard.after(0, lambda: self.mostra_dir(res))

    def mostra_dir(self, res):
        self.btn_dir.configure(state="normal")
        if res is None:
            self.log("Connection Error: SSL violation or timeout.", "DANGER")
        elif not res:
            self.log("No hidden resources identified.", "WARNING")
        else:
            self.log(f"Identified {len(res)} resources:", "SUCCESS")
            self.dashboard.report_data["directories"] = res
            for r in res: self.log(f"  📂 {r}", "SUCCESS")
        
        self.log_completion("Directory Busting")

    def avvia_recon(self):
        target = self.entry_ip.get().strip()
        if not target: return
        self.check_and_clear_logs()
        self.btn_recon.configure(state="disabled")
        self.dashboard.task_manager.start_task("recon", self._task_recon, target)

    def _task_recon(self, target, stop_event=None):
        score, report = analizza_headers(target)
        if stop_event and stop_event.is_set(): return
        
        self.dashboard.after(0, lambda: self.log(f"Security Hardening Score: {score}/6", "SUCCESS" if score >= 4 else "DANGER"))
        for l in report:
            if stop_event and stop_event.is_set(): return
            tag = "SUCCESS" if "✅" in l else ("WARNING" if "⚠️" in l else "DANGER")
            self.dashboard.after(0, lambda x=l, t=tag: self.log(x, t))
        
        robots = analizza_robots(target)
        if stop_event and stop_event.is_set(): return
        
        if robots:
            self.dashboard.after(0, lambda: self.log("Robots.txt findings:", "WARNING"))
            for path in robots:
                if stop_event and stop_event.is_set(): return
                self.dashboard.after(0, lambda p=path: self.log(f"  🤖 Disallow: {p}", "SUCCESS"))
        else:
            self.dashboard.after(0, lambda: self.log("Robots.txt is empty or missing.", "INFO"))
            
        self.dashboard.after(0, lambda: self.log("--- HTTP METHODS ANALYSIS ---", "INFO"))
        verbi_report = analizza_verbi_http(target)
        for r in verbi_report:
            if stop_event and stop_event.is_set(): return
            tag = "SUCCESS" if "✅" in r else ("DANGER" if "❌" in r else ("INFO" if "ℹ️" in r else "WARNING"))
            self.dashboard.after(0, lambda x=r, t=tag: self.log(x, t))
            
        self.dashboard.after(0, lambda: self.log_completion("Web/OSINT Recon"))
        self.dashboard.after(0, lambda: self.btn_recon.configure(state="normal"))

    def avvia_ssl(self):
        target = self.entry_ip.get().strip()
        if not target: return
        self.check_and_clear_logs()
        self.btn_ssl.configure(state="disabled")
        self.dashboard.task_manager.start_task("ssl_inspect", self._task_ssl_inspect, target)

    def _task_ssl_inspect(self, target, stop_event=None):
        self.dashboard.after(0, lambda: self.log(f"Starting SSL/TLS Handshake with {target}...", "INFO"))
        data = get_ssl_details(target)
        if stop_event and stop_event.is_set(): return
        self.dashboard.after(0, lambda: self.mostra_risultati_ssl(data))

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
