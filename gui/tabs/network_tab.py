import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import datetime
import os
import time
import queue
import datetime
from io import StringIO
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.markup import escape
from logic.network.port_scanner import scansione_porte, ottieni_ip
from logic.network.ghost_scanner import scansione_porte_ghost
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
        
        # --- GHOST MODE TOGGLE ---
        self.ghost_mode_switch = ctk.CTkSwitch(ctrl_frame, text="GHOST MODE", font=("Roboto", 11, "bold"), 
                                               progress_color="#7C3AED", command=self.update_ghost_ui)
        self.ghost_mode_switch.pack(side="right", padx=15)
        
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
        
        self.lbl_stealth_info = ctk.CTkLabel(self, text="", text_color="#A78BFA", font=("Roboto", 11, "italic"))
        self.lbl_stealth_info.grid(row=3, column=0, sticky="e", padx=20)

        # Console log con Font Monospace per allineamento perfetto delle tabelle
        self.console = ctk.CTkTextbox(self, height=450, fg_color="#0F172A", 
                                      font=("Consolas", 13) if os.name == "nt" else ("Courier", 13))
        self.console.grid(row=4, column=0, sticky="nsew", padx=20, pady=(0, 20))
        
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

    def update_ghost_ui(self):
        is_ghost = self.ghost_mode_switch.get()
        if is_ghost:
            self.btn_scan.configure(fg_color="#7C3AED", hover_color="#5B21B6") # Purple Stealth
            self.lbl_stealth_info.configure(text="⚠ GHOST MODE: Evasion Protocol Active (Intentional Delay)")
            self.log("GHOST PROTOCOL ENGAGED: Infiltration mode will bypass WAF detection.", "WARNING")
        else:
            self.btn_scan.configure(fg_color="#3B8ED0", hover_color="#1f538d") # Classic Blue
            self.lbl_stealth_info.configure(text="")
            self.log("INDUSTRIAL MODE RESTORED: Full power scanning enabled.", "INFO")

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
            panel_err = self._rich_render("CRITICAL ERROR: Could not resolve target host.", title="DNS FAILURE")
            self.dashboard.after(0, lambda: self.log(panel_err, "DANGER"))
            self.dashboard.after(0, lambda: self.btn_scan.configure(text="SCAN PORTS", fg_color="#3B8ED0"))
            return

        # Ripristiniamo il pulsante in modalità STOP ora che il task è partito
        self.dashboard.after(0, lambda: self.btn_scan.configure(text="STOP SCAN", fg_color="#EF4444", state="normal"))
        self.dashboard.after(0, lambda: self.log(f"TARGET RESOLVED: {ip}", "SUCCESS"))
        
        mode = self.scan_mode.get()
        porte = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 8080, 8443] if mode == "Quick Scan" else (1, 1000)
        
        # Carichiamo i parametri tecnici dai settings
        m_workers = self.dashboard.settings.get("network", "max_workers")
        s_timeout = self.dashboard.settings.get("network", "timeout")
        
        # DECISORE LOGICA: Standard (Tank) vs Ghost (Stealth)
        is_ghost = self.ghost_mode_switch.get()
        
        try:
            if is_ghost:
                # MOTORE GHOST: Isolato e silenzioso
                risultati, num_scansionati = scansione_porte_ghost(target, porte, callback_progress=self.aggiorna_progresso, 
                                                                  stop_event=stop_event)
            else:
                # MOTORE STANDARD: Carro armato industriale
                risultati, num_scansionati = scansione_porte(target, porte, callback_progress=self.aggiorna_progresso, 
                                                               stop_event=stop_event, max_workers=m_workers, timeout=s_timeout)
        except Exception as e:
            self.dashboard.after(0, lambda: self.log(f"CRITICAL ERROR in Scanner: {str(e)}", "DANGER"))
            color = "#7C3AED" if is_ghost else "#3B8ED0"
            self.dashboard.after(0, lambda: self.btn_scan.configure(text="SCAN PORTS", fg_color=color))
            return
        
        if stop_event and stop_event.is_set():
            self.dashboard.after(0, lambda: self.btn_scan.configure(text="SCAN PORTS", fg_color="#3B8ED0"))
            return

        self.dashboard.after(0, lambda: self.mostra_risultati_scan(risultati, num_scansionati))

    def aggiorna_progresso(self, corrente, totale, porta_attuale):
        perc = corrente / totale
        self.dashboard.after(0, lambda: self.progress_bar.set(perc))
        self.dashboard.after(0, lambda: self.lbl_status.configure(text=f"Probing port {porta_attuale}..."))

    def _rich_render(self, renderable, title=None, box_style=box.ASCII):
        """Motore di rendering Rich con stabilità ASCII totale."""
        buf = StringIO()
        # Larghezza contenuta per evitare wrapping e frammentazione
        cons = Console(file=buf, width=60, force_terminal=False, color_system=None)
        
        if isinstance(renderable, str):
            renderable = Panel(escape(renderable), title=title, box=box_style)
            
        cons.print(renderable)
        return buf.getvalue().rstrip()

    def mostra_risultati_scan(self, risultati, num_scansionati):
        is_ghost = self.ghost_mode_switch.get()
        color = "#7C3AED" if is_ghost else "#3B8ED0"
        self.btn_scan.configure(text="SCAN PORTS", fg_color=color)
        stats = {"total": num_scansionati, "identified": 0, "unknown": 0, "high_risk": 0}
        is_smart = self.dashboard.settings.get("network", "smart_log")
        unknown_group = [] 
        
        # Tabella Risultati Rich (Uso ASCII per stabilità totale)
        table = Table(title="[ PORT SCAN RESULTS ]", box=box.ASCII_DOUBLE_HEAD, show_header=True, width=60)
        table.add_column("PORT", width=10)
        table.add_column("STATUS", width=10)
        table.add_column("SERVICE / BANNER", width=34)

        def flush_unknown():
            if not unknown_group: return
            p_text = f"{unknown_group[0]}" if len(unknown_group) == 1 else f"{unknown_group[0]}-{unknown_group[-1]}"
            table.add_row(escape(p_text), "UNRES", "Silent/Firewalled")
            unknown_group.clear()

        num_stealth = 0
        for p, c, b, v in risultati:
            # Salvataggio dati report
            self.dashboard.report_data["scans"].append({"port": p, "risk": c, "service": b, "verified": v})
            
            if not v:
                num_stealth += 1
                if is_smart and b == "Potential Firewall Ghost / Silent":
                    unknown_group.append(p)
                    continue
            
            flush_unknown()
            status_label = "VERIFIED" if v else "STEALTH"
            stats["identified"] += 1 if v else 0
            if c == "ROSSO": stats["high_risk"] += 1
            table.add_row(escape(str(p)), status_label, escape(b[:34]))
        
        flush_unknown()
        
        # Stampa Tabella con analisi riga per riga per colori
        table_output = self._rich_render(table)
        for line in table_output.splitlines():
            level = "INFO"
            if "VERIFIED" in line: level = "SUCCESS"
            elif "STEALTH" in line: level = "WARNING"
            if "Potential" in line or "Ghost" in line: level = "WARNING"
            self.log(line, level)

        # --- EXECUTIVE SUMMARY RIQUADRATO (ASCII ROBUSTO) ---
        summary_content = (
            f"TARGET SCOPE   : {stats['total']} ports\n"
            f"VERIFIED OPEN  : {stats['identified']} services\n"
            f"STEALTH/SILENT : {num_stealth} ports"
        )
        if stats['high_risk'] > 0:
            summary_content += f"\n\n[!] SECURITY ALERT: {stats['high_risk']} Critical Points!"
            
        panel_sum = self._rich_render(Panel(summary_content, title="EXECUTIVE ANALYTICS", box=box.ASCII), box_style=box.ASCII)
        for line in panel_sum.splitlines():
            tag = "DANGER" if "ALERT" in line else "INFO"
            self.log(line, tag)
        
        # WAF/FIREWALL NOISE DETECTION
        if num_stealth > 3:
            waf_msg = (
                "SHIELD ACTIVE: Multiple Stealth Ports Detected!\n"
                "Firewall is likely spoofing open states (Ghosting).\n"
                "Only VERIFIED ports are confirmed 100% active."
            )
            panel_waf = self._rich_render(Panel(waf_msg, title="[!] FIREWALL SPOOFING", box=box.ASCII), box_style=box.ASCII)
            for line in panel_waf.splitlines():
                self.log(line, "WARNING")
        
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
            self.log("ERROR: Enumeration attempt failed.", "DANGER")
        elif not res:
            self.log("INFO: No identified resources via wordlist.", "WARNING")
        else:
            table_d = Table(title="[ ENUMERATION - DISCOVERED RESOURCES ]", box=box.ASCII, width=60)
            table_d.add_column("TYPE", width=12)
            table_d.add_column("RESOURCE FOUND", width=42)
            
            for r in res:
                table_d.add_row("FILE/DIR", escape(r))
            
            # Stampa con analisi colori riga per riga
            d_output = self._rich_render(table_d)
            for line in d_output.splitlines():
                # Coloriamo in verde brillante tutto ciò che è stato trovato
                level = "SUCCESS" if "FILE/DIR" in line else "INFO"
                self.log(line, level)
                
            self.dashboard.report_data["directories"] = res
        
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
        
        # --- TABELLA HEADERS RECON ---
        table_h = Table(title=f"[ WEB AUDIT - SCORE: {score}/6 ]", box=box.ASCII, width=60)
        table_h.add_column("STATUS", width=10)
        table_h.add_column("AUDIT FINDING", width=44)
        
        # Salviamo i dati per il report
        self.dashboard.report_data["recon"] = {"score": score, "headers": report, "robots": []}
        
        for l in report:
            tag = "PASS" if "✅" in l else ("WARN" if "⚠️" in l else "MISSING")
            clean_msg = l.replace("✅ ", "").replace("⚠️ ", "").replace("❌ ", "")
            table_h.add_row(tag, escape(clean_msg))
        
        # Stampa Tabella Recap con Analisi Colori Riga per Riga
        audit_output = self._rich_render(table_h)
        for line in audit_output.splitlines():
            level = "INFO"
            if "PASS" in line: level = "SUCCESS"
            elif "WARN" in line: level = "WARNING"
            elif "MISSING" in line: level = "DANGER"
            self.dashboard.after(0, lambda x=line, t=level: self.log(x, t))
        
        # --- OSINT / ROBOTS ---
        robots = analizza_robots(target)
        if stop_event and stop_event.is_set(): return
        
        if robots:
            self.dashboard.report_data["recon"]["robots"] = robots
            rob_text = "\n".join([f"-> {p}" for p in robots])
            panel_rob = self._rich_render(Panel(rob_text, title="OSINT: Robots.txt Analysis", box=box.ASCII))
            self.dashboard.after(0, lambda: self.log("\n" + panel_rob, "WARNING"))
        
        # --- HTTP METHODS & WAF INTEGRITY CHECK ---
        self.dashboard.after(0, lambda: self.log("Validating HTTP methods...", "INFO"))
        verbi = analizza_verbi_http(target)
        waf_deception = False
        
        if verbi:
            self.dashboard.report_data["http_methods"] = verbi
            table_v = Table(title="[ HTTP VERBS AUDIT ]", box=box.ASCII, width=60)
            table_v.add_column("STATUS", width=8)
            table_v.add_column("POLICY RESULT", width=46)
            
            for v in verbi:
                # Se rileviamo il falso positivo, alziamo il flag per l'alert finale
                if "Falso positivo rilevato" in v: waf_deception = True
                
                v_tag = "OK" if "✅" in v else ("RISK" if "❌" in v else "INFO")
                v_msg = v.replace("✅ ", "").replace("❌ ", "").replace("ℹ️ ", "")
                table_v.add_row(v_tag, escape(v_msg))
            
            # Stampa Tabella Verbi
            v_output = self._rich_render(table_v)
            for line in v_output.splitlines():
                level = "INFO"
                if "OK" in line: level = "SUCCESS"
                elif "RISK" in line: level = "DANGER"
                elif "INFO" in line: level = "WARNING"
                self.dashboard.after(0, lambda x=line, t=level: self.log(x, t))

        # --- ALERT DI INTEGRITÀ FINALE (Se WAF Deception rilevata) ---
        if waf_deception:
            self.dashboard.report_data["waf_alert"] = True
            warn_msg = (
                "SHIELD INTEGRITY ALERT: WAF Deception Detected!\n"
                "Target firewall attempted to spoof results.\n"
                "Surgical audit confirmed fake 'Success' signals.\n"
                "Data above might be partially filtered."
            )
            panel_warn = self._rich_render(Panel(warn_msg, title="[!] INTEGRITY WARNING", box=box.ASCII))
            for line in panel_warn.splitlines():
                self.dashboard.after(0, lambda x=line: self.log(x, "DANGER"))
            
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
            self.log(f"SSL ERROR: {data['message']}", "DANGER")
            return

        # --- PANEL CERTIFICATE INFO ---
        cert_info = (
            f"HOSTNAME   : {data['hostname']}\n"
            f"ISSUER     : {data['issuer']}\n"
            f"EXPIRY     : {data['expiry']} ({data['days_left']} days left)\n"
            f"CIPHER     : {data['protocol']} | {data['cipher']}"
        )
        panel_cert = self._rich_render(Panel(cert_info, title="[ TLS/SSL CERTIFICATE ]", box=box.ASCII))
        for line in panel_cert.splitlines():
            level = "SUCCESS"
            if data['days_left'] < 10: level = "DANGER"
            elif data['days_left'] < 30: level = "WARNING"
            self.log(line, level)
        
        if data['sans']:
            table_sans = Table(title="[ SUBJECT ALTERNATIVE NAMES (SANs) ]", box=box.ASCII, width=60)
            table_sans.add_column("DOMAIN", width=54)
            for sub in data['sans']:
                table_sans.add_row(escape(sub))
            
            sans_output = self._rich_render(table_sans)
            for line in sans_output.splitlines():
                self.log(line, "INFO")
            
        self.dashboard.report_data["ssl"] = data
        self.log_completion("SSL Inspection")
