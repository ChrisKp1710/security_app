import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import datetime
import json
import os
from gui.tabs.home_tab import HomeTab
from gui.tabs.network_tab import NetworkTab
from gui.tabs.crypto_tab import CryptoTab
from logic.utils.task_manager import TaskManager
from logic.utils.settings_manager import SettingsManager

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
        
        # --- BUSINESS LOGIC & SETTINGS ---
        self.settings = SettingsManager()
        self.settings.save_settings() # Crea il file se manca
        self.task_manager = TaskManager(max_workers=self.settings.get("network", "max_workers"))
        
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
        self.home_tab = HomeTab(self)
        self.network_tab = NetworkTab(self, self)
        self.crypto_tab = CryptoTab(self, self)


        self.last_target = ""
        self.show_home()

    def reset_results(self):
        """Inizializza o resetta la struttura dati dei risultati per un nuovo target."""
        self.report_data = {
            "target": "N/A",
            "timestamp": "",
            "scans": [],
            "recon": {"score": 0, "headers": [], "robots": []},
            "ssl": {}, # Dettagli certificato
            "http_methods": [], # Audit verbi HTTP
            "waf_alert": False, # Flag integrità WAF
            "directories": []
        }

    def log(self, message, level="INFO"):
        """Redirect log to network tab console."""
        self.network_tab.log(message, level)

    def select_frame(self, name):
        self.btn_home.configure(fg_color="transparent" if name != "home" else "#3B8ED0")
        self.btn_nav_scan.configure(fg_color="transparent" if name != "network" else "#3B8ED0")
        self.btn_nav_crypto.configure(fg_color="transparent" if name != "crypto" else "#3B8ED0")

        self.home_tab.grid_forget()
        self.network_tab.grid_forget()
        self.crypto_tab.grid_forget()

        if name == "home": self.home_tab.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        if name == "network": self.network_tab.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        if name == "crypto": self.crypto_tab.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)

    def show_home(self): self.select_frame("home")
    def show_network(self): self.select_frame("network")
    def show_crypto(self): self.select_frame("crypto")




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