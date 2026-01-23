import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter import ttk
import threading
import datetime
from logic.password_gen import genera_password
from logic.hash_checker import calcola_hash_file
from logic.port_scanner import scansione_porte, ottieni_ip
from logic.dir_finder import cerca_directory_nascoste

class Dashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Toolkit ULTIMATE v4.0 - DARK EDITION")
        self.root.geometry("750x850")
        self.root.configure(bg="#121212") # Sfondo principale scurissimo

        # --- STILE DARK PER TTK ---
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configurazione colori Tab
        style.configure("TNotebook", background="#121212", borderwidth=0)
        style.configure("TNotebook.Tab", background="#333333", foreground="#BBBBBB", padding=[10, 5], font=('Arial', 10, 'bold'))
        style.map("TNotebook.Tab", background=[("selected", "#00E676")], foreground=[("selected", "#000000")])
        
        style.configure("TFrame", background="#121212")
        style.configure("TLabel", background="#121212", foreground="#FFFFFF")
        
        # ProgressBar Dark
        style.configure("Horizontal.TProgressbar", troughcolor='#333333', bordercolor='#121212', background='#00E676', lightcolor='#00E676', darkcolor='#00E676')

        # --- Intestazione ---
        header = tk.Frame(root, bg="#1E1E1E", height=60)
        header.pack(fill="x")
        tk.Label(header, text="🛡️ CYBER SECURITY SUITE", font=("Impact", 24), fg="#00E676", bg="#1E1E1E").pack(pady=10)

        # --- SISTEMA A SCHEDE ---
        self.tabs = ttk.Notebook(root)
        self.tabs.pack(expand=True, fill="both", padx=10, pady=5)

        self.tab_scanner = ttk.Frame(self.tabs)
        self.tab_crypto = ttk.Frame(self.tabs)

        self.tabs.add(self.tab_scanner, text="🕵️ Network Scanner")
        self.tabs.add(self.tab_crypto, text="🔐 Crypto & Tools")

        # Setup delle pagine
        self.setup_scanner_tab()
        self.setup_crypto_tab()

    def setup_scanner_tab(self):
        # Frame Configurazione (Sfondo scuro)
        frame_input = tk.LabelFrame(self.tab_scanner, text=" Configurazione Target ", fg="#00E676", bg="#1E1E1E", padx=10, pady=10, font=('Arial', 10, 'bold'))
        frame_input.pack(fill="x", padx=10, pady=10)

        tk.Label(frame_input, text="Target:", font=("Arial", 11, "bold"), fg="white", bg="#1E1E1E").pack(side="left")
        self.entry_ip = tk.Entry(frame_input, width=25, font=("Courier", 12), bg="#333333", fg="#00FF00", insertbackground="white", borderwidth=0)
        self.entry_ip.insert(0, "epicode.com")
        self.entry_ip.pack(side="left", padx=10)
        
        self.lbl_ip = tk.Label(frame_input, text="IP: ???", fg="#03A9F4", bg="#1E1E1E", font=("Arial", 10, "bold"))
        self.lbl_ip.pack(side="left", padx=5)

        # Opzioni Radio (Sfondo scuro)
        self.var_scan_type = tk.IntVar(value=1)
        tk.Radiobutton(frame_input, text="Rapido", variable=self.var_scan_type, value=1, bg="#1E1E1E", fg="white", selectcolor="#00E676", activebackground="#1E1E1E").pack(side="left")
        tk.Radiobutton(frame_input, text="Full", variable=self.var_scan_type, value=2, bg="#1E1E1E", fg="white", selectcolor="#00E676", activebackground="#1E1E1E").pack(side="left", padx=5)

        # Pulsanti
        frame_btns = tk.Frame(self.tab_scanner, bg="#121212")
        frame_btns.pack(fill="x", padx=10, pady=5)
        
        tk.Button(frame_btns, text="🚀 START SCAN", bg="#00E676", fg="black", font=("Arial", 11, "bold"), width=20, command=self.avvia_scan).pack(side="left", padx=5)
        tk.Button(frame_btns, text="📂 DIR BRUTE", bg="#FFA000", fg="black", font=("Arial", 11, "bold"), width=20, command=self.avvia_dir).pack(side="left", padx=5)

        # Barra Progresso
        self.progress = ttk.Progressbar(self.tab_scanner, orient="horizontal", mode="determinate", style="Horizontal.TProgressbar")
        self.progress.pack(fill="x", padx=20, pady=10)
        self.lbl_status = tk.Label(self.tab_scanner, text="Ready for action.", fg="#888888", bg="#121212", font=("Arial", 9, "italic"))
        self.lbl_status.pack()

        # Console (Il cuore della Dark Mode)
        self.console = scrolledtext.ScrolledText(self.tab_scanner, font=("Courier New", 11), bg="#0A0A0A", fg="#FFFFFF", borderwidth=0, padx=10, pady=10)
        self.console.pack(padx=10, pady=5, fill="both", expand=True)
        
        # TAG COLORI CONSOLE (Ancora più accesi)
        self.console.tag_config("RED", foreground="#FF1744", font=("Courier New", 11, "bold"))
        self.console.tag_config("GREEN", foreground="#00E676", font=("Courier New", 11, "bold"))
        self.console.tag_config("YELLOW", foreground="#FFEA00", font=("Courier New", 11, "bold"))
        self.console.tag_config("CYAN", foreground="#00B0FF", font=("Courier New", 11, "bold"))
        self.console.tag_config("WHITE", foreground="#FFFFFF")

        tk.Button(self.tab_scanner, text="💾 SAVE LOG", bg="#03DAC6", fg="#000000", font=("Arial", 11, "bold"), width=20, command=self.salva_report).pack(pady=10)

    def setup_crypto_tab(self):
        # Password Section
        lf_pwd = tk.LabelFrame(self.tab_crypto, text=" Generator ", fg="#00E676", bg="#1E1E1E", padx=20, pady=20, font=('Arial', 10, 'bold'))
        lf_pwd.pack(fill="x", padx=20, pady=20)
        
        self.btn_pwd = tk.Button(lf_pwd, text="GENERATE SECURE PASSWORD", bg="#00B0FF", fg="white", font=("Arial", 12, "bold"), command=self.gestisci_password)
        self.btn_pwd.pack(pady=10)
        self.lbl_pwd_res = tk.Label(lf_pwd, text="---", font=("Courier", 18, "bold"), fg="#00E676", bg="#333", width=30)
        self.lbl_pwd_res.pack(pady=10)

        # Hash Section
        lf_hash = tk.LabelFrame(self.tab_crypto, text=" Hash Integrity ", fg="#00E676", bg="#1E1E1E", padx=20, pady=20, font=('Arial', 10, 'bold'))
        lf_hash.pack(fill="x", padx=20, pady=20)
        
        tk.Button(lf_hash, text="CHECK FILE HASH", bg="#7C4DFF", fg="white", font=("Arial", 11, "bold"), command=self.gestisci_hash).pack(pady=10)
        self.lbl_hash_res = tk.Label(lf_hash, text="No file selected", font=("Courier", 10), fg="#AAA", bg="#1E1E1E", wraplength=600)
        self.lbl_hash_res.pack(pady=5)

    def log(self, testo, colore="WHITE"):
        self.console.insert(tk.END, f"[{datetime.datetime.now().strftime('%H:%M:%S')}] ", "WHITE")
        self.console.insert(tk.END, f"{testo}\n", colore)
        self.console.see(tk.END)

    def avvia_scan(self):
        target = self.entry_ip.get()
        ip = ottieni_ip(target)
        if not ip:
            self.log("ERROR: Host resolution failed.", "RED")
            return
        
        self.lbl_ip.config(text=f"IP: {ip}")
        self.log(f"Starting scan on {target} ({ip})...", "CYAN")
        tipo = self.var_scan_type.get()
        porte = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 3389, 5432, 8080] if tipo == 1 else (1, 1000)
        self.progress['value'] = 0
        threading.Thread(target=self.thread_scan, args=(target, porte)).start()

    def thread_scan(self, target, porte):
        risultati = scansione_porte(target, porte, callback_progress=self.aggiorna_progresso)
        self.root.after(0, self.mostra_risultati_scan, risultati)

    def aggiorna_progresso(self, corrente, totale, porta_attuale):
        perc = (corrente / totale) * 100
        msg = f"Scanning Port {porta_attuale}... ({int(perc)}%)"
        self.root.after(0, lambda: self.progress.configure(value=perc))
        self.root.after(0, lambda: self.lbl_status.configure(text=msg))

    def mostra_risultati_scan(self, risultati):
        self.lbl_status.config(text="Scan Complete.")
        self.log("--- SCAN REPORT ---", "CYAN")
        if not risultati: self.log("No open ports found.", "YELLOW")
        for porta, colore, banner in risultati:
            tag = "RED" if colore == "ROSSO" else ("YELLOW" if colore == "GIALLO" else "GREEN")
            self.log(f"[+] PORT {porta} OPEN | {banner}", tag)

    def gestisci_password(self):
        pwd = genera_password(16)
        self.lbl_pwd_res.config(text=pwd)
        self.root.clipboard_clear()
        self.root.clipboard_append(pwd)
        messagebox.showinfo("Clipboard", "Password copied to clipboard!")

    def gestisci_hash(self):
        f = filedialog.askopenfilename()
        if f:
            h = calcola_hash_file(f)
            self.lbl_hash_res.config(text=f"File: {f.split('/')[-1]}\nSHA256: {h}", fg="#00E676")

    def avvia_dir(self):
        t = self.entry_ip.get()
        self.log(f"Enumerating directories on {t}...", "CYAN")
        threading.Thread(target=lambda: self.root.after(0, self.mostra_dir, cerca_directory_nascoste(t))).start()

    def mostra_dir(self, res):
        if not res: self.log("No hidden directories found.", "GREEN")
        else:
            self.log(f"Found {len(res)} directories:", "YELLOW")
            for r in res: self.log(f"  > {r}", "YELLOW")

    def salva_report(self):
        contenuto = self.console.get("1.0", tk.END)
        f = filedialog.asksaveasfilename(defaultextension=".txt")
        if f:
            with open(f, "w") as file: file.write(contenuto)
            messagebox.showinfo("Saved", "Log saved successfully!")