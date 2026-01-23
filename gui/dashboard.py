import tkinter as tk
from tkinter import filedialog, messagebox
import threading
from logic.password_gen import genera_password
from logic.hash_checker import calcola_hash_file
from logic.port_scanner import scansione_porte, ottieni_ip
from logic.dir_finder import cerca_directory_nascoste

class Dashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Toolkit v2.1")
        self.root.geometry("600x750")

        tk.Label(root, text="My Security Toolkit", font=("Arial", 22, "bold")).pack(pady=10)

        # TOOL 1: PASSWORD & HASH
        frame_top = tk.Frame(root)
        frame_top.pack(fill="x", padx=10)
        lf_pwd = tk.LabelFrame(frame_top, text=" Password Gen ", padx=5, pady=5)
        lf_pwd.pack(side="left", fill="both", expand=True, padx=5)
        tk.Button(lf_pwd, text="Genera", command=self.gestisci_password).pack()
        self.lbl_pwd = tk.Label(lf_pwd, text="---", fg="blue")
        self.lbl_pwd.pack()

        lf_hash = tk.LabelFrame(frame_top, text=" Hash File ", padx=5, pady=5)
        lf_hash.pack(side="left", fill="both", expand=True, padx=5)
        tk.Button(lf_hash, text="Scegli", command=self.gestisci_hash).pack()
        self.lbl_hash = tk.Label(lf_hash, text="---", font=("Courier", 8))
        self.lbl_hash.pack()

        # TOOL 2: PORT SCANNER
        self.lf_scan = tk.LabelFrame(root, text=" Port Scanner Visuale ", padx=10, pady=10)
        self.lf_scan.pack(padx=20, fill="x", pady=10)
        tk.Label(self.lf_scan, text="IP/Host Target:").pack()
        self.entry_ip = tk.Entry(self.lf_scan, width=30)
        self.entry_ip.insert(0, "epicode.com")
        self.entry_ip.pack(pady=5)
        
        # LABEL PER L'IP
        self.lbl_ip_trovato = tk.Label(self.lf_scan, text="IP: ---", font=("Arial", 10, "bold"), fg="blue")
        self.lbl_ip_trovato.pack()

        self.btn_scan = tk.Button(self.lf_scan, text="🔍 Avvia Analisi Porte", command=self.avvia_scan_porte)
        self.btn_scan.pack()
        self.frame_res_porte = tk.Frame(self.lf_scan)
        self.frame_res_porte.pack(pady=5)
        self.lbl_status_scan = tk.Label(self.lf_scan, text="", font=("Arial", 9, "italic"))
        self.lbl_status_scan.pack()

        # TOOL 3: DIRECTORY FINDER
        self.lf_dir = tk.LabelFrame(root, text=" Directory Hunter ", padx=10, pady=10)
        self.lf_dir.pack(padx=20, fill="x", pady=10)
        self.btn_dir = tk.Button(self.lf_dir, text="🕵️‍♂️ Cerca Directory Nascoste", command=self.avvia_scan_dir)
        self.btn_dir.pack(pady=5)
        self.lbl_res_dir = tk.Label(self.lf_dir, text="", fg="darkred", font=("Courier", 10))
        self.lbl_res_dir.pack()

    def gestisci_password(self):
        pwd = genera_password(12)
        self.lbl_pwd.config(text=pwd)
        self.root.clipboard_clear()
        self.root.clipboard_append(pwd)

    def gestisci_hash(self):
        f = filedialog.askopenfilename()
        if f:
            h = calcola_hash_file(f)
            self.lbl_hash.config(text=h[:10]+"...")

    def avvia_scan_porte(self):
        target = self.entry_ip.get()
        if not target:
            return
        
        # Trova l'IP subito
        ip = ottieni_ip(target)
        if ip:
            self.lbl_ip_trovato.config(text=f"IP: {ip}")
        else:
            self.lbl_ip_trovato.config(text="IP: Non trovato", fg="red")

        for widget in self.frame_res_porte.winfo_children():
            widget.destroy()
        self.lbl_status_scan.config(text="Scansione in corso...", fg="orange")
        self.btn_scan.config(state="disabled")
        threading.Thread(target=self.thread_porte, args=(target,)).start()

    def thread_porte(self, target):
        risultati = scansione_porte(target)
        self.root.after(0, self.fine_scan_porte, risultati)

    def fine_scan_porte(self, risultati):
        self.btn_scan.config(state="normal")
        self.lbl_status_scan.config(text="Completato.", fg="black")
        if not risultati:
            return
        if isinstance(risultati[0], str):
             tk.Label(self.frame_res_porte, text=risultati[0], fg="red").pack()
             return
        for porta, colore in risultati:
            testo = f"Porta {porta} (APERTA)"
            if colore == "red":
                testo += " [PERICOLO!]"
            tk.Label(self.frame_res_porte, text=testo, fg=colore, font=("Arial", 10, "bold")).pack()

    def avvia_scan_dir(self):
        target = self.entry_ip.get()
        if not target:
            return
        self.lbl_res_dir.config(text="Cerco directory...", fg="orange")
        self.btn_dir.config(state="disabled")
        threading.Thread(target=self.thread_dir, args=(target,)).start()

    def thread_dir(self, target):
        risultati = cerca_directory_nascoste(target)
        self.root.after(0, self.fine_scan_dir, risultati)

    def fine_scan_dir(self, risultati):
        self.btn_dir.config(state="normal")
        if not risultati:
            self.lbl_res_dir.config(text="Nessuna trovata.", fg="green")
        else:
            testo = "\n".join(risultati)
            self.lbl_res_dir.config(text=f"Trovate:\n{testo}", fg="purple")
