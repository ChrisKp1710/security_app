import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import os
import time
import queue
from logic.crypto.password_generator import genera_password
from logic.crypto.hash_verifier import calcola_hash_file
from logic.crypto.password_analyzer import calcola_robustezza
from logic.crypto.hash_identifier import identifica_hash
from logic.crypto.data_encoders import encode_data, decode_data
from logic.cracking.zip_bruteforcer import BruteForceManager
from logic.cracking.hashcat_gpu_bridge import generate_gpu_package, check_tools, crack_with_hashcat
from gui.config import COLOR_SUCCESS, COLOR_WARNING, COLOR_DANGER, COLOR_INFO, COLOR_MUTED

class CryptoTab(ctk.CTkFrame):
    def __init__(self, master, dashboard, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.dashboard = dashboard
        self.cracking_active = False
        self.cracker_mgr = BruteForceManager()
        self.target_zip = None
        self.setup_ui()

    def setup_ui(self):
        self.grid_columnconfigure(0, weight=1)
        
        # TabView principale per Crypto
        self.tabs = ctk.CTkTabview(self)
        self.tabs.pack(fill="both", expand=True, padx=20, pady=20)
        
        # --- TAB 1: IDENTITY & ACCESS (Password) ---
        tab_identity = self.tabs.add("🔑 Identity")
        
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
        tab_integrity = self.tabs.add("🛡️ Integrity")
        
        ctk.CTkLabel(tab_integrity, text="File Integrity Verifier", font=("Roboto", 18, "bold")).pack(pady=20)
        
        self.btn_hash = ctk.CTkButton(tab_integrity, text="📂 Select File to Hash", height=50, width=200, command=self.gestisci_hash)
        self.btn_hash.pack(pady=10)
        
        self.entry_expected_hash = ctk.CTkEntry(tab_integrity, placeholder_text="Paste Expected Hash here for comparison (Optional)", width=500, height=40)
        self.entry_expected_hash.pack(pady=20)
        
        self.lbl_hash_res = ctk.CTkLabel(tab_integrity, text="No file selected.", font=("Menlo", 13), wraplength=600, justify="center")
        self.lbl_hash_res.pack(pady=10)

        # --- TAB 3: ANALYST WORKBENCH (Tools) ---
        tab_analyst = self.tabs.add("🕵️ Analyst")
        
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
        self.slider_len.configure(command=lambda v: self.lbl_len_val.configure(text=str(int(v))))
        
        act_frame = ctk.CTkFrame(sub_rec, fg_color="transparent")
        act_frame.pack(fill="x", pady=10)
        
        self.btn_crack = ctk.CTkButton(act_frame, text="🔥 START ATTACK", command=self.toggle_crack, fg_color="#EF4444", hover_color="#B91C1C")
        self.btn_crack.pack(side="left", padx=20, expand=True, fill="x")
        
        self.btn_gpu = ctk.CTkButton(act_frame, text="🚀 GPU ATTACK", width=100, fg_color="#7C3AED", command=self.run_gpu_attack)
        self.btn_gpu.pack(side="right", padx=20)
        
        if not check_tools():
            self.btn_gpu.configure(state="disabled", fg_color="gray", text="GPU (Missing Tools)")
        
        self.lbl_crack_status = ctk.CTkLabel(sub_rec, text="System Idle.", font=("Menlo", 12))
        self.lbl_crack_status.pack(pady=5)
        self.pb_crack = ctk.CTkProgressBar(sub_rec, height=10)
        self.pb_crack.set(0)
        self.pb_crack.pack(fill="x", padx=20)

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

    def gestisci_password(self):
        pwd = genera_password(24)
        self.lbl_pwd_res.delete(0, "end")
        self.lbl_pwd_res.insert(0, pwd)
        self.dashboard.clipboard_clear()
        self.dashboard.clipboard_append(pwd)
        self.btn_pwd.configure(text="Copied!")
        self.dashboard.after(2000, lambda: self.btn_pwd.configure(text="Generate Key"))

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
        txt = self.txt_enc_in.get("1.0", "end-1c")
        mode = self.opt_algo.get()
        res = decode_data(txt, mode)
        self.txt_enc_out.delete("1.0", "end")
        self.txt_enc_out.insert("0.0", res)

    def select_zip(self):
        f = filedialog.askopenfilename(filetypes=[("ZIP Files", "*.zip")])
        if f:
            self.target_zip = f
            self.lbl_zip.configure(text=os.path.basename(f), text_color="white")

    def toggle_crack(self):
        if not self.cracking_active:
            if not self.target_zip:
                messagebox.showerror("Error", "Select a ZIP file first!")
                return
            self.cracking_active = True
            self.btn_crack.configure(text="⛔ STOP ATTACK")
            self.lbl_crack_status.configure(text="Initializing Warhead...")
            threading.Thread(target=self.bg_cracker_loop).start()
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
            if charset == "Numeric (0-9)": c_len = 10
            elif charset == "Alpha Lower (a-z)": c_len = 26
            elif charset == "Alpha Mix (a-zA-Z)": c_len = 52
            else: c_len = 94
            total_combinations = c_len ** length
            self.dashboard.after(0, lambda l=length: self.lbl_crack_status.configure(text=f"Brute Forcing Length: {l}..."))
            num_workers = self.cracker_mgr.start_length_attack(self.target_zip, charset, length)
            self.dashboard.after(0, lambda n=num_workers: self.dashboard.log(f"Deployed {n} workers. Target: {total_combinations:,.0f} combos.", "WARNING"))
            batch_attempts = 0
            while self.cracking_active:
                try:
                    msg = self.cracker_mgr.queue.get(timeout=0.25)
                    if msg[0] == "progress":
                        n = msg[1]
                        total_attempts += n
                        batch_attempts += n
                        now = time.time()
                        elapsed = now - start_time
                        if elapsed > 0.5:
                            speed = total_attempts / elapsed
                            speed_str = f"{speed:.0f} p/s" if speed < 1000 else f"{speed/1000:.1f} kH/s"
                            remaining = total_combinations - batch_attempts
                            eta_s = remaining / speed if speed > 0 else 0
                            eta_str = f"{int(eta_s)}s" if eta_s < 60 else f"{int(eta_s/60)}m"
                            ui_text = f"Speed: {speed_str} | ETA Cur Level: {eta_str}"
                            self.dashboard.after(0, lambda t=ui_text: self.lbl_crack_status.configure(text=t))
                            prog = min(1.0, batch_attempts / total_combinations)
                            self.dashboard.after(0, lambda p=prog: self.pb_crack.set(p))
                    elif msg[0] == "found":
                        pwd = msg[1]
                        self.dashboard.after(0, lambda p=pwd: self.crack_success(p))
                        return
                except queue.Empty:
                    if not any(p.is_alive() for p in self.cracker_mgr.processes): break
        if self.cracking_active:
            elapsed = time.time() - start_time
            self.dashboard.after(0, lambda: self.lbl_crack_status.configure(text=f"Exhausted in {elapsed:.1f}s. Password not found."))
            self.dashboard.after(0, self.toggle_crack)

    def crack_success(self, pwd):
        self.cracking_active = False
        self.cracker_mgr.stop_attack()
        self.btn_crack.configure(text="🔥 START ATTACK")
        self.lbl_crack_status.configure(text=f"PASSWORD FOUND: {pwd}", text_color=COLOR_SUCCESS)
        self.dashboard.log(f"ARCHIVE UNLOCKED! Password: {pwd}", "SUCCESS")
        messagebox.showinfo("VICTORY", f"Password Found:\n\n{pwd}")

    def run_gpu_attack(self):
        if not self.target_zip:
            messagebox.showerror("Error", "Select a ZIP file first!")
            return
        hash_data, cmd, err = generate_gpu_package(self.target_zip)
        if err:
            messagebox.showerror("Extraction Failed", err)
            return
        if messagebox.askyesno("GPU Attack", f"Ready to unleash GPU power?\nTarget: {os.path.basename(self.target_zip)}\n\nWARNING: This will run 'hashcat' on your system."):
            self.lbl_crack_status.configure(text="Initializing GPU Warhead...", text_color="#7C3AED")
            self.btn_gpu.configure(state="disabled")
            max_len = int(self.slider_len.get())
            mask = "?a" * max_len
            threading.Thread(target=self.thread_gpu_attack, args=(hash_data, mask)).start()

    def thread_gpu_attack(self, hash_data, mask):
        def update_log(line):
             if "Status" in line or "Speed" in line:
                 self.dashboard.after(0, lambda: self.lbl_crack_status.configure(text=f"GPU: {line[:50]}..."))
        pwd, err = crack_with_hashcat(hash_data, mask, callback_stdout=update_log)
        self.dashboard.after(0, lambda: self.btn_gpu.configure(state="normal"))
        if pwd:
            self.dashboard.after(0, lambda: self.crack_success(pwd))
        else:
            msg = err if err else "Password not found (or driver error)."
            self.dashboard.after(0, lambda: self.lbl_crack_status.configure(text="GPU Attack Failed."))
            self.dashboard.after(0, lambda: messagebox.showerror("GPU Result", msg))
