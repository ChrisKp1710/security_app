import customtkinter as ctk
from gui.config import COLOR_SUCCESS

class HomeTab(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.setup_ui()

    def setup_ui(self):
        self.grid_columnconfigure(0, weight=1)
        lbl_welcome = ctk.CTkLabel(
            self, 
            text="Welcome, Operator", 
            font=ctk.CTkFont(size=28, weight="bold")
        )
        lbl_welcome.pack(pady=(40, 10), anchor="w", padx=40)
        
        cards_container = ctk.CTkFrame(self, fg_color="transparent")
        cards_container.pack(fill="x", padx=40)
        
        # Scan Stat Card
        card1 = ctk.CTkFrame(cards_container, width=250, height=150, corner_radius=15)
        card1.pack(side="left", padx=(0, 20))
        card1.pack_propagate(False)
        
        ctk.CTkLabel(card1, text="Total Scans", font=("Roboto", 12), text_color="gray").pack(pady=(20, 5))
        self.lbl_stat_scans = ctk.CTkLabel(card1, text="0", font=("Roboto", 32, "bold"))
        self.lbl_stat_scans.pack()

        # Security Status Card
        card2 = ctk.CTkFrame(cards_container, width=250, height=150, corner_radius=15)
        card2.pack(side="left", padx=20)
        card2.pack_propagate(False)
        
        ctk.CTkLabel(card2, text="Latest Security Status", font=("Roboto", 12), text_color="gray").pack(pady=(20, 5))
        self.lbl_stat_pwd = ctk.CTkLabel(card2, text="Ready", font=("Roboto", 24, "bold"), text_color=COLOR_SUCCESS)
        self.lbl_stat_pwd.pack(pady=10)

    def increment_scans(self):
        current_val = int(self.lbl_stat_scans.cget("text"))
        self.lbl_stat_scans.configure(text=str(current_val + 1))
