# logic/network/constants.py

# --- MAPPATURA RISCHI PORTE ---
# ROSSO: Pericolo Critico (Dati in chiaro, vulnerabilità note)
# GIALLO: Sospetto/Attenzione (Servizi di amministrazione o potenziali ingressi)
# VERDE: Standard/Sicuro (Servizi web pubblici certificati)
RISCHIO_PORTE = {
    21: "ROSSO",   # FTP (In chiaro)
    22: "GIALLO",  # SSH (Admin)
    23: "ROSSO",   # Telnet (In chiaro)
    25: "GIALLO",  # SMTP
    53: "VERDE",   # DNS
    80: "VERDE",   # HTTP
    110: "ROSSO",  # POP3
    111: "GIALLO", # RPC
    135: "ROSSO",  # RPC Endpoint
    139: "ROSSO",  # NetBIOS
    143: "GIALLO", # IMAP
    443: "VERDE",  # HTTPS
    445: "ROSSO",  # SMB (Critico)
    993: "VERDE",  # IMAPS
    995: "VERDE",  # POP3S
    1723: "GIALLO",# PPTP VPN
    3306: "ROSSO", # MySQL (DB Access)
    3389: "ROSSO", # RDP (Admin Remote)
    5900: "ROSSO", # VNC
    8080: "GIALLO",# HTTP Proxy/Alt
    8443: "GIALLO" # HTTPS Alt
}

# --- PROFESSIONAL TOP PORTS ---
# Selezione delle porte più suscettibili e utilizzate in ambito professionale
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9000, 9200
] 
# Espansione intelligente delle porte di sviluppo comuni
TOP_PORTS += list(range(3000, 3010)) # React/Node/Web
TOP_PORTS += list(range(8000, 8010)) # Python/API
TOP_PORTS.sort()
