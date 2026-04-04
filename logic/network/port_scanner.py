import socket
import concurrent.futures
import time

RISCHIO_PORTE = {
    21: "ROSSO", 23: "ROSSO", 80: "VERDE", 443: "VERDE",
    3306: "ROSSO", 3389: "ROSSO", 8080: "GIALLO", 22: "GIALLO", 21: "ROSSO", 25: "GIALLO"
}

def analyze_service(banner, porta):
    """
    Analizza il banner grezzo per identificare la tecnologia specifica e le versioni.
    Trasforma stringhe complesse in identificazioni pulite e professionali.
    """
    banner_low = banner.lower()
    
    # --- WEB SERVER (Extraction logic) ---
    if "nginx" in banner_low: 
        ver = banner.split("/")[-1] if "/" in banner else ""
        return f"Web Server (Nginx) {ver}" if ver else "Web Server (Nginx)"
    if "apache" in banner_low:
        ver = banner.split("/")[-1] if "/" in banner else ""
        return f"Web Server (Apache) {ver}" if ver else "Web Server (Apache)"
    if "varnish" in banner_low:
        return f"CDN/Cache (Varnish) - {banner}"
    if "cloudflare" in banner_low:
        return "CDN/WAF (Cloudflare Shield)"
    if "netlify" in banner_low:
        return "Hosting Edge (Netlify)"
    if "iis" in banner_low or "microsoft-httpapi" in banner_low:
        return "Web Server (MS IIS)"
    
    # --- SSH (Precision Extraction) ---
    if "ssh" in banner_low:
        # Pulisce protocolli come SSH-2.0-OpenSSH_8.2p1
        parts = banner.split("-")
        ver = parts[-1] if len(parts) > 2 else banner
        return f"SSH Service ({ver.strip()})"
        
    # --- DATABASE ---
    if "mysql" in banner_low or "mariadb" in banner_low:
        return "Database (MySQL/MariaDB)"
    if "postgres" in banner_low:
        return "Database (PostgreSQL)"
        
    # --- MAIL / FTP ---
    if porta == 21 or "ftp" in banner_low:
        return f"File Transfer (FTP) - {banner[:30]}"
    if porta == 25 or "smtp" in banner_low:
        return f"Mail Server (SMTP) - {banner[:30]}"
    if porta == 110 or "pop3" in banner_low:
        return "Mail Server (POP3)"

    # Fallback: Se non riconosciamo nulla ma c'è testo
    if len(banner) > 3:
        return f"Service Detected: {banner[:40]}"
    
    # Se il banner è vuoto, indovina dalla porta
    if porta == 80: return "HTTP Web Server (No Banner)"
    if porta == 443: return "HTTPS Web Server (No Banner)"
    if porta == 22: return "SSH Service (Silent)"
    
    return "Unknown Service"

def ottieni_ip(target):
    try:
        # Pulizia base per il DNS
        target = target.strip().replace("https://", "").replace("http://", "").split("/")[0]
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def _scan_single_port(ip, porta, clean_host, stop_event=None, timeout=0.6):
    """Esegue la scansione di una singola porta con Double-Handshake Verification."""
    try:
        if stop_event and stop_event.is_set():
            return None
            
        time.sleep(0.005) 
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            res = s.connect_ex((ip, porta))
            if res == 0:
                raw_banner_text = ""
                verified = False
                try:
                    # TENTA BANNER GRABBING (Double Handshake)
                    s.settimeout(1.2) 
                    # Se è una porta web nota, mandiamo un probe HTTP
                    if porta in [80, 443, 8080, 8443]:
                        req = f"HEAD / HTTP/1.1\r\nHost: {clean_host}\r\nConnection: close\r\n\r\n"
                        s.send(req.encode())
                    
                    raw_data = s.recv(1024)
                    if raw_data:
                        decoded = raw_data.decode('utf-8', errors='ignore')
                        verified = True
                        lines = decoded.split('\r\n')
                        first_line = lines[0].strip()
                        server_header = next((line for line in lines if line.lower().startswith("server:")), None)
                        if server_header:
                            raw_banner_text = server_header.split(":", 1)[1].strip()
                        elif first_line:
                            raw_banner_text = first_line
                        else:
                            raw_banner_text = decoded.strip()[:50]
                except (socket.timeout, socket.error):
                    pass
                
                if verified:
                    raw_banner_text = ''.join(c for c in raw_banner_text if c.isprintable())[:80]
                    descrizione_servizio = analyze_service(raw_banner_text, porta)
                    colore = RISCHIO_PORTE.get(porta, "GIALLO")
                else:
                    # PORTA APERTA MA SILENTE (Possibile Firewall Ghost o Stealth Service)
                    descrizione_servizio = "Potential Firewall Ghost / Silent"
                    colore = "GIALLO"
                
                return (porta, colore, descrizione_servizio, verified)
    except Exception:
        pass
    return None

def scansione_porte(target, range_porte, callback_progress=None, stop_event=None, max_workers=50, timeout=0.6):
    """
    Esegue la scansione delle porte in parallelo.
    stop_event: threading.Event per interrompere la scansione.
    """
    clean_host = target.strip().replace("https://", "").replace("http://", "").split("/")[0]
    ip = ottieni_ip(target)
    if not ip: return [("Errore", "Host non trovato", "")]

    if isinstance(range_porte, list):
        lista_porte = range_porte
    else:
        start, end = range_porte
        lista_porte = list(range(start, end + 1))

    totale = len(lista_porte)
    risultati = []
    totale_scansionati = 0
    # Utilizziamo un pool di thread per velocizzare drasticamente la scansione
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_scan_single_port, ip, p, clean_host, stop_event=stop_event, timeout=timeout): p for p in lista_porte}
        
        for index, future in enumerate(concurrent.futures.as_completed(futures)):
            # Controllo interruzione
            if stop_event and stop_event.is_set():
                for f in futures: f.cancel()
                break
                
            totale_scansionati += 1
            porta = futures[future]
            if callback_progress:
                callback_progress(index + 1, totale, porta)
            
            try:
                res = future.result()
                if res:
                    risultati.append(res)
            except Exception:
                pass
                
    risultati.sort(key=lambda x: x[0])
    return risultati, totale_scansionati
