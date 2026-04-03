import socket
import concurrent.futures

RISCHIO_PORTE = {
    21: "ROSSO", 23: "ROSSO", 80: "VERDE", 443: "VERDE",
    3306: "ROSSO", 3389: "ROSSO", 8080: "GIALLO", 22: "GIALLO", 21: "ROSSO", 25: "GIALLO"
}

def analyze_service(banner, porta):
    """
    Analizza il banner grezzo per identificare la tecnologia specifica.
    Trasforma stringhe complesse in identificazioni pulite.
    """
    banner_low = banner.lower()
    
    # --- WEB SERVER ---
    if "nginx" in banner_low: return f"Web Server (Nginx) - {banner}"
    if "apache" in banner_low: return f"Web Server (Apache) - {banner}"
    if "iis" in banner_low or "microsoft-httpapi" in banner_low: return f"Web Server (Microsoft IIS) - {banner}"
    if "cloudflare" in banner_low: return f"CDN/WAF (Cloudflare) - {banner}"
    if "netlify" in banner_low: return f"CDN/Hosting (Netlify) - {banner}"
    
    # --- SSH ---
    if "ssh" in banner_low:
        ver = banner.split("-")[-1] if "-" in banner else banner
        return f"SSH Service ({ver.strip()})"
        
    # --- DATABASE ---
    if "mysql" in banner_low or "mariadb" in banner_low:
        return "Database (MySQL/MariaDB)"
    if "postgres" in banner_low:
        return "Database (PostgreSQL)"
        
    # --- MAIL / FTP ---
    if "ftp" in banner_low or "220" in banner and porta == 21:
        return f"File Transfer (FTP) - {banner}"
    if "smtp" in banner_low or "esmpt" in banner_low:
        return f"Mail Server (SMTP) - {banner}"
    if "pop3" in banner_low or "+ok" in banner_low:
        return "Mail Server (POP3)"

    # Fallback: Se non riconosciamo nulla ma c'è testo
    if len(banner) > 3:
        return f"Service Detected: {banner}"
    
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

def _scan_single_port(ip, porta, clean_host):
    """Esegue la scansione di una singola porta e restituisce il risultato."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.6)
            res = s.connect_ex((ip, porta))
            if res == 0:
                raw_banner_text = ""
                try:
                    req = f"HEAD / HTTP/1.1\r\nHost: {clean_host}\r\nUser-Agent: SecurityScanner/1.0\r\nConnection: close\r\n\r\n"
                    s.send(req.encode())
                    raw_data = s.recv(2048)
                    decoded = raw_data.decode('utf-8', errors='ignore')
                    lines = decoded.split('\r\n')
                    first_line = lines[0].strip()
                    server_header = next((line for line in lines if line.lower().startswith("server:")), None)
                    if server_header:
                        raw_banner_text = server_header.split(":", 1)[1].strip()
                    elif first_line:
                        raw_banner_text = first_line
                    else:
                        raw_banner_text = decoded.strip()[:50]
                except (socket.timeout, socket.error, ConnectionError):
                    pass
                
                raw_banner_text = ''.join(c for c in raw_banner_text if c.isprintable())[:80]
                descrizione_servizio = analyze_service(raw_banner_text, porta)
                colore = RISCHIO_PORTE.get(porta, "GIALLO")
                return (porta, colore, descrizione_servizio)
    except (socket.timeout, socket.error, ConnectionError, OSError):
        pass
    return None

def scansione_porte(target, range_porte, callback_progress=None, stop_event=None):
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
    
    # Utilizziamo un pool di thread per velocizzare drasticamente la scansione
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(_scan_single_port, ip, p, clean_host): p for p in lista_porte}
        
        for index, future in enumerate(concurrent.futures.as_completed(futures)):
            # Controllo interruzione
            if stop_event and stop_event.is_set():
                # Tentiamo di cancellare i future rimanenti
                for f in futures: f.cancel()
                break
                
            porta = futures[future]
            if callback_progress:
                callback_progress(index + 1, totale, porta)
            
            res = future.result()
            if res:
                risultati.append(res)
                
    # Ordiniamo i risultati per porta (dato che as_completed non garantisce l'ordine)
    risultati.sort(key=lambda x: x[0])
    return risultati
