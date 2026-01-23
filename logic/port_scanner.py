import socket

RISCHIO_PORTE = {
    21: "ROSSO", 23: "ROSSO", 80: "VERDE", 443: "VERDE",
    3306: "ROSSO", 3389: "ROSSO", 8080: "GIALLO", 22: "GIALLO"
}

def ottieni_ip(target):
    try:
        # Pulizia base per il DNS
        target = target.strip().replace("https://", "").replace("http://", "").split("/")[0]
        return socket.gethostbyname(target)
    except:
        return None

def scansione_porte(target, range_porte, callback_progress=None):
    """
    callback_progress: una funzione che riceve (numero_porta_corrente, totale_porte)
    """
    # --- FIX CRITICO: NORMALIZZAZIONE HOSTNAME ---
    # Indipendentemente da cosa scrive l'utente (es. "https://google.com/test"),
    # noi estraiamo solo "google.com" per usarlo nell'header HTTP Host.
    # Questo previene l'errore "400 Bad Request: Malformed Host Header".
    clean_host = target.strip().replace("https://", "").replace("http://", "").split("/")[0]

    risultati = []
    ip = ottieni_ip(target) # ottieni_ip fa la sua pulizia interna per il DNS
    
    if not ip: return [("Errore", "Host non trovato", "")]

    # Definizione lista porte
    if isinstance(range_porte, list):
        lista_porte = range_porte
    else:
        start, end = range_porte
        lista_porte = range(start, end + 1)

    totale = len(lista_porte)

    for index, porta in enumerate(lista_porte):
        if callback_progress:
            callback_progress(index + 1, totale, porta)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5) 
        try:
            res = s.connect_ex((ip, porta))
            if res == 0:
                # Porta Aperta -> Banner Grabbing Robusto
                banner = "Nessun banner"
                try:
                    # Costruiamo una richiesta HTTP/1.1 standard
                    # USIAMO clean_host INVECE DI target NELL'HEADER HOST
                    req = f"HEAD / HTTP/1.1\r\nHost: {clean_host}\r\nUser-Agent: SecurityScanner/1.0\r\nConnection: close\r\n\r\n"
                    
                    s.send(req.encode()) 
                    
                    raw_banner = s.recv(2048)
                    decoded = raw_banner.decode('utf-8', errors='ignore')
                    
                    # Parsing della risposta
                    lines = decoded.split('\r\n')
                    first_line = lines[0].strip()
                    server_header = next((line for line in lines if line.lower().startswith("server:")), None)
                    
                    if server_header:
                        banner = f"{first_line} | {server_header}"
                    elif first_line:
                        banner = first_line
                    else:
                        banner = decoded.strip()[:50]
                        
                except:
                    pass
                
                banner = ''.join(c for c in banner if c.isprintable())[:80]
                colore = RISCHIO_PORTE.get(porta, "GIALLO")
                risultati.append((porta, colore, banner))
        except:
            pass
        finally:
            s.close()
    
    return risultati
