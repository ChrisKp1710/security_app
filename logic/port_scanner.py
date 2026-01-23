import socket

RISCHIO_PORTE = {
    21: "ROSSO", 23: "ROSSO", 80: "VERDE", 443: "VERDE",
    3306: "ROSSO", 3389: "ROSSO", 8080: "GIALLO", 22: "GIALLO"
}

def ottieni_ip(target):
    try:
        target = target.strip().replace("https://", "").replace("http://", "").split("/")[0]
        return socket.gethostbyname(target)
    except:
        return None

def scansione_porte(target, range_porte, callback_progress=None):
    """
    callback_progress: una funzione che riceve (numero_porta_corrente, totale_porte)
    """
    risultati = []
    ip = ottieni_ip(target)
    
    if not ip: return [("Errore", "Host non trovato", "")]

    # Definizione lista porte
    if isinstance(range_porte, list):
        lista_porte = range_porte
    else:
        start, end = range_porte
        lista_porte = range(start, end + 1)

    totale = len(lista_porte)

    for index, porta in enumerate(lista_porte):
        # AVVISO PROGRESSO: Se c'è una funzione di callback, la chiamiamo
        if callback_progress:
            callback_progress(index + 1, totale, porta)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5) # Timeout rapido
        try:
            res = s.connect_ex((ip, porta))
            if res == 0:
                # Porta Aperta -> Banner Grabbing
                banner = "Nessun banner"
                try:
                    s.send(b'\r\n') 
                    banner = s.recv(1024).decode().strip()
                except:
                    pass
                
                # Cleanup caratteri strani nel banner
                banner = ''.join(c for c in banner if c.isprintable())

                colore = RISCHIO_PORTE.get(porta, "GIALLO")
                if porta == 80: banner = "HTTP Web Server"
                if porta == 443: banner = "HTTPS Web Server"
                
                risultati.append((porta, colore, banner))
        except:
            pass
        finally:
            s.close()
    
    return risultati