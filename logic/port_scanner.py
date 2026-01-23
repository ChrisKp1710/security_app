import socket

RISCHIO_PORTE = {
    80: "VERDE", 443: "VERDE", 22: "GIALLO", 21: "ROSSO", 
    23: "ROSSO", 3306: "ROSSO", 3389: "ROSSO", 8080: "GIALLO"
}

def ottieni_ip(target):
    """Traduce un dominio (google.com) in un indirizzo IP."""
    try:
        target_clean = target.strip().replace("https://", "").replace("http://", "").split("/")[0]
        ip = socket.gethostbyname(target_clean)
        return ip
    except:
        return None

def scansione_porte(target, porte=[21, 22, 23, 80, 443, 3306, 3389, 8080]):
    risultati = []
    target_clean = target.strip().replace("https://", "").replace("http://", "").split("/")[0]
    
    try:
        ip_target = socket.gethostbyname(target_clean)
    except:
        return [("ERRORE: Host non trovato", "red")]

    for porta in porte:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            res = s.connect_ex((ip_target, porta))
            if res == 0:
                livello = RISCHIO_PORTE.get(porta, "GIALLO")
                colore = "green" if livello == "VERDE" else ("orange" if livello == "GIALLO" else "red")
                risultati.append((porta, colore))
        except:
            pass
        s.close()
    
    return risultati