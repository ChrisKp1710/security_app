import http.client

def cerca_directory_nascoste(target):
    """
    Cerca cartelle comuni (admin, login, backup) su un sito web.
    Restituisce una lista di quelle trovate.
    """
    # Lista di cartelle comuni da cercare
    wordlist = ["/admin", "/login", "/wp-admin", "/test", "/backup", "/private", "/dashboard"]
    trovate = []
    
    # Pulizia target
    target = target.strip().replace("https://", "").replace("http://", "").split("/")[0]

    try:
        # Usa HTTPS di default con timeout e context sicuro
        conn = http.client.HTTPSConnection(target, timeout=3)
        
        # Headers per simulare un browser reale (Stealth Mode)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "*/*"
        }
    except:
        return ["Errore connessione iniziale"]

    for path in wordlist:
        try:
            # Inviamo la richiesta HEAD con gli headers
            conn.request("HEAD", path, headers=headers)
            res = conn.getresponse()
            res.read() # Consuma sempre il body per evitare stati inconsistenti
            
            # Codici 200 (OK), 301/302 (Redirect), 401/403 (Protetto ma esistente)
            if res.status in [200, 301, 302, 401, 403]:
                trovate.append(f"{path} (Code: {res.status})")
        except Exception:
            # Gestione silenziosa errori su singola richiesta (es. timeout)
            pass
            
    conn.close()
    return trovate
