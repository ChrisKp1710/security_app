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
        # Usa HTTPS di default
        conn = http.client.HTTPSConnection(target, timeout=2)
    except:
        return ["Errore connessione"]

    for path in wordlist:
        try:
            conn.request("HEAD", path) # 'HEAD' chiede solo se la pagina esiste, senza scaricarla tutta
            res = conn.getresponse()
            
            # Codici 200 (OK), 301/302 (Redirect), 401/403 (Protetto ma esistente)
            if res.status in [200, 301, 302, 401, 403]:
                trovate.append(f"{path} (Code: {res.status})")
        except:
            pass
            
    conn.close()
    return trovate
