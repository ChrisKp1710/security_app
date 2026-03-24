import http.client
import uuid

def cerca_directory_nascoste(target, wordlist_path=None):
    """
    Cerca cartelle comuni su un sito web con logica "Smart 404 Detection"
    per evitare falsi positivi su siti React/SPA.
    Accetta una wordlist esterna opzionale.
    """
    # Lista di cartelle comuni da cercare (Fallback)
    default_wordlist = [
        "/admin", "/login", "/wp-admin", "/dashboard", "/backup", 
        "/private", "/test", "/user", "/api", "/config", "/db"
    ]
    
    wordlist = []
    if wordlist_path:
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip()]
        except Exception:
            # Fallback silenzioso se il file non si apre
            wordlist = default_wordlist
    else:
        wordlist = default_wordlist

    trovate = []
    
    # 1. Pulizia e preparazione target
    target = target.strip().replace("https://", "").replace("http://", "").split("/")[0]

    # Headers per simulare un browser reale (Stealth Mode)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "*/*"
    }

    try:
        # Timeout leggermente più alto per stabilità
        conn = http.client.HTTPSConnection(target, timeout=4)
        try:
            
            # --- FASE 1: CALIBRAZIONE (Smart 404) ---
            # Cerchiamo un path casuale che sicuramente NON esiste
            random_path = f"/{uuid.uuid4()}"
            
            conn.request("HEAD", random_path, headers=headers)
            res_calib = conn.getresponse()
            res_calib.read() # Consuma il body
            
            # Analizziamo come il server gestisce gli errori
            baseline_status = res_calib.status
            baseline_len = res_calib.getheader("Content-Length")
            
            if baseline_len:
                baseline_len = int(baseline_len)
            else:
                baseline_len = 0

            # RILEVAMENTO COMPORTAMENTI "CATCH-ALL"
            # 1. Catch-All 200 (React/SPA): Risponde 200 a tutto
            is_200_catch_all = (baseline_status == 200)
            
            # 2. Catch-All 403 (WAF/Security): Risponde 403 a tutto quello che non conosce
            is_403_catch_all = (baseline_status == 403)

            # 3. Catch-All Redirect (Soft Fail): Risponde 301/302 a tutto (verso Login o Home)
            is_redirect_catch_all = (baseline_status in [301, 302, 307, 308])
            baseline_location = res_calib.getheader("Location")
            
            # --- FASE 2: SCANSIONE VERA ---
            for path in wordlist:
                try:
                    conn.request("HEAD", path, headers=headers)
                    res = conn.getresponse()
                    res.read() # Consuma body
                    
                    # Recupera lunghezza risposta attuale
                    curr_len = res.getheader("Content-Length")
                    curr_len = int(curr_len) if curr_len else 0
                    curr_location = res.getheader("Location")
                    
                    found = False
                    
                    # LOGICA DI FILTRO AVANZATA (SMART FILTERING v2.0)
                    status = res.status
                    
                    if status in [200, 301, 302, 307, 308, 401, 403]:
                        
                        # Caso A: Gestione Falsi Positivi 200 (SPA)
                        if status == 200 and is_200_catch_all:
                            diff = abs(curr_len - baseline_len)
                            if diff > 50: found = True
                        
                        # Caso B: Gestione Falsi Positivi 403 (WAF)
                        elif status == 403 and is_403_catch_all:
                            diff = abs(curr_len - baseline_len)
                            if diff > 50: found = True

                        # Caso C: Gestione Falsi Positivi Redirect (Login Loops)
                        elif status in [301, 302, 307, 308] and is_redirect_catch_all:
                            # Se redirige allo stesso posto del path casuale -> Falso Positivo
                            # Usiamo 'in' perché a volte gli url relativi/assoluti variano leggermente
                            if curr_location and baseline_location and (curr_location == baseline_location):
                                pass # È uguale, ignoriamo
                            else:
                                found = True # Redirige altrove! È interessante.

                        # Caso D: Comportamento Standard (Server Onesto)
                        # Se non rientra nei casi catch-all sopra, ci fidiamo del codice
                        elif not (status == 200 and is_200_catch_all) and \
                             not (status == 403 and is_403_catch_all) and \
                             not (status in [301, 302, 307, 308] and is_redirect_catch_all):
                            found = True

                    if found:
                        # Formattiamo l'output per la dashboard
                        info_extra = ""
                        if res.status in [301, 302, 307, 308]:
                            info_extra = f" -> Redirect to {curr_location}"
                        elif res.status in [401, 403]:
                            info_extra = " (Protected)"
                        
                        trovate.append(f"{path} [Code: {res.status}]{info_extra}")

                except (http.client.HTTPException, OSError, TimeoutError):
                    # Ignora errori di rete su singola richiesta
                    pass
        finally:
            conn.close()
            
    except (http.client.HTTPException, OSError, TimeoutError):
        # Restituiamo una tupla speciale o None per indicare errore critico
        return None
    return trovate