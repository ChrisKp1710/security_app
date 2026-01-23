import http.client
import urllib.parse

def analizza_headers(target):
    """
    Analizza gli header di sicurezza HTTP, seguendo i redirect (max 3 hop).
    """
    # Parsing iniziale
    if not target.startswith("http"): target = "https://" + target
    parsed = urllib.parse.urlparse(target)
    host = parsed.netloc
    path = parsed.path if parsed.path else "/"
    
    headers_report = []
    security_score = 0
    max_redirects = 3 # Evitiamo loop infiniti
    
    checks = {
        "Strict-Transport-Security": "HSTS (HTTPS Enforced)",
        "X-Frame-Options": "Anti-Clickjacking",
        "X-Content-Type-Options": "Anti-MIME Sniffing",
        "Content-Security-Policy": "CSP (XSS Protection)",
        "Referrer-Policy": "Referrer Policy"
    }

    try:
        current_host = host
        current_path = path
        
        # Loop per seguire i redirect
        for _ in range(max_redirects + 1):
            conn = http.client.HTTPSConnection(current_host, timeout=5)
            conn.request("HEAD", current_path, headers={"User-Agent": "Mozilla/5.0 SecurityScanner/2.0"})
            res = conn.getresponse()
            res_headers = {k.lower(): v for k, v in res.getheaders()}
            conn.close()
            
            # Se è un redirect (301, 302, 307, 308), seguiamolo
            if res.status in [301, 302, 307, 308]:
                location = res_headers.get('location')
                if location:
                    # Gestione redirect relativo o assoluto
                    new_parsed = urllib.parse.urlparse(location)
                    if new_parsed.netloc:
                        current_host = new_parsed.netloc
                    current_path = new_parsed.path if new_parsed.path else "/"
                    continue # Riprova col nuovo indirizzo
            
            # Se siamo qui, abbiamo la risposta finale (o abbiamo finito i tentativi)
            break

        # Analisi sulla risposta finale
        for header_key, desc in checks.items():
            key_lower = header_key.lower()
            if key_lower in res_headers:
                security_score += 1
                headers_report.append(f"✅ {desc}: Presente")
            else:
                headers_report.append(f"❌ {desc}: MANCANTE")
        
        # Analisi Server Header
        if "server" in res_headers:
            headers_report.append(f"⚠️ Server Info Leaked: {res_headers['server']}")
        else:
            security_score += 1 
            headers_report.append(f"✅ Server Info: Nascosto (Good Practice)")
            
        return security_score, headers_report

    except Exception as e:
        return 0, [f"Errore Analisi Headers: {str(e)}"]

def analizza_robots(target):
    """
    Scarica e analizza il file robots.txt per cercare path sensibili nascosti.
    """
    parsed = urllib.parse.urlparse(target if "://" in target else "https://" + target)
    host = parsed.netloc
    
    robots_path = []
    
    try:
        conn = http.client.HTTPSConnection(host, timeout=5)
        conn.request("GET", "/robots.txt", headers={"User-Agent": "Mozilla/5.0 SecurityScanner/2.0"})
        res = conn.getresponse()
        
        if res.status == 200:
            content = res.read().decode('utf-8', errors='ignore')
            lines = content.split('\n')
            
            for line in lines:
                line = line.strip()
                # Cerchiamo direttive 'Disallow' che spesso nascondono cartelle admin/private
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        robots_path.append(path)
        
        conn.close()
        # Filtriamo duplicati e teniamo i primi 10 risultati interessanti
        return list(set(robots_path))[:10]

    except Exception:
        return None
