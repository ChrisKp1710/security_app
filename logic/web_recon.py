import http.client
import urllib.parse

def analizza_headers(target):
    """
    Analizza gli header di sicurezza HTTP di un sito target.
    Restituisce un report dettagliato e un punteggio di sicurezza.
    """
    # Pulizia target per ottenere solo host e path base
    parsed = urllib.parse.urlparse(target if "://" in target else "https://" + target)
    host = parsed.netloc
    
    headers_report = []
    security_score = 0
    max_score = 5 # HSTS, X-Frame, X-Content, CSP, Server-Hidden
    
    # Headers critici da cercare
    checks = {
        "Strict-Transport-Security": "HSTS (HTTPS Enforced)",
        "X-Frame-Options": "Anti-Clickjacking",
        "X-Content-Type-Options": "Anti-MIME Sniffing",
        "Content-Security-Policy": "CSP (XSS Protection)",
        "Referrer-Policy": "Referrer Policy"
    }

    try:
        conn = http.client.HTTPSConnection(host, timeout=5)
        conn.request("HEAD", "/", headers={"User-Agent": "Mozilla/5.0 SecurityScanner/2.0"})
        res = conn.getresponse()
        res_headers = {k.lower(): v for k, v in res.getheaders()}
        conn.close()

        # Analisi
        for header_key, desc in checks.items():
            key_lower = header_key.lower()
            if key_lower in res_headers:
                security_score += 1
                headers_report.append(f"✅ {desc}: Presente")
            else:
                headers_report.append(f"❌ {desc}: MANCANTE")
        
        # Analisi Extra: Server Header (Information Disclosure)
        if "server" in res_headers:
            headers_report.append(f"⚠️ Server Info Leaked: {res_headers['server']}")
        else:
            security_score += 1 # Bonus se nascondono la versione del server
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
