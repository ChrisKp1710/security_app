import http.client
import urllib.parse
import random
import string

# Set completo di Header Browser (Chrome 123) per bypassare i filtri bot dei WAF
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9,it;q=0.8",
    "Connection": "close", # Forza la chiusura per evitare conflitti di stato su server rigidi
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control": "max-age=0"
}

def analizza_headers(target):
    """
    Analizza gli header di sicurezza HTTP simulando un browser reale (max 3 redirect).
    """
    if not target.startswith("http"): target = "https://" + target
    parsed = urllib.parse.urlparse(target)
    host = parsed.netloc
    path = parsed.path if parsed.path else "/"
    
    headers_report = []
    security_score = 0
    max_redirects = 3
    
    checks = {
        "Strict-Transport-Security": "HSTS (HTTPS Enforced)",
        "X-Frame-Options": "Anti-Clickjacking",
        "X-Content-Type-Options": "Anti-MIME Sniffing",
        "Content-Security-Policy": "CSP (XSS Protection)",
        "Referrer-Policy": "Referrer Policy"
    }

    try:
        curr_host, curr_path = host, path
        res_headers = {}

        for _ in range(max_redirects + 1):
            conn = http.client.HTTPSConnection(curr_host, timeout=5)
            conn.request("GET", curr_path, headers=BROWSER_HEADERS)
            res = conn.getresponse()
            res_headers = {k.lower(): v for k, v in res.getheaders()}
            res.read(1024) 
            conn.close()
            
            if res.status in [301, 302, 307, 308]:
                loc = res_headers.get('location', '')
                if loc:
                    p = urllib.parse.urlparse(loc)
                    if p.netloc: curr_host = p.netloc
                    curr_path = p.path if p.path else "/"
                    continue
            break

        for h_key, desc in checks.items():
            if h_key.lower() in res_headers:
                security_score += 1
                headers_report.append(f"✅ {desc}: Presente")
            else:
                headers_report.append(f"❌ {desc}: MANCANTE")
        
        server = res_headers.get("server", "Nascosto (Good Practice)")
        if server != "Nascosto (Good Practice)":
            headers_report.append(f"⚠️ Server Info Leaked: {server}")
        else:
            security_score += 1
            headers_report.append(f"✅ Server Info: Nascosto")
            
        return security_score, headers_report

    except Exception as e:
        return 0, [f"Errore Analisi Headers: {str(e)}"]

def analizza_robots(target):
    """
    Analizza robots.txt con Browser Headers.
    """
    parsed = urllib.parse.urlparse(target if "://" in target else "https://" + target)
    host = parsed.netloc
    paths = []
    try:
        conn = http.client.HTTPSConnection(host, timeout=5)
        conn.request("GET", "/robots.txt", headers=BROWSER_HEADERS)
        res = conn.getresponse()
        if res.status == 200:
            content = res.read().decode('utf-8', errors='ignore')
            for line in content.split('\n'):
                if line.strip().lower().startswith("disallow:"):
                    p = line.split(":", 1)[1].strip()
                    if p and p != "/": paths.append(p)
        conn.close()
        return list(set(paths))[:10]
    except Exception: return None

def _esegui_richiesta_isolata(host, method, path, body=None):
    """Esegue una singola richiesta HTTP aprendo e chiudendo la connessione."""
    try:
        conn = http.client.HTTPSConnection(host, timeout=5)
        conn.request(method, path, body=body, headers=BROWSER_HEADERS)
        res = conn.getresponse()
        data = res.read().decode('utf-8', errors='ignore')
        status = res.status
        headers = {k.lower(): v for k, v in res.getheaders()}
        conn.close()
        return status, data, headers
    except Exception as e:
        return 0, str(e), {}

def analizza_verbi_http(target):
    """
    Testa i verbi HTTP con connessioni isolate per evitare errori di stato (Request-sent).
    """
    if not target.startswith("http"): target = "https://" + target
    parsed = urllib.parse.urlparse(target)
    host = parsed.netloc
    report = []
    
    canary_body = "AUDIT-ELITE-VERIFY-007"
    canary_file = "/sec_test_" + "".join(random.choices(string.ascii_lowercase, k=10)) + ".txt"

    # 1. OPTIONS Check
    status, _, headers = _esegui_richiesta_isolata(host, "OPTIONS", "/")
    allowed = headers.get("allow") or headers.get("public")
    report.append(f"ℹ️ Modalità HTTP consentite: {allowed}" if allowed else "ℹ️ Nessun header 'Allow' fornito.")

    # 2. TRACE Check
    status, body, _ = _esegui_richiesta_isolata(host, "TRACE", "/")
    if status == 200 and canary_body in body:
        report.append("❌ CRITICO: HTTP TRACE abilitato (Rischio XST).")
    else:
        report.append("✅ HTTP TRACE è disabilitato/sicuro.")

    # 3. PUT Canary Double-Check
    status_put, _, _ = _esegui_richiesta_isolata(host, "PUT", canary_file, body=canary_body)
    
    if status_put in [200, 201, 204]:
        # Verifica reale del contenuto
        status_get, body_get, _ = _esegui_richiesta_isolata(host, "GET", canary_file)
        if status_get == 200 and canary_body in body_get:
            report.append(f"❌ CRITICO: HTTP PUT VULNERABILE! File creato: {canary_file}")
        else:
            report.append("✅ HTTP PUT: Falso positivo rilevato (WAF deception/JS Challenge).")
    elif status_put in [401, 403]:
        report.append("⚠️ HTTP PUT: Bloccato (401/403).")
    else:
        report.append("✅ HTTP PUT correttamente bloccato.")

    return report
