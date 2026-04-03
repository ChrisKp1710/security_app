import http.client
import urllib.parse
import random
import string

# User-Agent realistico per evitare blocchi/stripping dai WAF (Cloudflare, etc.)
REAL_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def analizza_headers(target):
    """
    Analizza gli header di sicurezza HTTP, seguendo i redirect (max 3 hop) con UA reale.
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
        current_host = host
        current_path = path
        res_headers = {}

        for _ in range(max_redirects + 1):
            conn = http.client.HTTPSConnection(current_host, timeout=5)
            conn.request("HEAD", current_path, headers={"User-Agent": REAL_UA})
            res = conn.getresponse()
            res_headers = {k.lower(): v for k, v in res.getheaders()}
            conn.close()
            
            if res.status in [301, 302, 307, 308]:
                location = res_headers.get('location')
                if location:
                    new_parsed = urllib.parse.urlparse(location)
                    if new_parsed.netloc: current_host = new_parsed.netloc
                    current_path = new_parsed.path if new_parsed.path else "/"
                    continue
            break

        for header_key, desc in checks.items():
            if header_key.lower() in res_headers:
                security_score += 1
                headers_report.append(f"✅ {desc}: Presente")
            else:
                headers_report.append(f"❌ {desc}: MANCANTE")
        
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
    Analizza robots.txt con UA reale per evitare 403/Forbidden.
    """
    parsed = urllib.parse.urlparse(target if "://" in target else "https://" + target)
    host = parsed.netloc
    robots_path = []
    
    try:
        conn = http.client.HTTPSConnection(host, timeout=5)
        conn.request("GET", "/robots.txt", headers={"User-Agent": REAL_UA})
        res = conn.getresponse()
        
        if res.status == 200:
            content = res.read().decode('utf-8', errors='ignore')
            for line in content.split('\n'):
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/": robots_path.append(path)
        
        conn.close()
        return list(set(robots_path))[:10]
    except Exception: return None

def analizza_verbi_http(target):
    """
    Testa i verbi HTTP con Canary Check per evitare falsi positivi di PUT/DELETE.
    """
    if not target.startswith("http"): target = "https://" + target
    parsed = urllib.parse.urlparse(target)
    host = parsed.netloc
    report = []
    
    try:
        conn = http.client.HTTPSConnection(host, timeout=5)
        # 1. Test OPTIONS
        conn.request("OPTIONS", "/", headers={"User-Agent": REAL_UA})
        res_options = conn.getresponse()
        res_options.read()
        allowed = res_options.getheader("Allow") or res_options.getheader("Public")
        report.append(f"ℹ️ Modalità HTTP consentite: {allowed}" if allowed else "ℹ️ Nessun header 'Allow' fornito via OPTIONS.")

        # 2. Test TRACE
        xst_payload = "XST-VERIFY-" + "".join(random.choices(string.ascii_letters, k=8))
        conn.request("TRACE", "/", headers={"User-Agent": REAL_UA, "X-Verify": xst_payload})
        res_trace = conn.getresponse()
        trace_body = res_trace.read().decode('utf-8', errors='ignore')
        if res_trace.status == 200 and xst_payload in trace_body:
            report.append("❌ CRITICO: HTTP TRACE abilitato (Rischio XST).")
        else:
            report.append("✅ HTTP TRACE è disabilitato/sicuro.")

        # 3. Test PUT (CANARY TEST ANTI-WAF)
        canary_filename = "/sec_audit_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12)) + ".txt"
        conn.request("PUT", canary_filename, body="audit_verify", headers={"User-Agent": REAL_UA})
        res_put = conn.getresponse()
        res_put.read()
        
        if res_put.status in [200, 201, 204]:
            # Proviamo a verificare se il file esiste davvero (Canary GET)
            conn.request("GET", canary_filename, headers={"User-Agent": REAL_UA})
            res_verify = conn.getresponse()
            res_verify.read()
            if res_verify.status == 200:
                report.append(f"❌ CRITICO: HTTP PUT VULNERABILE! File creato: {canary_filename}")
            else:
                report.append("✅ HTTP PUT: Falso positivo rilevato (Cloudflare/WAF deception).")
        elif res_put.status in [401, 403]:
            report.append("⚠️ HTTP PUT: Bloccato (401/403).")
        else:
            report.append("✅ HTTP PUT correttamente bloccato.")

        conn.close()
        return report
    except Exception as e:
        return [f"Errore Analisi Verbi: {str(e)}"]
