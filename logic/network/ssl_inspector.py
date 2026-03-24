import ssl
import socket
import datetime
from urllib.parse import urlparse

def get_ssl_details(target):
    """
    Analizza il certificato SSL del target per estrarre informazioni di Intelligence.
    Focus su SANs (Subdomains) e Validità.
    """
    # Pulizia target
    if "://" in target:
        hostname = urlparse(target).netloc
    else:
        hostname = target.split("/")[0]
        
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    conn.settimeout(5.0)

    try:
        conn.connect((hostname, 443))
        cert = conn.getpeercert()
        cipher = conn.cipher()
        protocol = conn.version()
        conn.close()
        
        # Estrazione Dati
        subject = dict(x[0] for x in cert['subject'])
        issuer = dict(x[0] for x in cert['issuer'])
        not_after_str = cert['notAfter']
        
        # Parsing Data Scadenza
        # Formato tipico: 'May 24 12:00:00 2026 GMT'
        expiry_date = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
        days_left = (expiry_date - datetime.datetime.now()).days
        
        # Estrazione SANs (Subject Alternative Names) - GOLD MINE per Recon
        sans = []
        if 'subjectAltName' in cert:
            sans = [x[1] for x in cert['subjectAltName'] if x[0] == 'DNS']

        return {
            "status": "success",
            "hostname": hostname,
            "issuer": issuer.get('organizationName', 'Unknown Issuer'),
            "subject": subject.get('commonName', 'Unknown Subject'),
            "expiry": expiry_date.strftime('%Y-%m-%d'),
            "days_left": days_left,
            "protocol": protocol,
            "cipher": cipher[0],
            "sans": sans
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }
