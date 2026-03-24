import re

def identifica_hash(hash_str):
    """
    Analizza una stringa e tenta di identificare il tipo di hash.
    Restituisce una lista di possibili candidati.
    """
    hash_str = hash_str.strip()
    length = len(hash_str)
    
    candidates = []
    
    # MD5: 32 hex chars
    if length == 32 and re.match(r'^[a-fA-F0-9]{32}$', hash_str):
        candidates.append("MD5 (Very Weak)")
        candidates.append("NTLM (Windows Pwd)")
        
    # SHA-1: 40 hex chars
    elif length == 40 and re.match(r'^[a-fA-F0-9]{40}$', hash_str):
        candidates.append("SHA-1 (Weak)")
        candidates.append("MySQL v5")
        
    # SHA-256: 64 hex chars
    elif length == 64 and re.match(r'^[a-fA-F0-9]{64}$', hash_str):
        candidates.append("SHA-256 (Strong)")
        
    # SHA-512: 128 hex chars
    elif length == 128 and re.match(r'^[a-fA-F0-9]{128}$', hash_str):
        candidates.append("SHA-512 (Very Strong)")
        
    # Bcrypt: Starts with $2a$, $2b$, $2y$ - length around 60
    elif hash_str.startswith("$2") and length in [59, 60]:
        candidates.append("Bcrypt (Blowfish - Resistant)")
        
    # MD5-Crypt (Unix): Starts with $1$
    elif hash_str.startswith("$1$"):
        candidates.append("MD5-Crypt (Unix Pwd)")
        
    # SHA-256-Crypt (Unix): Starts with $5$
    elif hash_str.startswith("$5$"):
        candidates.append("SHA-256-Crypt (Unix Pwd)")
        
    # SHA-512-Crypt (Unix): Starts with $6$
    elif hash_str.startswith("$6$"):
        candidates.append("SHA-512-Crypt (Unix Pwd)")
        
    else:
        # Fallback per lunghezza
        if length == 16: candidates.append("MySQL Old / NTLM Half")
        if length == 96: candidates.append("SHA-384")

    return candidates if candidates else ["Unknown Format / Raw String"]
