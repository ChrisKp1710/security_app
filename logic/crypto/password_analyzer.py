import math
import string

def calcola_robustezza(password):
    """
    Analizza la robustezza di una password calcolando l'entropia (bit)
    e stimando il tempo di cracking (Brute Force).
    """
    if not password:
        return 0, "N/A", "Empty", "#EF4444" # Rosso

    # 1. Calcolo dimensione pool di caratteri (R)
    pool_size = 0
    if any(c in string.ascii_lowercase for c in password): pool_size += 26
    if any(c in string.ascii_uppercase for c in password): pool_size += 26
    if any(c in string.digits for c in password): pool_size += 10
    if any(c in string.punctuation for c in password): pool_size += 32
    
    # 2. Calcolo Entropia (E = L * log2(R))
    # L = Lunghezza password
    lunghezza = len(password)
    entropia = lunghezza * math.log2(pool_size) if pool_size > 0 else 0
    
    # 3. Stima Tempo Cracking
    # Ipotesi: Attaccante con GPU potente (100 miliardi tentativi/sec = 10^11)
    attempts_per_sec = 100_000_000_000
    combinazioni = pool_size ** lunghezza
    seconds = combinazioni / attempts_per_sec
    
    time_str = format_time(seconds)
    
    # 4. Assegnazione Punteggio e Colore
    if entropia < 28:
        score_text = "Molto Debole"
        color = "#EF4444" # Rosso
        val = 0.2
    elif entropia < 36:
        score_text = "Debole"
        color = "#F59E0B" # Arancione
        val = 0.4
    elif entropia < 60:
        score_text = "Buona"
        color = "#3B82F6" # Blu
        val = 0.6
    elif entropia < 128:
        score_text = "Forte"
        color = "#10B981" # Verde Smeraldo
        val = 0.8
    else:
        score_text = "Inviolabile"
        color = "#8B5CF6" # Viola
        val = 1.0
        
    return int(entropia), time_str, score_text, color, val

def format_time(seconds):
    if seconds < 1: return "Istantaneo"
    if seconds < 60: return f"{int(seconds)} secondi"
    if seconds < 3600: return f"{int(seconds/60)} minuti"
    if seconds < 86400: return f"{int(seconds/3600)} ore"
    if seconds < 31536000: return f"{int(seconds/86400)} giorni"
    if seconds < 31536000 * 100: return f"{int(seconds/31536000)} anni"
    if seconds < 31536000 * 100000: return f"{int(seconds/31536000)} secoli"
    return "Eternità"
