import secrets
import string

def genera_password(lunghezza=12):
    """
    Genera una password crittograficamente sicura.
    Usa il modulo 'secrets' (CSPRNG) invece di 'random' per garantire imprevedibilità.
    """
    if lunghezza < 8:
        lunghezza = 8  # Enforce minimum length for security
        
    caratteri = string.ascii_letters + string.digits + string.punctuation
    # secrets.choice è l'equivalente sicuro di random.choice
    password = "".join(secrets.choice(caratteri) for i in range(lunghezza))
    return password
