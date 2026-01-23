import random
import string

def genera_password(lunghezza=12):
    """Genera una password sicura con lettere, numeri e simboli."""
    caratteri = string.ascii_letters + string.digits + string.punctuation
    password = "".join(random.choice(caratteri) for i in range(lunghezza))
    return password
