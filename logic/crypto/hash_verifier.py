import hashlib

def calcola_hash_file(percorso_file):
    """Calcola l'impronta digitale (SHA-256) di un file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(percorso_file, "rb") as f:
            # Legge il file a piccoli pezzi per non rallentare il Mac
            for block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(block)
        return sha256_hash.hexdigest()
    except Exception as e:
        return f"Errore: {str(e)}"
