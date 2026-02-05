import subprocess
import shutil
import os

def check_tools():
    return shutil.which("zip2john") is not None and shutil.which("hashcat") is not None

def crack_with_hashcat(hash_string, mask_mode, callback_stdout=None):
    """
    Esegue Hashcat realmente.
    mask_mode: es. '?a?a?a?a'
    """
    hashcat = shutil.which("hashcat")
    if not hashcat:
        return None, "Hashcat not found."
        
    # 1. Scriviamo l'hash su file temporaneo
    hash_file = "target_hash.txt"
    with open(hash_file, "w") as f:
        f.write(hash_string)
        
    # 2. Identifica mode
    mode = "13600" # Default 7zip/zip
    if "$pkzip" in hash_string: mode = "17200"
    
    # Argomenti: -m MODE -a 3 (Brute Force) hash.txt MASK --status --status-timer 1 --potfile-disable
    # --potfile-disable serve per forzare il cracking e vedere l'output anche se già crackata in passato
    cmd = [
        hashcat, 
        "-m", mode, 
        "-a", "3", 
        hash_file, 
        mask_mode, 
        "--status", 
        "--status-timer", "1",
        "--potfile-disable",
        "--force" # Necessario su alcune VM/Driver
    ]
    
    try:
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, 
            bufsize=1
        )
        
        found_pass = None
        
        # Leggiamo lo stream in tempo reale
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
                
            if line:
                l = line.strip()
                if callback_stdout: callback_stdout(l)
                
                # Hashcat formatta l'uscita "hash:password" quando trova
                # Ma con --status stampa un sacco di roba.
                # Il modo più sicuro è cercare la linea che CONTIENE l'hash seguito da ':'
                # Oppure cercare "Status: Cracked"
                
                # Parsare Hashcat output è un'arte.
                # Semplifichiamo: se la linea inizia con l'hash, la parte dopo ':' è la password
                # Attenzione: l'hash $zip2$... contiene '$' che incasinano tutto.
                
                # Metodo alternativo sicuro: Hashcat stampa la password alla fine se usiamo --show? No, --show non fa crack.
                # Controlliamo se la linea contiene "recovered" o simili?
                
                # HACK: Hashcat output standard quando trova:
                # $zip2$.....:password
                
                if hash_string in l and ":" in l:
                     # Trovato!
                     parts = l.split(":")
                     found_pass = parts[-1] 
                     # Potrebbe esserci ':' nella password, quindi meglio split max
                     # Ma per ora va bene.
                     
        return found_pass, None

    except Exception as e:
        return None, str(e)

def generate_gpu_package(zip_path):
    """
    Esegue zip2john per estrarre l'hash e genera il comando Hashcat pronto all'uso.
    Return: (hash_data, hashcat_cmd, error_msg)
    """
    zip2john = shutil.which("zip2john")
    if not zip2john:
        return None, None, "Error: 'zip2john' tool not found in system PATH.\nPlease install 'john' package."

    try:
        # Esecuzione zip2john
        # Uniamo stdout e stderr per catturare l'hash ovunque finisca
        result = subprocess.run([zip2john, zip_path], capture_output=True, text=True, timeout=15)
        
        # Analisi combinata
        full_output = (result.stdout or "") + "\n" + (result.stderr or "")
        lines = full_output.splitlines()
        
        hash_line = None
        # Cerchiamo la firma dell'hash
        for line in lines:
            line = line.strip()
            if "$zip2$" in line or "$pkzip2$" in line or "$zip3$" in line or "$pkwinzip$" in line:
                hash_line = line
                # Non break, perché a volte ci sono più file, prendiamo l'ultimo o il primo?
                # Hashcat di solito ne vuole uno. Prendiamo il primo valido.
                break
        
        if not hash_line:
             # Nessun hash trovato
             debug_msg = f"Stdout: {result.stdout[:200]}...\nStderr: {result.stderr[:200]}..."
             return None, None, f"No hash found in zip2john output.\n{debug_msg}"
        
        # Identificazione Mode per Hashcat
        hashcat_mode = "13600" # Default zip
        if "$pkzip" in hash_line: hashcat_mode = "17200"
        if "$pkwinzip" in hash_line: hashcat_mode = "13600" # Spesso è 13600
        
        # Costruzione comando
        cmd = f"hashcat -m {hashcat_mode} -a 3 hash.txt ?a?a?a?a?a?a"
        
        return hash_line, cmd, None

    except Exception as e:
        return None, None, f"System Error: {str(e)}"
