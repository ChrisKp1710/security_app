import multiprocessing
import zipfile
import itertools
import string
import time
import os

# Definiamo i caratteri possibili
CHARS_NUM = string.digits
CHARS_ALPHA_LOWER = string.ascii_lowercase
CHARS_ALPHA_MIX = string.ascii_letters
CHARS_FULL = string.ascii_letters + string.digits + string.punctuation

class CrackResult:
    def __init__(self, password=None, attempts=0, time_elapsed=0):
        self.password = password
        self.attempts = attempts
        self.time_elapsed = time_elapsed

def worker_crack(zip_path, charset, length, start_index, chunk_size, queue, stop_event):
    """
    Worker che gira su un processo separato.
    Analizza un 'chunk' specifico di combinazioni per una data lunghezza.
    """
    try:
        zf = zipfile.ZipFile(zip_path)
        # Ottimizzazione: proviamo ad aprire solo il primo file per testare la pwd
        first_file = zf.namelist()[0]
    except:
        return

    count = 0
    # Generatore di combinazioni (itertools è ottimizzato in C)
    iterator = itertools.product(charset, repeat=length)
    
    # Saltiamo fino al nostro chunk (Fast Forward)
    # Nota: itertools.islice sarebbe meglio ma per distribuire il carico
    # su indici numerici precisi bisogna fare un po' di matematica.
    # Per semplicità in questo worker, assumiamo che 'start_index' e 'chunk_size' 
    # siano gestiti dividendo lo spazio ALPHA.
    
    # STRATEGIA PRO: Divisione per lettera iniziale
    # Ogni worker si prende un set di lettere iniziali.
    # Esempio: Worker 1 fa pass che iniziano per 'a', Worker 2 per 'b'...
    
    # Qui implementiamo la logica pura passata dal manager per semplicità: 
    # iteriamo su tutto il charset nel range assegnato (start_char_idx -> end_char_idx)
    
    # Recuperiamo gli indici del charset globale
    base_iterator = itertools.product(charset, repeat=length-1) # Tutte le combo tranne la prima lettera
    
    # Il worker deve prefissare con le lettere del suo chunk
    my_prefixes = charset[start_index : start_index + chunk_size]
    
    for prefix in my_prefixes:
        # Se qualcuno ha già trovato la password, fermati
        if stop_event.is_set():
            return

        # Per ogni prefisso assegnato, proseguiamo con tutte le combinazioni del resto
        # Ricreiamo l'iteratore base per ogni prefisso per essere safe
        base_iterator = itertools.product(charset, repeat=length-1)
        
        for suffix_tuple in base_iterator:
            if stop_event.is_set(): return
            
            # Costruiamo la password
            # ''.join è veloce, ma bytes è meglio per zipfile
            candidate = (prefix + ''.join(suffix_tuple))
            candidate_bytes = candidate.encode('utf-8')
            
            count += 1
            if count % 5000 == 0:
                # Notifica progressi ogni 5000 tentativi (meno overhead)
                queue.put(("progress", 5000))
                count = 0
            
            try:
                # TENTATIVO 1: Fast Check (Leggiamo solo il primo file)
                zf.setpassword(candidate_bytes)
                zf.read(first_file)
                
                # TENTATIVO 2: Strict Check (False Positive Protection)
                # ZipCrypto ha un 1/256 di probabilità di falso positivo sull'header.
                # Se read() passa, facciamo un controllo COMPLETO dell'archivio per essere sicuri al 100%.
                # Questo rallenta solo quando "pensiamo" di aver trovato la password.
                if zf.testzip() is None:
                    # SE SIAMO QUI, è SICURAMENTE LEI!
                    stop_event.set() # Ferma tutti gli altri
                    queue.put(("found", candidate))
                    return
            except (RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile):
                # Password errata o altro errore zip
                pass
            except Exception:
                pass
                
    # Fine del lavoro assegnato
    queue.put(("progress", count)) # Flush rimanenti

class BruteForceManager:
    def __init__(self):
        self.processes = []
        self.queue = multiprocessing.Queue()
        self.stop_event = multiprocessing.Event()
    
    def start_attack(self, zip_path, charset_mode, max_length):
        """
        Avvia i processi worker.
        Restituisce il numero di core usati.
        """
        self.stop_event.clear()
        
        # Selezione Charset
        if charset_mode == "Numeric (0-9)": charset = CHARS_NUM
        elif charset_mode == "Alpha Lower (a-z)": charset = CHARS_ALPHA_LOWER
        elif charset_mode == "Alpha Mix (a-zA-Z)": charset = CHARS_ALPHA_MIX
        else: charset = CHARS_FULL
        
        cpu_count = multiprocessing.cpu_count()
        # Riserviamo 1 core per la GUI se possibile, altrimenti usiamo tutto
        workers_count = max(1, cpu_count - 1)
        
        # Stima del workload
        # Assegniamo le lettere iniziali ai worker.
        # Es: charset di 10 caratteri, 2 worker -> W1: 0-5, W2: 5-10
        chars_len = len(charset)
        chunk_size = max(1, chars_len // workers_count)
        
        # Facciamo partire i job per ogni lunghezza (incremental brute force)
        # NOTA: Per semplicità didattica, qui lanciamo solo la lunghezza MAX.
        # In un tool vero faremmo un loop 1..max_length gestito esternamente.
        # Qui assumiamo che l'utente sappia la lunghezza o che lo modifichiamo dopo.
        # MODIFICA: Implementiamo loop interno o esterno? Esterno è meglio per update GUI.
        # Facciamo che questa func lancia solo UNA lunghezza specifica.
        pass

    def start_length_attack(self, zip_path, charset_mode, length):
        self.stop_event.clear()
        
        # Selezione Charset
        if charset_mode == "Numeric (0-9)": charset = CHARS_NUM
        elif charset_mode == "Alpha Lower (a-z)": charset = CHARS_ALPHA_LOWER
        elif charset_mode == "Alpha Mix (a-zA-Z)": charset = CHARS_ALPHA_MIX
        else: charset = CHARS_FULL # Full
        
        cpu_count = multiprocessing.cpu_count()
        workers_count = max(1, cpu_count) # Usiamo tutto il power
        
        chars_len = len(charset)
        chunk_size = (chars_len // workers_count) + 1
        
        self.processes = []
        
        for i in range(workers_count):
            start_index = i * chunk_size
            if start_index >= chars_len: break
            
            # Calibrazione fine chunk
            real_chunk = min(chunk_size, chars_len - start_index)
            
            p = multiprocessing.Process(
                target=worker_crack,
                args=(zip_path, charset, length, start_index, real_chunk, self.queue, self.stop_event)
            )
            p.daemon = True # Se il main muore, muoiono anche loro
            p.start()
            self.processes.append(p)
            
        return len(self.processes)

    def stop_attack(self):
        self.stop_event.set()
        for p in self.processes:
            p.terminate()
