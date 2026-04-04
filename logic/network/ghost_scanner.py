import random
import time
from logic.network.port_scanner import ottieni_ip, _scan_single_port

def scansione_porte_ghost(target, range_porte, callback_progress=None, stop_event=None, jitter_range=(0.7, 2.2)):
    """
    Esegue una scansione Stealth 'GHOST MODE'.
    - Ordine casuale delle porte (Shuffle)
    - Singolo thread (Sequenziale)
    - Jitter adattivo tra ogni porta
    """
    clean_host = target.strip().replace("https://", "").replace("http://", "").split("/")[0]
    ip = ottieni_ip(target)
    if not ip: return [("Errore", "Host non trovato", "", False)], 0

    if isinstance(range_porte, list):
        lista_porte = list(range_porte)
    else:
        start, end = range_porte
        lista_porte = list(range(start, end + 1))

    # COLLO DI BOTTIGLIA: Rimescolamento casuale per eludere le firme dei bot
    random.shuffle(lista_porte)
    
    totale = len(lista_porte)
    risultati = []
    totale_scansionati = 0

    for index, porta in enumerate(lista_porte):
        # Controllo interruzione manuale
        if stop_event and stop_event.is_set():
            break
            
        totale_scansionati += 1
        
        # PROBING CHIRURGICO (Sequenziale)
        res = _scan_single_port(ip, porta, clean_host, stop_event=stop_event)
        if res:
            risultati.append(res)
            
        # FEEDBACK PROGRESSO
        if callback_progress:
            callback_progress(index + 1, totale, porta)
            
        # ADAPTIVE JITTER: Simula il respiro umano tra una porta e l'altra
        if index < totale - 1: # Non aspettare dopo l'ultima porta
            tempo_attesa = random.uniform(jitter_range[0], jitter_range[1])
            # Piccoli step per permettere l'interruzione immediata anche durante la pausa
            step = 0.5
            attesa_residua = tempo_attesa
            while attesa_residua > 0:
                if stop_event and stop_event.is_set(): break
                time.sleep(min(step, attesa_residua))
                attesa_residua -= step

    # Riordina i risultati per il report
    risultati.sort(key=lambda x: x[0])
    return risultati, totale_scansionati
