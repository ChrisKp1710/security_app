# Security Toolkit Pro - Bug Report & Fix Requirements

> Documento tecnico per AI agent. Ogni task e' autonomo e include file, riga, problema, e fix esatto richiesto.

---

## TASK 1 - CRITICO: Import mancante `get_ssl_details`

- **File**: `gui/dashboard.py`
- **Riga problema**: 620
- **Sintomo**: `NameError: name 'get_ssl_details' is not defined` quando si clicca il bottone "SSL"
- **Causa**: La funzione `get_ssl_details` e' definita in `logic/ssl_inspector.py:6` ma non viene importata nel dashboard
- **Fix richiesto**: Aggiungere alla riga 12 (dopo l'import di `web_recon`) la seguente riga:
  ```python
  from logic.ssl_inspector import get_ssl_details
  ```

---

## TASK 2 - CRITICO: Crash `math.log2(0)` su password di soli spazi

- **File**: `logic/password_strength.py`
- **Righe problema**: 9-10 e 22
- **Sintomo**: `ValueError: math domain error` quando l'utente digita una password composta solo da spazi (es. `"   "`)
- **Causa**: Il guard alla riga 9 (`if not password`) non cattura stringhe di soli spazi (in Python `not "   "` e' `False`). Lo spazio (chr 32) non rientra in nessuna delle 4 categorie a righe 14-17 (`ascii_lowercase`, `ascii_uppercase`, `digits`, `punctuation`), quindi `pool_size` resta 0. Alla riga 22, `math.log2(0)` crasha.
- **Fix richiesto**: Sostituire la riga 9-10 con:
  ```python
  if not password or not password.strip():
      return 0, "N/A", "Empty", "#EF4444", 0.0
  ```
  Nota: il return deve avere **5 valori** (non 4 come adesso), perche' `dashboard.py:513` fa unpack di 5 variabili: `bits, time_str, score, color, progress_val = calcola_robustezza(pwd)`. Il quinto valore `0.0` e' il progress bar value.

---

## TASK 3 - CRITICO: Path senza `/` nella wordlist

- **File**: `deep_wordlist.txt`
- **Tutte le righe** (2-127, escludendo commenti)
- **Sintomo**: Le richieste HTTP vanno come `HEAD admin HTTP/1.1` invece di `HEAD /admin HTTP/1.1`, causando errori 400 Bad Request
- **Causa**: I path nella wordlist non hanno il prefisso `/`. Il `dir_finder.py:77` fa `conn.request("HEAD", path, ...)` che richiede il path con slash iniziale.
- **Fix richiesto**: Due opzioni (sceglierne UNA):
  - **Opzione A** (consigliata): Modificare `logic/dir_finder.py` riga 20 per normalizzare i path letti dal file:
    ```python
    wordlist = [line.strip() if line.strip().startswith("/") else "/" + line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    ```
    Nota: questo fix deve anche **filtrare le righe di commento** (che iniziano con `#`), altrimenti path come `# Common Admin Interfaces` verrebbero scansionati.
  - **Opzione B**: Aggiungere `/` a ogni riga non-commento di `deep_wordlist.txt`

---

## TASK 4 - ALTO: Vulnerabilita' XSS nei report HTML

- **File**: `logic/report_generator.py`
- **Righe problema**: 130, 140, 146, 152
- **Sintomo**: Un server target malevolo puo' iniettare codice JavaScript nei report HTML tramite banner di servizio o path di redirect
- **Causa**: I dati provenienti dalla rete (`s['service']`, `h`, `r`, `d`) sono inseriti direttamente nell'HTML con f-string senza escaping
- **Fix richiesto**: Aggiungere `import html` in cima al file (dopo riga 3), poi applicare `html.escape()` a tutti i valori dinamici nelle 4 righe:
  - Riga 130: `{html.escape(s['service'])}` al posto di `{s['service']}`
  - Riga 108: `{html.escape(str(data['target']))}` al posto di `{data['target']}`
  - Riga 140: `{html.escape(h)}` al posto di `{h}`
  - Riga 146: `{html.escape(r)}` al posto di `{r}`
  - Riga 152: `{html.escape(d)}` al posto di `{d}`

---

## TASK 5 - ALTO: Worker cracker muore silenziosamente

- **File**: `logic/cracker.py`
- **Riga problema**: 25-30
- **Sintomo**: Se il file ZIP non e' valido o e' vuoto, il worker processo fa `return` senza mettere nulla nella queue. La GUI in `dashboard.py:420` controlla `if not any(p.is_alive() ...)` per uscire dal loop, ma nel frattempo non riceve nessun messaggio e resta appesa fino a quando tutti i processi terminano senza feedback.
- **Fix richiesto**: Sostituire il blocco righe 25-30 con:
  ```python
  try:
      zf = zipfile.ZipFile(zip_path)
      first_file = zf.namelist()[0]
  except Exception:
      queue.put(("error", "Invalid or empty ZIP file"))
      return
  ```
  Poi in `dashboard.py`, nel metodo `bg_cracker_loop` (dopo riga 415), aggiungere la gestione del messaggio "error":
  ```python
  elif msg[0] == "error":
      self.after(0, lambda m=msg[1]: self.log(f"Worker Error: {m}", "DANGER"))
  ```

---

## TASK 6 - MEDIO: Riga duplicata in `gestisci_hash`

- **File**: `gui/dashboard.py`
- **Righe problema**: 668-670
- **Sintomo**: Nessun crash, ma la stessa operazione viene eseguita due volte inutilmente
- **Codice attuale**:
  ```python
  self.lbl_hash_res.configure(text=res_text, text_color=color)

  self.lbl_hash_res.configure(text=res_text, text_color=color)
  ```
- **Fix richiesto**: Rimuovere la riga 670 (la seconda copia) e la riga vuota 669.

---

## TASK 7 - MEDIO: Bare `except:` senza `Exception`

- **File**: `logic/port_scanner.py`
- **Righe problema**: 57, 115, 126
- **Sintomo**: `except:` nudo cattura TUTTO, inclusi `KeyboardInterrupt` e `SystemExit`. Questo impedisce di terminare il programma con Ctrl+C durante una scansione.
- **Fix richiesto**: Sostituire ogni `except:` con `except Exception:` nelle 3 righe indicate.

Stesso problema in:
- **File**: `logic/cracker.py`
- **Riga problema**: 29
- **Fix richiesto**: Sostituire `except:` con `except Exception:` (gia' coperto nel TASK 5 sopra).

---

## TASK 8 - MEDIO: `check.txt` con dati sensibili nel repository

- **File**: `check.txt` (root del progetto)
- **Contenuto**: `secret data`
- **Sintomo**: File di test con dati placeholder committato nel repo pubblico
- **Fix richiesto**: Rimuovere il file dal repository con `git rm check.txt` e aggiungere `check.txt` al `.gitignore`.

---

## TASK 9 - MEDIO: `start_attack()` codice morto nel cracker

- **File**: `logic/cracker.py`
- **Righe problema**: 107-136
- **Sintomo**: Il metodo `start_attack` ha 30 righe di codice + commenti ma termina con `pass` alla riga 136. Non fa nulla. Non e' chiamato da nessuna parte (il dashboard usa `start_length_attack`).
- **Fix richiesto**: Rimuovere tutto il metodo `start_attack` (righe 107-136). Oppure, se si vuole mantenerlo come entry point semplificato, implementarlo come wrapper che chiama `start_length_attack` in loop.

---

## TASK 10 - MEDIO: File temporaneo `target_hash.txt` mai rimosso

- **File**: `logic/gpu_bridge.py`
- **Riga problema**: 18-20
- **Sintomo**: Ogni volta che si lancia un GPU attack, viene creato `target_hash.txt` nella current working directory e non viene mai cancellato.
- **Fix richiesto**: Aggiungere cleanup con `try/finally` dopo la chiusura del processo (dopo riga 83):
  ```python
  finally:
      if os.path.exists(hash_file):
          os.remove(hash_file)
  ```
  Oppure usare `tempfile.NamedTemporaryFile` al posto del file hardcoded.

---

## TASK 11 - MEDIO: Thread safety su `report_data`

- **File**: `gui/dashboard.py`
- **Righe problema**: 594-596 (`thread_recon`) e 554-559 (`mostra_risultati_scan`)
- **Sintomo**: `self.report_data` viene modificato da thread background (es. `thread_recon` a riga 595-596 scrive `self.report_data["recon"]` direttamente) senza lock. Se l'utente preme "EXPORT" mentre il recon e' in corso, i dati potrebbero essere in stato inconsistente.
- **Fix richiesto**: Aggiungere un `threading.Lock()` nell'`__init__` della classe:
  ```python
  self._data_lock = threading.Lock()
  ```
  E wrappare ogni accesso a `self.report_data` nei thread con:
  ```python
  with self._data_lock:
      self.report_data["recon"]["score"] = score
      self.report_data["recon"]["headers"] = report
  ```

---

## TASK 12 - BASSO: Versione inconsistente

- **File**: `gui/dashboard.py`
- **Righe problema**: 36 e 74
- **Sintomo**: Il titolo della finestra (riga 36) dice `v5.1`, la sidebar (riga 74) dice `v5.0`, il report HTML in `report_generator.py:157` dice `v5.0`
- **Fix richiesto**: Definire una costante `APP_VERSION = "5.1"` in cima a `dashboard.py` e usarla in tutte e 3 le posizioni. Aggiornare anche `report_generator.py:157`.

---

## TASK 13 - BASSO: `format_time` mostra "secoli" ma calcola anni

- **File**: `logic/password_strength.py`
- **Riga problema**: 63
- **Codice attuale**: `return f"{int(seconds/31536000)} secoli"`
- **Causa**: `seconds / 31536000` produce anni, non secoli. Un secolo = 100 anni.
- **Fix richiesto**: Sostituire con:
  ```python
  if seconds < 31536000 * 100000: return f"{int(seconds / (31536000 * 100))} secoli"
  ```

---

## TASK 14 - BASSO: Chiave `21` duplicata in `RISCHIO_PORTE`

- **File**: `logic/port_scanner.py`
- **Riga problema**: 4-5
- **Codice attuale**: `21: "ROSSO", 23: "ROSSO", 80: "VERDE", 443: "VERDE", 3306: "ROSSO", 3389: "ROSSO", 8080: "GIALLO", 22: "GIALLO", 21: "ROSSO", 25: "GIALLO"`
- **Causa**: La chiave `21` appare due volte. Python non da errore ma usa solo l'ultimo valore.
- **Fix richiesto**: Rimuovere la seconda occorrenza di `21: "ROSSO"`. Aggiungere anche le porte mancanti che sono nella lista Quick Scan di `dashboard.py:539` ma non nel dizionario: `23`, `25`, `53`, `110`, `139`, `445`, `8443`.

---

## TASK 15 - BASSO: `requirements.txt` include `requests` inutilizzato

- **File**: `requirements.txt`
- **Riga problema**: 2
- **Sintomo**: Il pacchetto `requests` e' elencato come dipendenza ma nessun file del progetto lo importa. Tutte le chiamate HTTP usano `http.client` (stdlib).
- **Fix richiesto**: Rimuovere `requests` dal file. Il contenuto corretto e':
  ```
  customtkinter
  ```

---

## TASK 16 - BASSO: Socket non chiuso in caso di errore in `ssl_inspector.py`

- **File**: `logic/ssl_inspector.py`
- **Righe problema**: 18 e 55
- **Causa**: Il socket wrappato (`conn`) viene creato a riga 18, ma `conn.close()` e' solo dentro il `try` (riga 26). Se `connect` fallisce (riga 22), l'except a riga 55 non chiude il socket.
- **Fix richiesto**: Spostare `conn.close()` in un blocco `finally`:
  ```python
  try:
      conn.connect((hostname, 443))
      ...
  except Exception as e:
      return {"status": "error", "message": str(e)}
  finally:
      conn.close()
  ```

---

## RIEPILOGO PRIORITA'

| # | Priorita' | File | Descrizione |
|---|-----------|------|-------------|
| 1 | CRITICO | dashboard.py | Import `get_ssl_details` mancante |
| 2 | CRITICO | password_strength.py | Crash `log2(0)` + return 4 valori invece di 5 |
| 3 | CRITICO | deep_wordlist.txt / dir_finder.py | Path senza `/` + commenti non filtrati |
| 4 | ALTO | report_generator.py | XSS injection nei report HTML |
| 5 | ALTO | cracker.py + dashboard.py | Worker muore senza notificare la GUI |
| 6 | MEDIO | dashboard.py:668-670 | Riga duplicata `gestisci_hash` |
| 7 | MEDIO | port_scanner.py + cracker.py | Bare `except:` senza `Exception` |
| 8 | MEDIO | check.txt | File con dati sensibili nel repo |
| 9 | MEDIO | cracker.py:107-136 | Metodo `start_attack()` vuoto |
| 10 | MEDIO | gpu_bridge.py:18-20 | File temporaneo mai rimosso |
| 11 | MEDIO | dashboard.py | Thread safety su `report_data` |
| 12 | BASSO | dashboard.py + report_generator.py | Versione inconsistente |
| 13 | BASSO | password_strength.py:63 | "secoli" mostra anni |
| 14 | BASSO | port_scanner.py:4-5 | Chiave `21` duplicata |
| 15 | BASSO | requirements.txt | `requests` non usato |
| 16 | BASSO | ssl_inspector.py | Socket non chiuso su errore |
