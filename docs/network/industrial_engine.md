# Motore Industriale: High-Speed Precision (Industrial Engine)

Il **Motore Industriale** è il cuore pulsante del toolkit per quanto riguarda la velocità di esecuzione. Progettato per audit su vasta scala, combina il parallelismo massivo con una logica di verifica rigorosa.

## ⚙️ Architettura Multi-Thread
Il toolkit utilizza un `ThreadPoolExecutor` (default 50 workers) per interrogare centinaia di porte contemporaneamente.
- **Vantaggio**: Scansione di interi range di porte in pochi secondi.
- **Sfida**: La velocità spesso causa falsi positivi o mancate risposte. 
- **Soluzione**: Gestione adattiva dei timeout (default 0.6s) per bilanciare latenza e affidabilità.

## 🧪 Double-Handshake Verification
Il fulcro dell'accuratezza del nostro software è la tecnica del **"Doppio Riscontro"**.
1. **TCP SYN/ACK (Primo Handshake)**: Lo scanner riceve il segnale che la porta è tecnicamente "aperta".
2. **Application Probe (Secondo Handshake)**: Lo scanner invia immediatamente una richiesta applicativa (es. `HEAD / HTTP/1.1`) per leggere il **Banner** del servizio.
   - **Scenario Real-Open**: Se il servizio risponde con un banner valido (es. `nginx/1.18.0`), la porta viene marcata come `VERIFIED`.
   - **Scenario Firewall-Ghost**: Se la porta risulta aperta ma non risponde ad alcuna interrogazione applicativa, viene marcata come `STEALTH/SILENT`.

### 🛡️ Perché il Double-Handshake?
I moderni Firewall spesso tentano di ingannare gli scanner rispondendo "Aperto" a tutte le porte (TCP SYN flood). Senza il nostro secondo livello di verifica, l'auditor riceverebbe un report inutile pieno di falsi positivi. **Il nostro toolkit filtra il rumore e mostra solo la verità.**

## 🧠 Intelligence dei Rischi
Integrato nel motore c'è il modulo `constants.py` che assegna automaticamente un livello di rischio (Verde, Giallo, Rosso) basandosi sul servizio verificato.
- **Esempio**: Un servizio Telnet (23) o FTP (21) in chiaro riceve immediatamente un'allerta rossa, indipendentemente dalla velocità dello scan.

---
> **Security Note**: Il Motore Industriale è la scelta ideale quando il fattore tempo è critico, ma l'accuratezza non può essere compromessa.
