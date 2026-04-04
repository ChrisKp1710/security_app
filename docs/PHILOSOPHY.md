# Project Philosophy: Accuracy & Stealth over Speed

Benvenuti nel cuore tecnico del **Security Toolkit Pro**. Questo documento spiega la visione e i principi ingegneristici che guidano ogni singola riga di codice di questo progetto.

## 🛡️ Visione del Progetto
A differenza di molti scanner "brute-force" che inondano la rete di pacchetti, il nostro toolkit è stato progettato con la filosofia del **Puntatore Laser**: precisione chirurgica ed estrema discrezione.

### 🎯 1. Accuratezza vs Velocità
In ambito professionale, un falso positivo è peggio di un risultato mancante. 
- **Double-Handshake Verification**: Non ci fidiamo dello stato TCP `SYN/ACK`. Ogni porta "aperta" viene interrogata con un probe applicativo (Banner Grabbing) per confermare che dietro ci sia davvero un servizio attivo e non un inganno del firewall.
- **Cognizione di Causa**: Se il sistema rileva un comportamento sospetto (es. troppe porte aperte tutte uguali), segnala automaticamente la presenza di un Firewall Deception System (Ghosting).

### 🥷 2. L'Eredità Ghost (Stealth Protocol)
La Modalità Ghost è stata sviluppata con il principio del **"Basso Profilo"**.
- **Perché è "lenta"?**: La velocità è la firma digitale più comune dei bot e degli scanner automatici. Rallentare la scansione con l'**Adaptive Jitter** e rimescolare le porte (**Port Shuffling**) maschera il traffico come se fosse una navigazione umana legittima, rendendo il toolkit invisibile ai WAF moderni (Cloudflare, Netlify, Sucuri).
- **Integrità del Pen-Test**: Un audit silenzioso evita il blocco dell'IP dell'operatore, garantendo che l'intera ricognizione possa essere completata senza interruzioni.

## 🧱 Affidabilità Architetturale
Il toolkit segue un approccio **Modulare e Centralizzato (v6.5/v6.6)**:
- **Disaccoppiamento**: La GUI non sa come avviene la scansione, riceve solo dati verificati.
- **Single Source of Truth**: I rischi e le configurazioni sono centralizzati per evitare incoerenze nei report.

---
> **Developer Goal**: Costruire uno strumento di cui un Security Auditor possa fidarsi ciecamente, sapendo che ogni risultato mostrato a schermo è stato validato tecnicamente ai più alti standard di settore.
