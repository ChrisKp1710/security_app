# Gestione Dati e Reportistica (Persistence & Export)

L'affidabilità di un toolkit di sicurezza non si misura solo dalla scansione, ma da come i dati vengono salvati, protetti e presentati.

## 🧠 1. SettingsManager (Persistenza)
Il modulo `settings_manager.py` gestisce il ciclo di vita delle configurazioni dell'applicazione.
- **Logica**: Utilizziamo un formato JSON standard (`settings.json`) per memorizzare le preferenze dell'utente (target di default, timeout, charset per il cracking).
- **Integrità**: Il gestore utilizza un metodo di **Recursive Update**. Ciò significa che se una nuova versione del software aggiunge nuovi campi di default, questi vengono integrati senza cancellare le vecchie impostazioni dell'utente.
- **Robustezza**: In caso di file di configurazione corrotto, il toolkit ripristina automaticamente i valori di fabbrica per garantire l'avvio del software.

## 📊 2. ReportExporter (Audit Output)
Il motore di esportazione (`report_exporter.py`) trasforma i dati tecnici grezzi in documenti pronti per il cliente finale.

### ✨ Esportazione HTML Interattiva
- **Design Professionale**: Utilizziamo un layout a griglia CSS sofisticato con tonalità di colore coordinate al rischio (Verde per SUCCESS, Giallo per WARNING, Rosso per DANGER).
- **Trasparenza**: Ogni report include i metadati dell'audit (Target, Versione della Suite, Timestamp) per garantire la tracciabilità delle operazioni.
- **Inclusione Risorse**: Il report HTML integra le risorse estetiche internamente, rendendolo un file autonomo che può essere inviato via email senza perdere lo stile.

### 🧱 Esportazione JSON & TXT
- **JSON**: Pensato per l'integrazione con altri tool di sicurezza o per l'importazione in database di gestione vulnerabilità.
- **TXT (ASCII Art)**: Mantiene l'estetica "Hacker/Cyber" della console, ideale per un riepilogo rapido o per l'archiviazione in log testuali.

---
> **Expert Note**: La separazione tra la logica di analisi e la logica di export garantisce che il toolkit possa essere esteso con nuovi formati (es. PDF o XML) con il minimo sforzo.
