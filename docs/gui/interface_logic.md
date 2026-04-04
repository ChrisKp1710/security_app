# Architettura dell'Interfaccia (GUI & Flow)

L'interfaccia utente del toolkit non è solo un "front-end" estetico, ma un sofisticato controller asincrono che gestisce il flusso di dati in tempo reale tra l'utente e i motori di scansione.

## 📊 1. Dashboard & Routing
L'applicazione utilizza un'architettura a **Tab-Component**, dove ogni sezione (Network, Crypto, OSINT) è un modulo indipendente.
- **Vantaggio**: Massima modularità. Se un domani vogliamo aggiungere un nuovo modulo, lo facciamo creando semplicemente un nuovo Tab senza toccare la finestra principale.
- **Integrità Estetica**: Utilizziamo CustomTkinter per garantire un look coerente e moderno, con un tema scuro professionale (`dark-blue`) che riflette la natura "Cyber" del progetto.

## 🔬 2. Gestione Asincrona (Non-Blocking UI)
Una delle sfide più grandi della scansione di rete è evitare che la finestra del software si blocchi (congelamento) durante l'attesa delle risposte del server.
- **Soluzione**: Ogni scansione viene avviata in un **Thread separato**.
- **Task Manager**: Utilizziamo un gestore di task che permette di monitorare lo stato di ogni operazione in background.
- **Interruzione Sicura**: Implementiamo un `threading.Event` (Stop Event) che permette all'utente di interrompere istantaneamente il flusso di dati di qualsiasi motore (Industrial o Ghost) senza crashare l'applicazione.

## 📄 3. Integrazione Rich (High-Fidelity Logging)
Per i log in console, il toolkit integra la libreria **Rich**.
- **Perché Rich?**: Permette di visualizzare tabelle boxate, colori ANSI e segnali visivi (Verde/Giallo/Rosso) direttamente all'interno della GUI.
- **Esperienza Utente**: Questo fornisce all'auditor un feedback immediato e leggibile, emulando l'ambiente dei migliori tool CLI (Command Line Interface), ma all'interno di un'applicazione moderna con pulsanti e grafici.

---
> **Expert Note**: Questo design asincrono garantisce che il toolkit rimanga fluido e reattivo anche quando interroga migliaia di porte contemporaneamente.
