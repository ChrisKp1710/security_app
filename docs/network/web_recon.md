# Masterclass: Ricognizione Web Avanzata (Web Recon)

Il toolkit non si ferma alla scansione delle porte. La sezione **Web Recon** esegue un'analisi profonda dell'infrastruttura HTTP/HTTPS del target, utilizzando tecniche di Intelligence per mappare la superficie d'attacco.

## 🕵️‍♂️ 1. Security Header Audit
Il modulo `http_recon.py` interroga il server simulando un browser reale (Chrome 123) per bypassare i filtri bot elementari.
- **Logica**: Analizziamo la presenza di header di sicurezza critici (**HSTS**, **CSP**, **Clickjacking Protection**).
- **Audit di Valore**: Invece di limitarci a mostrare i dati grezzi, assegniamo un punteggio (**Score 0-6**) che riflette la robustezza dell'Hardening del server.
- **Verbi HTTP**: Testiamo attivamente i metodi HTTP potenzialmente pericolosi (**PUT**, **TRACE**). Per evitare falsi positivi dei WAF, eseguiamo una **Canary Verification** (tentiamo di creare un file casuale e verificare se esiste davvero).

## 🔒 2. SSL/TLS Certificate Inspection
L'ispezione SSL (`ssl_inspector.py`) è una miniera d'oro per la ricognizione OSINT.
- **Validità & Cipher**: Verifichiamo la data di scadenza e la robustezza degli algoritmi di cifratura (es. TLSv1.3).
- **SAN Discovery (Subject Alternative Names)**: Estraiamo tutti i nomi alternativi dal certificato. Questa tecnica permette spesso di scoprire sottodomini "nascosti" o interni che non sono tipicamente indicizzati dai motori di ricerca.

## 📂 3. Smart 404 Detection (Directory Buster)
Il **Directory Buster** (`directory_buster.py`) utilizza una tecnica proprietaria per eliminare i falsi positivi comuni nelle moderne Web Application (SPA/React).
- **Il Problema**: Molti server rispondono `200 OK` a qualsiasi richiesta, anche se la pagina non esiste (Catch-All).
- **La Soluzione (V2.0)**:
  1. **Calibrazione**: Prima della scansione, il toolkit invia una richiesta a un path che sicuramente NON esiste (es. un UUID casuale).
  2. **Baseline**: Memoizza lo status code, la lunghezza e la location di questa risposta.
  3. **Diff Check**: Durante la scansione, un path viene considerato "trovato" solo se la sua risposta differisce significativamente dalla Baseline (es. diversa lunghezza del body o divergenza nel redirect).

---
> **Expert Note**: Questa cura dei dettagli trasforma un semplice scanner in uno strumento di precisione per investigazioni professionali.
