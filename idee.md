# 🚀 Roadmap Sviluppo & Idee Future

Documento di raccolta idee per l'evoluzione del Security Toolkit.

## 1. 🌍 Reconnaissance (Raccolta Informazioni)
Obiettivo: Aumentare la consapevolezza situazionale prima dell'attacco/test.
- **Analisi HTTP Headers**: Scansione degli header di sicurezza (es. X-Frame-Options, CSP, HSTS) per valutare l'hardening del server.
- **WHOIS & Geolocation**: Identificazione del proprietario del dominio/IP e localizzazione geografica del server.

## 2. 📂 Web & Directory Busting
Obiettivo: Rendere la ricerca più profonda e flessibile.
- **Wordlist Personalizzate**: Possibilità di caricare file `.txt` esterni (es. SecLists) invece di usare solo la lista interna.
- **Analisi robots.txt**: Download e lettura automatica del file `robots.txt` per scoprire path sensibili che gli sviluppatori hanno tentato di nascondere.
- **User-Agent Spoofing**: Simulare browser reali (Chrome/Firefox) per evitare blocchi anti-bot basilari.

## 3. 🛡️ Crittografia e Sicurezza
Obiettivo: Strumenti più didattici e analitici.
- **Password Strength Meter**: Analisi della robustezza di una password (entropia) con stima del tempo di cracking.
- **Confronto Hash**: Funzione per confrontare l'hash calcolato con uno originale fornito dall'utente (Verifica integrità/Match).

## 4. 📝 Reporting & Export
Obiettivo: Professionalizzare l'output.
- **Export Strutturato**: Salvataggio report in formato JSON o CSV per interoperabilità con altri tool.
- **Log Dettagliati**: Opzione per salvare anche gli errori o i tentativi falliti (debug log).
