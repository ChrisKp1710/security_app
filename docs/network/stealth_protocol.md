# Protocollo Stealth: Modalità Ghost (Evasion Strategy)

La **Modalità Ghost** non è una semplice scansione sequenziale. È un protocollo di infiltrazione silente progettato per superare le barriere di sicurezza più avanzate (IDS, IPS, WAF).

## 🥷 Perché il Ghost Mode?
In molti audit di sicurezza, scansioni troppo veloci o prevedibili vengono immediatamente bloccate dal Firewall, portando a risultati incompleti o al bando dell'IP dell'auditor.

### 🧩 1. Port Shuffling (Rimescolamento)
Invece di scansionare le porte in ordine (1, 2, 3...), il Ghost Mode utilizza l'algoritmo di **Fisher-Yates Shuffle**.
- **Logica**: Il server riceve pacchetti sparsi nel tempo e nello spazio delle porte. 
- **Risultato**: Questo schema rompe le firme di scansione ("Sequential Scan Detect") utilizzate dai Firewall, rendendo impossibile distinguere la scansione da traffico di rete casuale o legittimo.

### 🕰️ 2. Adaptive Jitter (Sincronizzazione Umana)
Il toolkit introduce un ritardo variabile (**Jitter**) tra una porta e l'altra (default 0.7s - 2.2s).
- **Logica**: Una scansione automatica ha solitamente un intervallo fisso (es. 10ms). Un intervallo variabile simula l'interazione umana o una navigazione reale.
- **Risultato**: I Web Application Firewall (WAF) come Cloudflare non rilevano il pattern di automazione, permettendo la scansione completa di domini protetti da Shield attivi.

### 🔍 3. Probing Sequenziale (Single-Thread)
A differenza del motore Industrial, il Ghost Mode opera in **singolo thread**.
- **Tecnica**: Una sola connessione alla volta viene aperta. 
- **Obiettivo**: Minimizzare l'occupazione di banda e mantenere un rumore di fondo quasi nullo.

## 🛡️ Affidabilità dell'Audit
Sebbene più lenta, la Modalità Ghost è la scelta d'elezione per:
1. Audit su infrastrutture Mission-Critical.
2. Ricognizione OSINT senza allertare il SOC (Security Operations Center).
3. Superamento di limitazioni di "Rate Limiting" aggressive.

---
> **Expert Note**: Il Ghost Mode è lo strumento definitivo per l'auditor che cerca la qualità del dato e la discrezione sopra ogni altra cosa.
