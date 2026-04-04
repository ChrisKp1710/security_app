# Metodologia di Audit Network Professionale (v1.0)

Questo documento illustra i principi tecnici e teorici che rendono il nostro toolkit uno degli strumenti di scansione più accurati e resilienti del settore. La nostra filosofia si basa sul superamento della semplice "connettività" per raggiungere la **Certezza Audit**.

---

## 🛡️ 1. L'Architettura Duale: Industrial vs Ghost
Il toolkit non è un blocco monolitico, ma una suite adattiva che offre due approcci distinti alla scansione:

### ⚙️ Modalità Industrial (Carro Armato)
- **Obiettivo**: Velocità e copertura massiva.
- **Tecnica**: Multi-threading ad alta concorrenza.
- **Utilizzo**: Scansioni in ambienti locali, reti aziendali senza IPS aggressivi o fasi di discovery rapida.

### 🥷 Modalità Ghost (Infiltrazione)
- **Obiettivo**: Evasione dei sistemi di rilevamento IDS/IPS/WAF.
- **Tecnica**: Scansione sequenziale a thread singolo.
- **Punto di Forza**: Invisibility-by-Design.

---

## 🤫 2. Tecniche di Evasione Firewalls (Ghost Mode)
Per i target protetti da colossi come Netlify o Cloudflare, la velocità è il nemico. La modalità Ghost implementa due tecniche "Surgical Stealth":

### 🎲 Port Randomization (Shuffle)
Gli scanner tradizionali seguono un ordine lineare (1, 2, 3...). Questo è una firma (signature) che i firewall riconoscono istantaneamente. Noi applichiamo un **rimescolamento casuale delle porte**, rendendo il pattern di traffico imprevedibile e indistinguibile da un'attività utente sporadica.

### ⏳ Adaptive Jitter (Respiro Umano)
Il firewall analizza la cadenza dei pacchetti. Un bot invia pacchetti a intervalli millimetrici. Noi iniettiamo un **Jitter variabile (0.7s - 2.2s)** tra ogni sonda. Questo "respiro" simula il comportamento incostante di un operatore umano, eludendo la soglia di allarme dei sistemi WAF.

---

## 🔍 3. Il Motore delle Verità: Double-Handshake Verification
Il problema più grande negli audit sono i **Falsi Positivi** generati dai firewall (Tarpits/Spoofing). Molti firewall "mentono" dicendo che una porta è aperta per far perdere tempo allo scanner.

### 🤝 Il Double-Check
Il nostro strumento non si fida del semplice `TCP Handshake` (porta aperta). Esegue un secondo passaggio obbligatorio sul livello applicativo:
1. **TCP Connect**: La porta risponde? (Sospetto Aperta).
2. **Banner Grabbing**: Il servizio risponde a un probe specifico? (Certificazione).

### 🏷️ Classificazione dei Risultati
- **✅ VERIFIED**: Abbiamo ricevuto un Banner reale (es. `SSH-2.0`, `HTTP/1.1`). Il servizio esiste ed è vulnerabile all'audit.
- **⚠️ STEALTH / GHOST**: La porta risponde alla connessione ma rimane muta. Il tool identifica questo comportamento come un probabile trucco del firewall o un servizio silente (Ninja Service).

---

## 🛡️ 4. WAF Noise Filtering & Shield Alerts
Il toolkit osserva l'intero pattern della scansione. Se rileva che un numero insolito di porte (es. > 3) sono in stato "Stealth", attiva istantaneamente l'**Alert di Integrità**.
Questo avvisa l'utente che il target sta tentando di ingannarlo, preservando "la faccia" dell'auditor che evita di segnalare servizi inesistenti nel report finale.

---

## 📈 5. Ottimizzazione "Top Ports Professional"
Invece di una scansione lineare distruttiva (1-65535), applichiamo una logica di **Priority Auditing**. Focalizzandoci sulle 1000 porte statisticamente più utilizzate e suscettibili di attacchi, massimizziamo i risultati utili riducendo drasticamente il tempo di esposizione al target.

---
> [!NOTE]
> **Conclusion**: Questa cura chirurgica nei passaggi tecnici è ciò che trasforma il toolkit in una suite di precisione enterprise, garantendo che ogni riga del tuo report sia supportata da una verifica multi-livello.
