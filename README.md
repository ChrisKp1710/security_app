# 🛡️ Security Toolkit ULTIMATE v4.0 - DARK EDITION

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)

Una suite completa di strumenti per la sicurezza informatica con interfaccia grafica dark mode moderna. Progettata per penetration testing, analisi della sicurezza di rete e gestione delle password.

## ✨ Caratteristiche

### 🕵️ Network Scanner
- **Port Scanning**: Scansione rapida o completa delle porte TCP
- **Banner Grabbing**: Identificazione automatica dei servizi in esecuzione
- **Analisi del Rischio**: Classificazione delle porte aperte per livello di rischio (ROSSO/GIALLO/VERDE)
- **Risoluzione DNS**: Conversione automatica hostname → IP
- **Progress Bar**: Monitoraggio in tempo reale dell'avanzamento della scansione

### 🔐 Crypto & Security Tools
- **Password Generator**: Generazione di password sicure con lettere, numeri e simboli speciali
- **File Hash Checker**: Calcolo dell'impronta digitale SHA-256 per verifica dell'integrità dei file
- **Directory Brute Force**: Enumerazione di directory nascoste comuni su web server

### 🎨 Interfaccia Utente
- **Dark Mode**: Design professionale con tema scuro ottimizzato
- **Console Integrata**: Output colorato in stile terminale per facile lettura dei risultati
- **Multithreading**: Operazioni asincrone per un'interfaccia sempre reattiva
- **Export Log**: Salvataggio dei report di scansione in formato testo

## 📋 Requisiti

- Python 3.8 o superiore
- Tkinter (incluso di default con Python)
- Sistema operativo: macOS, Linux o Windows

## 🚀 Installazione

### 1. Clona il repository
```bash
git clone https://github.com/tuousername/security_app.git
cd security_app
```

### 2. Verifica i requisiti
```bash
python3 --version
```

### 3. Avvia l'applicazione
```bash
python3 main.py
```

## 📖 Utilizzo

### Network Scanner

#### Scansione Rapida
1. Inserisci l'hostname o l'IP del target (es. `epicode.com`)
2. Seleziona l'opzione **Rapido** per scansionare le porte più comuni
3. Clicca su **🚀 START SCAN**
4. Visualizza i risultati colorati nella console:
   - 🟢 **VERDE**: Porte sicure (80, 443)
   - 🟡 **GIALLO**: Porte a medio rischio (22, 8080)
   - 🔴 **ROSSO**: Porte ad alto rischio (21, 23, 3306, 3389)

#### Scansione Completa
Seleziona **Full** per scansionare le porte dalla 1 alla 1000

#### Directory Enumeration
1. Inserisci l'hostname del sito web target
2. Clicca su **📂 DIR BRUTE**
3. L'applicazione cercherà directory comuni come:
   - `/admin`
   - `/login`
   - `/wp-admin`
   - `/backup`
   - `/dashboard`

### Crypto & Tools

#### Generatore Password
1. Vai alla scheda **🔐 Crypto & Tools**
2. Clicca su **GENERATE SECURE PASSWORD**
3. La password (16 caratteri) viene generata e copiata automaticamente negli appunti

#### Verifica Integrità File
1. Clicca su **CHECK FILE HASH**
2. Seleziona un file dal file picker
3. Visualizza l'hash SHA-256 del file per verificarne l'autenticità

### Salvataggio Report
Clicca su **SAVE LOG** nella scheda Scanner per esportare tutti i risultati in un file .txt

## 🏗️ Architettura del Progetto

```
security_app/
├── main.py                 # Entry point dell'applicazione
├── gui/
│   ├── __init__.py
│   └── dashboard.py        # Interfaccia grafica Tkinter con dark theme
└── logic/
    ├── __init__.py
    ├── port_scanner.py     # Scansione porte e banner grabbing
    ├── dir_finder.py       # Enumerazione directory web
    ├── password_gen.py     # Generazione password sicure
    └── hash_checker.py     # Calcolo hash SHA-256
```

### Moduli Principali

#### `main.py`
Entry point che inizializza l'interfaccia Tkinter e avvia il dashboard principale.

#### `dashboard.py`
- Gestione dell'interfaccia grafica con sistema a schede
- Implementazione del dark theme con colori personalizzati
- Console con output colorato e tagging
- Threading per operazioni asincrone

#### `port_scanner.py`
```python
scansione_porte(target, range_porte, callback_progress=None)
```
Scansiona le porte TCP del target e tenta di recuperare i banner dei servizi.

#### `dir_finder.py`
```python
cerca_directory_nascoste(target)
```
Utilizza richieste HTTP HEAD per verificare l'esistenza di directory comuni.

#### `password_gen.py`
```python
genera_password(lunghezza=12)
```
Genera password casuali con alta entropia utilizzando lettere, numeri e simboli.

#### `hash_checker.py`
```python
calcola_hash_file(percorso_file)
```
Calcola l'hash SHA-256 di un file leggendolo a blocchi per ottimizzare le performance.

## ⚠️ Avvertenze Legali

**IMPORTANTE**: Questo software è progettato esclusivamente per scopi educativi e di testing su sistemi di cui si possiede l'autorizzazione.

- ❌ **NON** utilizzare su sistemi senza autorizzazione esplicita
- ❌ **NON** utilizzare per attività illegali
- ✅ Utilizzare solo su infrastrutture proprie o con permesso scritto
- ✅ Rispettare le leggi locali e internazionali sulla sicurezza informatica

L'autore non si assume alcuna responsabilità per uso improprio del software.

## 🔒 Best Practices di Sicurezza

- Testa sempre in ambienti controllati (lab virtuali, macchine locali)
- Documenta tutte le attività di penetration testing
- Ottieni autorizzazioni scritte prima di qualsiasi test
- Rispetta gli scope agreement concordati
- Non salvare log in ambienti non sicuri

## 🤝 Contribuire

I contributi sono benvenuti! Per contribuire:

1. Fai un fork del progetto
2. Crea un branch per la tua feature (`git checkout -b feature/NuovaFunzionalità`)
3. Committa le modifiche (`git commit -m 'Aggiunge NuovaFunzionalità'`)
4. Push sul branch (`git push origin feature/NuovaFunzionalità`)
5. Apri una Pull Request

## 📝 TODO & Roadmap

- [ ] Aggiungere scansione UDP
- [ ] Implementare salvataggio risultati in formato JSON/CSV
- [ ] Aggiungere supporto per proxy SOCKS
- [ ] Implementare database di vulnerabilità note (CVE)
- [ ] Aggiungere crittografia/decrittografia file
- [ ] Implementare analisi di sicurezza Wi-Fi
- [ ] Aggiungere test di SQL injection basilari

## 📄 Licenza

Questo progetto è distribuito sotto licenza MIT. Vedi il file `LICENSE` per maggiori dettagli.

## 👨‍💻 Autore

Creato con ❤️ per la community della cybersecurity

## 🙏 Ringraziamenti

- Tkinter per il framework GUI
- La community open source della sicurezza informatica
- Tutti i contributor che hanno migliorato questo progetto

---

**Disclaimer**: Questo è uno strumento educativo. L'utilizzo improprio può violare leggi locali e internazionali. Usa sempre in modo responsabile ed etico.
