# 🛡️ Security Toolkit Pro v4.5 - Enterprise Edition

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![UI Framework](https://img.shields.io/badge/UI-CustomTkinter-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Security](https://img.shields.io/badge/Security-CSPRNG-orange.svg)

**Security Toolkit Pro** è una suite avanzata di strumenti per la cyber-sicurezza e la ricognizione web, progettata con un approccio "Smart" per ridurre i falsi positivi e fornire analisi accurate. Sviluppata per scopi didattici e professionali, l'app combina una logica di scansione intelligente con un'interfaccia moderna in stile 2025/26.

## 🚀 Perché questo tool è diverso?

A differenza dei comuni scanner amatoriali, questo toolkit implementa algoritmi di **calibrazione dinamica** per interpretare correttamente le risposte dei server moderni (React, SPA, WAF, Cloudflare).

### 🧠 Logica Smart & Anti-False Positive
*   **Calibration Engine**: Prima di ogni scansione, il tool analizza il comportamento del server (404, 200 catch-all, 403 blocks o 301 redirects) per creare una "baseline" di confronto.
*   **Smart Redirect Filter**: Identifica se un redirect è un "soft-fail" generico verso la login o se punta a una risorsa reale e specifica, rivelando la struttura nascosta del sito.
*   **WAF Detection**: Riconosce i blocchi preventivi dei firewall (403 Forbidden) evitando di inondare il report di risultati inutili.

## ✨ Caratteristiche Principali

### 🌐 Network Operations Center
*   **Intelligent Port Scanner**: Non solo rileva porte aperte, ma esegue un **Service Fingerprinting** per identificare tecnologie come Nginx, Apache, SSH, MySQL e la loro versione.
*   **Directory Brute-Force**: Enumerazione di directory con filtraggio intelligente basato sulla dimensione della risposta e sulla destinazione dei redirect.
*   **Deep Reconnaissance**: 
    *   **Security Headers Analysis**: Valutazione dell'hardening del server (HSTS, CSP, X-Frame-Options, ecc.) con punteggio di sicurezza (Security Score).
    *   **Robots.txt Discovery**: Analisi automatica dei percorsi sensibili esposti nel file robots.txt.

### 🔐 Crypto Lab (Laboratorio Crittografico)
*   **CSPRNG Password Generator**: Generazione di chiavi basata sul modulo `secrets` di Python per garantire l'imprevedibilità crittografica.
*   **Password Strength Meter**: Analisi in tempo reale dell'entropia (bit) e stima del tempo necessario per un attacco Brute Force professionale.
*   **File Integrity**: Calcolo hash SHA-256 con lettura a blocchi per gestire file di grandi dimensioni senza saturare la memoria.

### 🎨 Interfaccia Utente (UI/UX)
*   **Modern Dark Mode**: Basata su `CustomTkinter`, con angoli arrotondati, animazioni di feedback e gerarchia visiva chiara.
*   **Multi-threading**: Tutte le operazioni pesanti corrono in background per garantire un'interfaccia sempre fluida e reattiva.

## 🛠 Installazione

### 1. Clonazione del repository
```bash
git clone https://github.com/tuo-username/security_app.git
cd security_app
```

### 2. Installazione dipendenze
Il progetto richiede `customtkinter` per la parte grafica:
```bash
pip install customtkinter
```

### 3. Avvio
```bash
python3 main.py
```

## 📖 Utilizzo Professionale

1.  **Recon**: Inserisci un dominio (es. `https://bersaglio.com`).
2.  **Scan**: Esegui prima il **Port Scan** per identificare i servizi esposti.
3.  **Deep Recon**: Clicca su **🛡️ RECON** per analizzare la corazza di sicurezza del server (Headers).
4.  **Directory Busting**: Se il server è un sito web, avvia il **DIR BUST** per cercare punti di ingresso non indicizzati.

## ⚠️ Disclaimer Legale

**IMPORTANTE**: Questo software è creato esclusivamente per scopi educativi e per attività di Ethical Hacking autorizzate. L'utilizzo di questo strumento verso bersagli senza previa autorizzazione scritta è illegale. L'autore non si assume alcuna responsabilità per l'uso improprio del software.

---
*Sviluppato con passione per la community di Cyber Security.*