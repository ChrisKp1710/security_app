import json
import os

class SettingsManager:
    """
    Gestore delle impostazioni del toolkit.
    Carica i dati da un file JSON e fornisce valori di default.
    """
    def __init__(self, settings_file="settings.json"):
        self.settings_file = settings_file
        self.settings = self.get_default_settings()
        self.load_settings()

    def get_default_settings(self):
        return {
            "network": {
                "max_workers": 50,
                "timeout": 0.6,
                "smart_log": True,
                "default_target": "epicode.com"
            },
            "crypto": {
                "default_charset": "Alpha Lower (a-z)",
                "default_max_len": 4
            },
            "ui": {
                "theme": "dark-blue",
                "font_family": "Roboto"
            }
        }

    def load_settings(self):
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, "r") as f:
                    user_settings = json.load(f)
                    # Merge recursivo semplice per non perdere nuovi campi di default
                    self._update_recursive(self.settings, user_settings)
            except Exception as e:
                print(f"Errore nel caricamento settings: {e}")
                self.save_settings() # Riscrittura corretta dei default

    def save_settings(self):
        try:
            with open(self.settings_file, "w") as f:
                json.dump(self.settings, f, indent=4)
        except Exception as e:
            print(f"Errore nel salvataggio settings: {e}")

    def _update_recursive(self, base, update):
        for k, v in update.items():
            if isinstance(v, dict) and k in base:
                self._update_recursive(base[k], v)
            else:
                base[k] = v

    def get(self, section, key):
        return self.settings.get(section, {}).get(key)
