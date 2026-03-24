import base64
import urllib.parse
import binascii

def encode_data(text, mode):
    try:
        if mode == "Base64":
            return base64.b64encode(text.encode()).decode()
        elif mode == "URL":
            return urllib.parse.quote(text)
        elif mode == "Hex":
            return text.encode().hex()
        elif mode == "Binary":
            return ' '.join(format(ord(c), '08b') for c in text)
        return "Unknown Mode"
    except Exception as e:
        return f"Error: {str(e)}"

def decode_data(text, mode):
    try:
        if mode == "Base64":
            padded = text + '=' * (-len(text) % 4) # Fix padding if missing
            return base64.b64decode(padded).decode('utf-8', errors='ignore')
        elif mode == "URL":
            return urllib.parse.unquote(text)
        elif mode == "Hex":
            return bytes.fromhex(text.strip().replace(" ", "")).decode('utf-8', errors='ignore')
        elif mode == "Binary":
            text = text.replace(" ", "")
            return ''.join(chr(int(text[i:i+8], 2)) for i in range(0, len(text), 8))
        return "Unknown Mode"
    except Exception as e:
        return f"Error: {str(e)}"
