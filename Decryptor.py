import base64
import codecs
import urllib.parse
import hashlib

# Morse dictionary
MORSE_CODE_DICT = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '/': ' ', '-----': '0', '.----': '1', '..---': '2',
    '...--': '3', '....-': '4', '.....': '5', '-....': '6',
    '--...': '7', '---..': '8', '----.': '9'
}

# Decoding functions
def from_base64(text):
    try:
        return base64.b64decode(text).decode()
    except:
        return None

def from_hex(text):
    try:
        return bytes.fromhex(text).decode()
    except:
        return None

def from_binary(text):
    try:
        return ''.join([chr(int(b, 2)) for b in text.split()])
    except:
        return None

def from_rot13(text):
    try:
        return codecs.decode(text, 'rot_13')
    except:
        return None

def from_url(text):
    try:
        return urllib.parse.unquote(text)
    except:
        return None

def from_caesar(text, shift):
    result = ''
    for c in text:
        if c.isupper():
            result += chr((ord(c) - 65 - shift) % 26 + 65)
        elif c.islower():
            result += chr((ord(c) - 97 - shift) % 26 + 97)
        else:
            result += c
    return result

def from_xor(text, key):
    try:
        return ''.join(chr(ord(c) ^ key) for c in text)
    except:
        return None

def from_morse(morse):
    try:
        return ''.join(MORSE_CODE_DICT.get(code, '?') for code in morse.strip().split(' '))
    except:
        return None

def hash_check(text):
    return {
        "MD5": hashlib.md5(text.encode()).hexdigest(),
        "SHA1": hashlib.sha1(text.encode()).hexdigest(),
        "SHA256": hashlib.sha256(text.encode()).hexdigest(),
        "SHA512": hashlib.sha512(text.encode()).hexdigest()
    }

# Auto-detection and decoding
def auto_decode(text):
    result = {
        "Base64": from_base64(text),
        "Hex": from_hex(text),
        "Binary": from_binary(text),
        "ROT13": from_rot13(text),
        "URL Decoded": from_url(text),
        "Morse Code": from_morse(text),
        "Caesar Ciphers": {f"Shift {i}": from_caesar(text, i) for i in range(1, 26)},
        "XOR Ciphers": {f"Key {k}": from_xor(text, k) for k in range(1, 11)},
        "Hashes": hash_check(text)
    }
    return result

# 🧪 Example usage:
if __name__ == "__main__":
    sample = "SGFja2luZyBpcyBmdW4hIFRyeSBtb3JlIQ=="  # Base64-encoded
    results = auto_decode(sample)
    for key, value in results.items():
        print(f"\n[{key}]")
        if isinstance(value, dict):
            for subkey, subvalue in value.items():
                print(f"{subkey}: {subvalue}")
        else:
            print(value)
if __name__ == "__main__":
    sample = "SGFja2luZyBpcyBmdW4hIFRyeSBtb3JlIQ=="  # Example Base64 input
    results = auto_decode(sample)
    for key, value in results.items():
        print(f"\n[{key}]")
        if isinstance(value, dict):
            for subkey, subvalue in value.items():
                print(f"{subkey}: {subvalue}")
        else:
            print(value)
