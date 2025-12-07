# ciphers/vigenere.py

def encrypt(text, key):
    """
    Vigenere Şifreleme
    Anahtar (Key) Türü: String (Metin)
    """
    result = ""
    key_index = 0
    key = key.upper()
    
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - 65
            if char.isupper():
                result += chr((ord(char) + shift - 65) % 26 + 65)
            else:
                result += chr((ord(char) + shift - 97) % 26 + 97)
            key_index += 1
        else:
            result += char
    return result

def decrypt(text, key):
    """
    Vigenere Deşifreleme
    """
    result = ""
    key_index = 0
    key = key.upper()
    
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - 65
            # Geriye doğru kaydırma işlemi
            if char.isupper():
                result += chr((ord(char) - shift - 65) % 26 + 65)
            else:
                result += chr((ord(char) - shift - 97) % 26 + 97)
            key_index += 1
        else:
            result += char
    return result