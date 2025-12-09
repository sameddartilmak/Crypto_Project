# ciphers/vigenere.py

def encrypt(text, key):
    """
    Vigenere Şifreleme
    Anahtar (Key): Sadece harflerden (A-Z) oluşmalıdır.
    """
    # 1. Anahtar Kontrolü (Sadece harf olmalı)
    if not key.isalpha():
        return "Hata: Vigenere anahtarı sadece harflerden oluşmalıdır (Örn: KEY, KALEM)."
    
    result = ""
    key_index = 0
    key = key.upper()
    
    for char in text:
        if char.isalpha(): # Sadece harfleri şifrele
            # Anahtardaki harfin alfabedeki sırası (A=0, B=1...)
            shift = ord(key[key_index % len(key)]) - 65
            
            if char.isupper():
                result += chr((ord(char) + shift - 65) % 26 + 65)
            else:
                result += chr((ord(char) + shift - 97) % 26 + 97)
            
            key_index += 1
        else:
            # Sayı veya sembolse dokunma, olduğu gibi ekle
            result += char
            
    return result

def decrypt(text, key):
    """
    Vigenere Deşifreleme
    """
    # 1. Anahtar Kontrolü
    if not key.isalpha():
        return "Hata: Vigenere anahtarı sadece harflerden oluşmalıdır."

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