def encrypt(text, shift):
    """
    Sezar Şifreleme: Metni belirtilen anahtar (shift) kadar kaydırır.
    Anahtar (Key) Türü: Integer (Tam sayı)
    """
    result = ""
    try:
        shift = int(shift)
    except ValueError:
        return "Hata: Sezar şifrelemesi için anahtar bir tam sayı olmalıdır."

    for char in text:
        if char.isupper():
            # ASCII 65 = 'A'
            result += chr((ord(char) + shift - 65) % 26 + 65)
        elif char.islower():
            # ASCII 97 = 'a'
            result += chr((ord(char) + shift - 97) % 26 + 97)
        else:
            # Harf değilse değiştirmeden bırak
            result += char
    return result

def decrypt(text, shift):
    """
    Sezar Deşifreleme: Şifreli metni anahtar kadar geri kaydırır.
    """
    try:
        shift = int(shift)
    except ValueError:
        return "Hata: Anahtar bir tam sayı olmalıdır."
        
    # Geriye doğru kaydırmak için shift'in negatifini veya 26 - shift kullanırız.
    return encrypt(text, -shift)