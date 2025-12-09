import math

def modInverse(a, m):
    """
    Modüler tersi bulur. (a*x) % m = 1 olan x sayısını arar.
    """
    for x in range(1, m):
        if (((a % m) * (x % m)) % m == 1):
            return x
    return -1

def encrypt(text, key):
    """
    Affine Şifreleme
    Anahtar (Key) Türü: Tuple veya String "a,b" (Örn: "5,8")
    a ve 26 aralarında asal olmalıdır.
    """
    try:
        # Anahtar string gelirse "5,8" gibi parçala
        if isinstance(key, str):
            parts = key.split(',')
            a = int(parts[0])
            b = int(parts[1])
        else:
            a, b = key
            
        if math.gcd(a, 26) != 1:
            return "Hata: 'a' değeri 26 ile aralarında asal olmalıdır. (Örn: 1, 3, 5, 7, 9, 11...)"
    except:
        return "Hata: Anahtar formatı 'a,b' şeklinde olmalıdır (Örn: 5,8)."

    result = ""
    for char in text:
        if char.isupper():
            result += chr(((a * (ord(char) - 65) + b) % 26) + 65)
        elif char.islower():
            result += chr(((a * (ord(char) - 97) + b) % 26) + 97)
        else:
            result += char
    return result

def decrypt(text, key):
    """
    Affine Deşifreleme
    Formül: a^-1 * (x - b) mod 26
    """
    try:
        if isinstance(key, str):
            parts = key.split(',')
            a = int(parts[0])
            b = int(parts[1])
        else:
            a, b = key
            
        mod_inverse_a = modInverse(a, 26)
        if mod_inverse_a == -1:
             return "Hata: 'a' değerinin modüler tersi yok."
    except:
        return "Hata: Anahtar formatı 'a,b' şeklinde olmalıdır."

    result = ""
    for char in text:
        if char.isupper():
            result += chr(((mod_inverse_a * ((ord(char) - 65) - b)) % 26) + 65)
        elif char.islower():
            result += chr(((mod_inverse_a * ((ord(char) - 97) - b)) % 26) + 97)
        else:
            result += char
    return result