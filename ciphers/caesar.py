def encrypt(text, shift):
    result = ""
    try:
        shift = int(shift)
    except ValueError:
        return "Hata: Sezar şifrelemesi için anahtar bir tam sayı olmalıdır."

    for char in text:
        if char.isupper():
            result += chr((ord(char) + shift - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) + shift - 97) % 26 + 97)
        else:
            result += char
    return result

def decrypt(text, shift):
    try:
        shift = int(shift)
    except ValueError:
        return "Hata: Anahtar bir tam sayı olmalıdır."
    return encrypt(text, -shift)