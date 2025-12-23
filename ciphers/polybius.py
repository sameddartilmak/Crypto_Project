
def create_polybius_square(key=None):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ" # J yok, I ile birleşik
    square = []
    key_chars = []
    if key:
        key = key.upper().replace("J", "I")
        for char in key:
            if char.isalpha() and char not in key_chars:
                key_chars.append(char)

    for char in key_chars:
        square.append(char)
        
    for char in alphabet:
        if char not in square:
            square.append(char)
            
    return square

def encrypt(text, key=""):
    square = create_polybius_square(key)
    text = text.upper().replace("J", "I")
    ciphertext = ""
    
    for char in text:
        if char in square:
            index = square.index(char)
            row = (index // 5) + 1
            col = (index % 5) + 1
            ciphertext += f"{row}{col} "
        else:
            ciphertext += char
            
    return ciphertext.strip()

def decrypt(text, key=""):
    square = create_polybius_square(key)
    plaintext = ""
    i = 0
    clean_text = text.replace(" ", "")
    words = text.split("  ")
    digits = []
    non_digit_map = {} 
    
    temp_digits = ""
    for char in text:
        if char.isdigit():
            temp_digits += char
        else:
            pass 

    if len(temp_digits) % 2 != 0:
        return "Hata: Eksik rakam! Polybius şifresi çift rakamlardan oluşmalıdır."

    for i in range(0, len(temp_digits), 2):
        row = int(temp_digits[i])
        col = int(temp_digits[i+1])
        
        if 1 <= row <= 5 and 1 <= col <= 5:
            index = (row - 1) * 5 + (col - 1)
            plaintext += square[index]
        else:
            plaintext += "?" 
            
    return plaintext