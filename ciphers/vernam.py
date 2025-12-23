def clean_text(text):
    return "".join([c.upper() for c in text if c.isalpha()])

def encrypt(text, key):
    """
    Vernam Şifreleme: (Plaintext + Key) mod 26
    KURAL: Anahtar, metinden kısa olamaz!
    """
    text = clean_text(text)
    key = clean_text(key)
    
    if len(key) < len(text):
        return f"Hata: Vernam anahtarı, metinden kısa olamaz! (Metin: {len(text)}, Anahtar: {len(key)})"
    
    ciphertext = ""
    for i in range(len(text)):
        p_val = ord(text[i]) - 65
        k_val = ord(key[i]) - 65
        
        c_val = (p_val + k_val) % 26
        ciphertext += chr(c_val + 65)
        
    return ciphertext

def decrypt(text, key):
    """
    Vernam Deşifreleme: (Ciphertext - Key) mod 26
    """
    text = clean_text(text)
    key = clean_text(key)
    
    if len(key) < len(text):
        return "Hata: Anahtar uzunluğu yetersiz."
        
    plaintext = ""
    for i in range(len(text)):
        c_val = ord(text[i]) - 65
        k_val = ord(key[i]) - 65
        
        p_val = (c_val - k_val) % 26
        plaintext += chr(p_val + 65)
        
    return plaintext