import math

def encrypt(text, key):
    """
    Root (Route) Şifreleme:
    Metni satır satır yaz, sütun sütun oku.
    Anahtar (Key): Sütun sayısı (Sayı olmalı).
    """
    # Boşlukları temizle
    text = text.replace(" ", "").upper()
    
    try:
        cols = int(key)
    except ValueError:
        return "Hata: Root (Route) anahtarı bir sayı olmalıdır (Sütun sayısı)."
        
    if cols <= 1:
        return "Hata: Sütun sayısı 1'den büyük olmalıdır."

    # Satır sayısını hesapla
    rows = math.ceil(len(text) / cols)
    
    # Matrisi (Izgarayı) oluştur ve doldur
    # Eksik kalan yerleri 'X' ile doldur (Padding)
    padded_len = rows * cols
    text += 'X' * (padded_len - len(text))
    
    # Şifreleme: Sütun sütun okuma
    # Örn:
    # M E R
    # H A B
    # A X X
    # Çıktı (Sütun 1 + Sütun 2 + Sütun 3): MHA EAX RBX
    
    ciphertext = ""
    for c in range(cols):
        for r in range(rows):
            # Matrisin [r][c] indeksindeki karakter
            # String üzerindeki indeksi: (r * cols) + c
            index = (r * cols) + c
            ciphertext += text[index]
            
    return ciphertext

def decrypt(text, key):
    """
    Root (Route) Deşifreleme:
    Şifrelerken yapılanın tersi: Sütun sütun yazılmış veriyi geri satır satır diz.
    """
    text = text.replace(" ", "").upper()
    
    try:
        cols = int(key)
    except ValueError:
        return "Hata: Anahtar sayı olmalıdır."

    rows = math.ceil(len(text) / cols)
    
    # Deşifreleme mantığı:
    # Şifreli metni alıp, sanal bir matrise "sütun sütun" yerleştirmeliyiz.
    # Sonra "satır satır" okumalıyız.
    
    plaintext_matrix = [['' for _ in range(cols)] for _ in range(rows)]
    
    idx = 0
    for c in range(cols):
        for r in range(rows):
            if idx < len(text):
                plaintext_matrix[r][c] = text[idx]
                idx += 1
                
    # Satır satır oku
    plaintext = ""
    for r in range(rows):
        for c in range(cols):
            plaintext += plaintext_matrix[r][c]
            
    # Sondaki X'leri temizle (Opsiyonel, bazen X orijinal metinde de olabilir)
    return plaintext.rstrip('X')