# ciphers/playfair.py

def create_matrix(key):
    """
    Playfair için 5x5 Anahtar Matrisi oluşturur.
    J harfi I olarak kabul edilir.
    """
    key = key.upper().replace("J", "I").replace("İ", "I")
    matrix = []
    seen = set()
    
    # 1. Anahtardaki harfleri ekle (Tekrar edenleri atla)
    for char in key:
        if char not in seen and 65 <= ord(char) <= 90: # Sadece A-Z
            matrix.append(char)
            seen.add(char)
            
    # 2. Alfabenin geri kalanını ekle
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for char in alphabet:
        if char not in seen:
            matrix.append(char)
            seen.add(char)
            
    # Listeyi 5x5 matrise (list of lists) çevir
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def find_position(matrix, char):
    """Matriste harfin satır ve sütununu bulur."""
    for r, row in enumerate(matrix):
        for c, val in enumerate(row):
            if val == char:
                return r, c
    return None, None

def prepare_text(text):
    """
    Metni Playfair kurallarına göre ikililere hazırlar:
    1. J -> I yapılır.
    2. Harf olmayanlar silinir.
    3. Tekrar eden harflerin arasına 'X' konur (LL -> LX L).
    4. Uzunluk tek ise sona 'X' eklenir.
    """
    text = text.upper().replace("J", "I").replace("İ", "I")
    clean_text = "".join([c for c in text if 65 <= ord(c) <= 90])
    
    if not clean_text: return ""

    result = ""
    i = 0
    while i < len(clean_text):
        a = clean_text[i]
        b = ''
        
        if i + 1 < len(clean_text):
            b = clean_text[i+1]
        
        if a == b:
            result += a + 'X' # Çift harf kuralı (HELLO -> HELXLO)
            i += 1
        elif b:
            result += a + b
            i += 2
        else:
            result += a + 'X' # Tek kalan harf kuralı
            i += 1
            
    return result

def playfair_core(text, key, mode='encrypt'):
    """
    Playfair Çekirdek Mantığı (Substitution'daki translate yerine geçer)
    """
    if not key:
        return "Hata: Playfair anahtarı boş olamaz."

    matrix = create_matrix(key)
    
    # Şifrelerken metni hazırla (X ekle vs), Deşifrelerken sadece temizle
    if mode == 'encrypt':
        processed_text = prepare_text(text)
    else:
        # Deşifrelerken boşlukları sil ve J->I yap
        processed_text = text.upper().replace(" ", "").replace("J", "I")
        processed_text = "".join([c for c in processed_text if 65 <= ord(c) <= 90])

    if mode == 'decrypt' and len(processed_text) % 2 != 0:
        return "Hata: Şifreli metin uzunluğu tek sayı olamaz (Eksik karakter)."

    result = ""
    shift = 1 if mode == 'encrypt' else -1
    
    # İkililer (Digraphs) halinde işle
    for i in range(0, len(processed_text), 2):
        char1 = processed_text[i]
        char2 = processed_text[i+1]
        
        r1, c1 = find_position(matrix, char1)
        r2, c2 = find_position(matrix, char2)
        
        # Harf matriste yoksa (örn: geçersiz karakter) olduğu gibi bırak veya atla
        if r1 is None or r2 is None:
            continue 

        # KURAL 1: Aynı Satır -> Sağa (encrypt) / Sola (decrypt) kaydır
        if r1 == r2:
            result += matrix[r1][(c1 + shift) % 5]
            result += matrix[r2][(c2 + shift) % 5]
        # KURAL 2: Aynı Sütun -> Aşağı (encrypt) / Yukarı (decrypt) kaydır
        elif c1 == c2:
            result += matrix[(r1 + shift) % 5][c1]
            result += matrix[(r2 + shift) % 5][c2]
        # KURAL 3: Dikdörtgen -> Köşeleri değiştir
        else:
            result += matrix[r1][c2]
            result += matrix[r2][c1]
            
    return result

# --- DIŞARIYA AÇILAN FONKSİYONLAR (Substitution Kodu ile Aynı Yapıda) ---

def encrypt(text, key):
    """
    Playfair Şifreleme
    Anahtar: Herhangi bir kelime olabilir (Örn: MONARCHY)
    """
    return playfair_core(text, key, mode='encrypt')

def decrypt(text, key):
    """
    Playfair Deşifreleme
    """
    return playfair_core(text, key, mode='decrypt')