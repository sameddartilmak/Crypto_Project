# ciphers/columnar.py
import math

def encrypt(text, key):
    """
    Columnar Transposition Şifreleme
    Anahtar: Kelime (String)
    """
    msg = text
    cipher = ""
    
    k_indx = 0
    msg_len = float(len(msg))
    msg_lst = list(msg)
    
    # Anahtardaki harflerin alfabetik sırasını bul (key index)
    key_lst = sorted(list(key))
    
    # Sütun sayısı = Anahtar uzunluğu
    col = len(key)
    row = int(math.ceil(msg_len / col))
    
    # Boş yerleri doldur (Padding) - Genelde '_' veya 'X' kullanılır, burada boşluk bırakmıyoruz
    fill_null = int((row * col) - msg_len)
    msg_lst.extend('_' * fill_null)
    
    # Matris oluştur
    matrix = [msg_lst[i: i + col] for i in range(0, len(msg_lst), col)]
    
    # Anahtardaki sıralamaya göre sütunları oku
    for _ in range(col):
        curr_idx = key.find(key_lst[k_indx])
        
        # Aynı harften varsa çakışmayı önlemek için o harfi kullanılamaz yap
        key_lst[k_indx] = '*' 
        
        for r in matrix:
            cipher += r[curr_idx]
            
        k_indx += 1
        
    return cipher

def decrypt(cipher, key):
    """
    Columnar Transposition Deşifreleme
    """
    msg = ""
    k_indx = 0
    msg_indx = 0
    msg_len = float(len(cipher))
    msg_lst = list(cipher)
    
    col = len(key)
    row = int(math.ceil(msg_len / col))
    
    key_lst = sorted(list(key))
    
    # Deşifreleme matrisini oluştur
    dec_cipher = []
    for _ in range(row):
        dec_cipher += [[None] * col]
    
    # Hangi sütunda kaç karakter olduğunu ve son satır boşluklarını hesapla
    # Son satırdaki dolu hücre sayısı = mod işlemi
    # Ancak biz şifrelerken '_' ile doldurduğumuz için her sütun tam dolu sayılır (row kadar)
    # Eğer '_' kullanmasaydık matematik daha karmaşık olurdu.
    
    # Sütun sütun matrise yerleştir
    for _ in range(col):
        curr_idx = key.find(key_lst[k_indx])
        key_lst[k_indx] = '*'
        
        for j in range(row):
            dec_cipher[j][curr_idx] = msg_lst[msg_indx]
            msg_indx += 1
        k_indx += 1
    
    # Satır satır oku
    try:
        msg = ''.join(sum(dec_cipher, []))
    except TypeError:
        return "Hata oluştu"
        
    # Sonradan eklediğimiz '_' dolgu karakterlerini temizle
    null_count = msg.count('_')
    if null_count > 0:
        return msg[: -null_count]
        
    return msg