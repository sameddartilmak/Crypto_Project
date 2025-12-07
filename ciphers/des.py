# ciphers/des.py

# ==========================================
# KÜTÜPHANELİ VERSİYON (YORUM SATIRI)
# ==========================================
# Kullanmak için: pip install pycryptodome
#
# from Crypto.Cipher import DES
# from Crypto.Util.Padding import pad, unpad
# import base64
#
# def encrypt_lib(text, key):
#     # DES anahtarı 8 byte olmalıdır.
#     key = key.ljust(8)[:8].encode('utf-8')
#     cipher = DES.new(key, DES.MODE_ECB)
#     padded_text = pad(text.encode('utf-8'), DES.block_size)
#     encrypted_bytes = cipher.encrypt(padded_text)
#     return base64.b64encode(encrypted_bytes).decode('utf-8')
#
# def decrypt_lib(encrypted_text, key):
#     key = key.ljust(8)[:8].encode('utf-8')
#     cipher = DES.new(key, DES.MODE_ECB)
#     decoded_encrypted_text = base64.b64decode(encrypted_text)
#     decrypted_text = unpad(cipher.decrypt(decoded_encrypted_text), DES.block_size)
#     return decrypted_text.decode('utf-8')
# ==========================================


# ==========================================
# KÜTÜPHANESİZ (MANUEL) VERSİYON
# ==========================================

# DES Sabit Tabloları (Permütasyon, S-Box vb.)
PI = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

CP_1 = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

CP_2 = [14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32]

E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

S_BOX = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

PI_1 = [40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25]

SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def string_to_bit_array(text):
    array = list()
    for char in text:
        binval = bin(char)[2:].zfill(8)
        array.extend([int(x) for x in list(binval)])
    return array

def bit_array_to_string(array):
    res = ''.join([str(x) for x in array])
    return ''.join([chr(int(res[i:i+8], 2)) for i in range(0, len(res), 8)])

def permute(block, table):
    return [block[x - 1] for x in table]

def xor(t1, t2):
    return [x ^ y for x, y in zip(t1, t2)]

def expand(block, table):
    return [block[x - 1] for x in table]

def substitute(block):
    res = []
    for i in range(0, len(block), 6):
        section = block[i:i+6]
        row = int(str(section[0]) + str(section[5]), 2)
        col = int(''.join([str(x) for x in section[1:5]]), 2)
        val = S_BOX[i//6][row][col]
        res.extend([int(x) for x in bin(val)[2:].zfill(4)])
    return res

def generate_keys(key):
    keys = []
    key = string_to_bit_array(key)
    # Anahtar 64 bit değilse padding veya kesme yapılmalı
    # Bu basit implementasyonda 64 bit (8 char) varsayıyoruz
    key = permute(key, CP_1)
    L, R = key[:28], key[28:]
    for shift in SHIFT:
        L = L[shift:] + L[:shift]
        R = R[shift:] + R[:shift]
        keys.append(permute(L + R, CP_2))
    return keys

def des_block(block, keys):
    block = permute(block, PI)
    L, R = block[:32], block[32:]
    for key in keys:
        tmp = R
        R = expand(R, E)
        R = xor(R, key)
        R = substitute(R)
        R = permute(R, P)
        R = xor(L, R)
        L = tmp
    return permute(R + L, PI_1)

def pad(text):
    while len(text) % 8 != 0:
        text += ' '
    return text

def encrypt(text, key):
    # Anahtarı 8 karaktere tamamla/kırp
    key = key.ljust(8)[:8] 
    # Python string to bytes
    keys = generate_keys(key.encode('latin-1'))
    text = pad(text)
    res = []
    for i in range(0, len(text), 8):
        block = string_to_bit_array(text[i:i+8].encode('latin-1'))
        processed_block = des_block(block, keys)
        res.extend(processed_block)
    
    # Sonucu hex olarak döndürelim (okunabilir olması için)
    binary_str = ''.join([str(x) for x in res])
    hex_res = hex(int(binary_str, 2))[2:].upper()
    return hex_res

def decrypt(text, key):
    # Hex stringi geri binary array'e çevir
    try:
        bin_str = bin(int(text, 16))[2:]
        # Baştaki sıfırları tamamla
        fill_len = (len(text) * 4) - len(bin_str)
        bin_str = '0' * fill_len + bin_str
        
        full_bit_array = [int(x) for x in bin_str]
    except:
        return "Hata: Geçersiz Hex formatı"

    key = key.ljust(8)[:8]
    keys = generate_keys(key.encode('latin-1'))
    keys.reverse() # Deşifreleme için anahtarları tersten kullan
    
    res = []
    for i in range(0, len(full_bit_array), 64):
        block = full_bit_array[i:i+64]
        processed_block = des_block(block, keys)
        res.extend(processed_block)
        
    decrypted_str = bit_array_to_string(res)
    return decrypted_str.rstrip() # Padding boşluklarını sil