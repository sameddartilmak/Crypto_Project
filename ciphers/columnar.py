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
    key_lst = sorted(list(key))
    
    col = len(key)
    row = int(math.ceil(msg_len / col))
    fill_null = int((row * col) - msg_len)
    msg_lst.extend('_' * fill_null)

    matrix = [msg_lst[i: i + col] for i in range(0, len(msg_lst), col)]
    
    for _ in range(col):
        curr_idx = key.find(key_lst[k_indx])
        
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

    dec_cipher = []
    for _ in range(row):
        dec_cipher += [[None] * col]

    for _ in range(col):
        curr_idx = key.find(key_lst[k_indx])
        key_lst[k_indx] = '*'
        
        for j in range(row):
            dec_cipher[j][curr_idx] = msg_lst[msg_indx]
            msg_indx += 1
        k_indx += 1

    try:
        msg = ''.join(sum(dec_cipher, []))
    except TypeError:
        return "Hata oluştu"
        
    null_count = msg.count('_')
    if null_count > 0:
        return msg[: -null_count]
        
    return msg