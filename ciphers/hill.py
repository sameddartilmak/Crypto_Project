# ciphers/hill.py
import math

def modInverse(a, m):
    for x in range(1, m):
        if (((a % m) * (x % m)) % m == 1):
            return x
    return -1

def get_key_matrix_from_numbers(key_string):
    """
    "6 24 1 13" gibi string'i alıp [[6, 24], [1, 13]] matrisine çevirir.
    """
    try:
        key_string = key_string.replace(',', ' ')
        numbers = [int(x) for x in key_string.split()]
    except ValueError:
        return None, "Hata: Anahtar sadece sayılardan oluşmalıdır (Örn: 6 24 1 13)."

    length = len(numbers)
    n = int(math.sqrt(length))
    
    if n * n != length:
        return None, f"Hata: {length} adet sayı girdiniz. Tam kare olmalı (4 sayı->2x2, 9 sayı->3x3)."
    
    key_matrix = []
    k = 0
    for i in range(n):
        row = []
        for j in range(n):
            row.append(numbers[k] % 26)
            k += 1
        key_matrix.append(row)
        
    return key_matrix, n

def get_cofactor_matrix(matrix, n):
    cofactors = []
    for r in range(n):
        cofactorRow = []
        for c in range(n):
            minor = []
            for i in range(n):
                if i == r: continue
                row = []
                for j in range(n):
                    if j == c: continue
                    row.append(matrix[i][j])
                minor.append(row)
            
            det = (minor[0][0] * minor[1][1] - minor[0][1] * minor[1][0])
            cofactorRow.append(((-1)**(r+c)) * det)
        cofactors.append(cofactorRow)
    return cofactors

def transpose_matrix(matrix, n):
    return [[matrix[j][i] for j in range(n)] for i in range(n)]

def encrypt(text, key):
    text = text.upper().replace(" ", "")
    
    key_matrix, n_or_error = get_key_matrix_from_numbers(key)
    
    if key_matrix is None:
        return n_or_error
        
    n = n_or_error 

    while len(text) % n != 0:
        text += 'X'
        
    cipher_text = ""
    for i in range(0, len(text), n):
        vector = [[ord(text[i+j]) % 65] for j in range(n)]
        
        res_vector = []
        for r in range(n):
            val = 0
            for c in range(n):
                val += key_matrix[r][c] * vector[c][0]
            res_vector.append(val % 26)
            
        for val in res_vector:
            cipher_text += chr(val + 65)
            
    return cipher_text

def decrypt(text, key):
    key_matrix, n_or_error = get_key_matrix_from_numbers(key)
    
    if key_matrix is None:
        return n_or_error
        
    n = n_or_error

    det = 0
    if n == 2:
        det = (key_matrix[0][0] * key_matrix[1][1] - key_matrix[0][1] * key_matrix[1][0])
    elif n == 3:
        for c in range(3):
            det += ((-1)**c) * key_matrix[0][c] * (key_matrix[1][(c+1)%3] * key_matrix[2][(c+2)%3] - key_matrix[1][(c+2)%3] * key_matrix[2][(c+1)%3])
    
    det = det % 26
    det_inv = modInverse(det, 26)
    
    if det_inv == -1:
        return "Hata: Bu matrisin tersi yoktur (Determinant mod 26'da terslenemez)."

    inv_key_matrix = []
    if n == 2:
        inv_key_matrix = [
            [(key_matrix[1][1] * det_inv) % 26, (-key_matrix[0][1] * det_inv) % 26],
            [(-key_matrix[1][0] * det_inv) % 26, (key_matrix[0][0] * det_inv) % 26]
        ]
    elif n == 3:
        cofactors = get_cofactor_matrix(key_matrix, n)
        adjugate = transpose_matrix(cofactors, n)
        inv_key_matrix = [[(adjugate[i][j] * det_inv) % 26 for j in range(n)] for i in range(n)]

    plain_text = ""
    for i in range(0, len(text), n):
        vector = [[ord(text[i+j]) % 65] for j in range(n)]
        
        res_vector = []
        for r in range(n):
            val = 0
            for c in range(n):
                val += inv_key_matrix[r][c] * vector[c][0]
            res_vector.append(val % 26)
            
        for val in res_vector:
            plain_text += chr(val + 65)
            
    return plain_text