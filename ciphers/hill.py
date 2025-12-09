# ciphers/hill.py
import math

def modInverse(a, m):
    for x in range(1, m):
        if (((a % m) * (x % m)) % m == 1):
            return x
    return -1

def get_key_matrix(key, n):
    key_matrix = []
    k = 0
    for i in range(n):
        row = []
        for j in range(n):
            row.append(ord(key[k]) % 65)
            k += 1
        key_matrix.append(row)
    return key_matrix

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
            
            # Determinant of 2x2 minor
            det = (minor[0][0] * minor[1][1] - minor[0][1] * minor[1][0])
            cofactorRow.append(((-1)**(r+c)) * det)
        cofactors.append(cofactorRow)
    return cofactors

def transpose_matrix(matrix, n):
    return [[matrix[j][i] for j in range(n)] for i in range(n)]

def matrix_multiply(A, B, n):
    C = []
    for i in range(len(A)): # rows of A
        val = 0
        for j in range(n):
            val += A[i] * B[j][0]
        C.append(val % 26)
    return C

def encrypt(text, key):
    key = key.upper().replace(" ", "")
    text = text.upper().replace(" ", "")
    
    # Matris boyutu belirle (2x2 veya 3x3)
    n = int(math.sqrt(len(key)))
    if n * n != len(key):
        return "Hata: Anahtar uzunluğu tam kare olmalı (4 harf -> 2x2, 9 harf -> 3x3)"
        
    key_matrix = get_key_matrix(key, n)
    
    # Padding (Metin uzunluğu n'in katı olmalı)
    while len(text) % n != 0:
        text += 'X'
        
    cipher_text = ""
    for i in range(0, len(text), n):
        vector = [[ord(text[i+j]) % 65] for j in range(n)]
        
        # Vektör x Matris çarpımı
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
    key = key.upper().replace(" ", "")
    n = int(math.sqrt(len(key)))
    
    if n * n != len(key):
        return "Hata: Anahtar uzunluğu tam kare olmalı"

    key_matrix = get_key_matrix(key, n)
    
    # Determinant Hesapla
    det = 0
    if n == 2:
        det = (key_matrix[0][0] * key_matrix[1][1] - key_matrix[0][1] * key_matrix[1][0])
    elif n == 3:
        for c in range(3):
            det += ((-1)**c) * key_matrix[0][c] * (key_matrix[1][(c+1)%3] * key_matrix[2][(c+2)%3] - key_matrix[1][(c+2)%3] * key_matrix[2][(c+1)%3])
    
    det = det % 26
    det_inv = modInverse(det, 26)
    
    if det_inv == -1:
        return "Hata: Bu anahtarın tersi yoktur (Determinant 26 ile aralarında asal değil). Başka anahtar deneyin."

    # Adjoint (Ek Matris) ve Ters Matris Bulma
    inv_key_matrix = []
    if n == 2:
        # 2x2 Ters Matris: [d -b, -c a] * det_inv
        inv_key_matrix = [
            [(key_matrix[1][1] * det_inv) % 26, (-key_matrix[0][1] * det_inv) % 26],
            [(-key_matrix[1][0] * det_inv) % 26, (key_matrix[0][0] * det_inv) % 26]
        ]
    elif n == 3:
        # 3x3 için Cofactor -> Transpose -> Modulo
        cofactors = get_cofactor_matrix(key_matrix, n)
        adjugate = transpose_matrix(cofactors, n)
        inv_key_matrix = [[(adjugate[i][j] * det_inv) % 26 for j in range(n)] for i in range(n)]

    # Deşifreleme (Şifreli Vektör x Ters Matris)
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