from ecies import encrypt, decrypt
from ecies.utils import generate_eth_key
import binascii
import secrets
import hashlib

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
G_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
G_Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def generate_keys_lib():
    eth_k = generate_eth_key()
    priv_key = eth_k.to_hex()
    pub_key = eth_k.public_key.to_hex()
    return priv_key, pub_key

def encrypt_lib(msg, pub_key_hex):
    if isinstance(msg, str): msg = msg.encode('utf-8')
    try:
        encrypted = encrypt(pub_key_hex, msg)
        return binascii.hexlify(encrypted).decode('utf-8')
    except Exception as e: return f"Lib Error: {e}"

def decrypt_lib(cipher_hex, priv_key_hex):
    try:
        cipher_bytes = binascii.unhexlify(cipher_hex)
        decrypted = decrypt(priv_key_hex, cipher_bytes)
        return decrypted.decode('utf-8')
    except Exception as e: return f"Lib Error: {e}"

def point_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2: return None
    if x1 == x2: m = (3 * x1 * x1 + A) * pow(2 * y1, -1, P)
    else: m = (y1 - y2) * pow(x1 - x2, -1, P)
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)

def scalar_mult(k, point):
    result = None
    addend = point
    while k:
        if k & 1: result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

def generate_keys_manual():
    priv_int = secrets.randbelow(N)
    pub_point = scalar_mult(priv_int, (G_X, G_Y))
    pub_str = f"{pub_point[0]},{pub_point[1]}"
    return str(priv_int), pub_str

def encrypt_manual(msg, pub_key_str):
    try:
        x, y = map(int, pub_key_str.split(','))
        receiver_pub_point = (x, y)
        k = secrets.randbelow(N)
        R_point = scalar_mult(k, (G_X, G_Y))
        S_point = scalar_mult(k, receiver_pub_point)
        shared_secret = S_point[0]
        key_hash = hashlib.sha256(str(shared_secret).encode()).digest()
        
        if isinstance(msg, str): msg = msg.encode('utf-8')
        encrypted_bytes = bytearray()
        for i, byte in enumerate(msg):
            encrypted_bytes.append(byte ^ key_hash[i % len(key_hash)])
        
        R_str = f"{R_point[0]},{R_point[1]}"
        cipher_hex = binascii.hexlify(encrypted_bytes).decode()
        return f"{R_str}|{cipher_hex}"
    except Exception as e: return f"Manual Error: {e}"

def decrypt_manual(payload, priv_key_str):
    try:
        R_str, cipher_hex = payload.split('|')
        rx, ry = map(int, R_str.split(','))
        R_point = (rx, ry)
        priv_int = int(priv_key_str)
        S_point = scalar_mult(priv_int, R_point)
        shared_secret = S_point[0]
        key_hash = hashlib.sha256(str(shared_secret).encode()).digest()
        cipher_bytes = binascii.unhexlify(cipher_hex)
        decrypted_bytes = bytearray()
        for i, byte in enumerate(cipher_bytes):
            decrypted_bytes.append(byte ^ key_hash[i % len(key_hash)])
        return decrypted_bytes.decode('utf-8')
    except Exception as e: return f"Manual Error: {e}"