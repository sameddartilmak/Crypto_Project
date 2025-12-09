import socket
import json
import sys
import os
import datetime

# Üst klasördeki 'ciphers' paketini görebilmek için yol ekliyoruz
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# TÜM MODÜLLERİ DAHİL ET (Eksiksiz)
from ciphers import aes, des, rsa, caesar, vigenere, affine, rail_fence, substitution, columnar

# RSA Anahtarları Başlangıçta Üretilir
print("RSA Anahtarları üretiliyor... Lütfen bekleyin.")
PRIVATE_KEY, PUBLIC_KEY = rsa.generate_keys()
print("RSA Anahtarları Hazır!")

HOST = '127.0.0.1'
PORT = 65432

def log_to_file(algo, encrypted, key, decrypted, status):
    filename = f"logs_{algo}.txt"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(filename, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] Durum: {status}\n")
        f.write(f"Şifreli: {encrypted}\n")
        f.write(f"Anahtar: {key}\n")
        f.write(f"Çözülmüş: {decrypted}\n")
        f.write("-" * 30 + "\n")

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server {HOST}:{PORT} üzerinde dinleniyor...")

        while True:
            conn, addr = s.accept()
            with conn:
                data = conn.recv(8192) 
                if not data: break
                
                try:
                    request = json.loads(data.decode('utf-8'))
                    req_type = request.get('type')
                    
                    # 1. Public Key İsteği
                    if req_type == 'GET_PUBLIC_KEY':
                        response = {"status": "success", "public_key": PUBLIC_KEY.decode('utf-8')}
                        conn.sendall(json.dumps(response).encode('utf-8'))
                        continue
                    
                    # 2. Şifre Çözme İsteği
                    algo = request.get('algorithm')
                    mode = request.get('mode')
                    cipher_text = request.get('ciphertext')
                    
                    print(f"\n--- YENİ MESAJ ({algo} - {mode}) ---")
                    # Ekrana çok uzun metin basmamak için kısaltma
                    display_text = cipher_text[:50] + "..." if len(cipher_text) > 50 else cipher_text
                    print(f"Şifreli Metin: {display_text}")

                    decrypted_text = ""
                    server_key = "RSA Private Key (Gizli)" # Varsayılan

                    # --- ALGORİTMA SEÇİMİ ---
                    
                    # A) RSA (Otomatik)
                    if algo == 'rsa':
                        print("RSA Mesajı otomatik çözülüyor...")
                        decrypted_text = rsa.decrypt(cipher_text, PRIVATE_KEY)
                    
                    # B) Modern Simetrik (AES / DES)
                    elif algo == 'aes':
                        print(f"AES Çözme Anahtarını Girin:")
                        server_key = input(">> ")
                        if mode == 'manual': decrypted_text = aes.decrypt_manual(cipher_text, server_key)
                        else: decrypted_text = aes.decrypt_lib(cipher_text, server_key)

                    elif algo == 'des':
                        print(f"DES Çözme Anahtarını Girin:")
                        server_key = input(">> ")
                        if mode == 'manual': decrypted_text = des.decrypt_manual(cipher_text, server_key)
                        else: decrypted_text = des.decrypt_lib(cipher_text, server_key)

                    # C) Klasik Algoritmalar (Sezar, Vigenere vb.)
                    # SORUNU ÇÖZEN KISIM BURASI: else bloğu
                    else:
                        print(f"Lütfen {algo.upper()} Anahtarını Girin:")
                        server_key = input(">> ")
                        
                        if algo == 'sezar': decrypted_text = caesar.decrypt(cipher_text, server_key)
                        elif algo == 'vigenere': decrypted_text = vigenere.decrypt(cipher_text, server_key)
                        elif algo == 'affine': decrypted_text = affine.decrypt(cipher_text, server_key)
                        elif algo == 'rail_fence': decrypted_text = rail_fence.decrypt(cipher_text, server_key)
                        elif algo == 'substitution': decrypted_text = substitution.decrypt(cipher_text, server_key)
                        elif algo == 'columnar': decrypted_text = columnar.decrypt(cipher_text, server_key)
                        else: decrypted_text = "Hata: Bilinmeyen Algoritma"

                    # --- SONUÇ GÖNDERİMİ ---
                    if "Hata" in decrypted_text:
                        status = "Hata"
                        resp = {"status": "error", "message": decrypted_text}
                    else:
                        status = "Başarılı"
                        resp = {"status": "success", "plaintext": decrypted_text}
                    
                    print(f"Çözülen Metin: {decrypted_text}")
                    log_to_file(f"{algo}_{mode}", cipher_text, server_key, decrypted_text, status)
                    conn.sendall(json.dumps(resp).encode('utf-8'))

                except json.JSONDecodeError: print("JSON Hatası")
                except Exception as e: 
                    print(f"Server Hatası: {e}")
                    # Hata durumunda client'a boş değil hata mesajı dönelim
                    err_resp = {"status": "error", "message": str(e)}
                    conn.sendall(json.dumps(err_resp).encode('utf-8'))

if __name__ == "__main__":
    start_server()