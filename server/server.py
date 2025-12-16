import socket
import json
import sys
import os
import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ciphers import aes, des, rsa, caesar, vigenere, affine, rail_fence, substitution, columnar, hill

# RSA Key Üretimi
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
                data = conn.recv(16384) # Buffer arttırıldı
                if not data: break
                
                try:
                    request = json.loads(data.decode('utf-8'))
                    req_type = request.get('type')
                    
                    if req_type == 'GET_PUBLIC_KEY':
                        response = {"status": "success", "public_key": PUBLIC_KEY.decode('utf-8')}
                        conn.sendall(json.dumps(response).encode('utf-8'))
                        continue
                    
                    algo = request.get('algorithm')
                    mode = request.get('mode')
                    cipher_text = request.get('ciphertext')
                    encrypted_key_b64 = request.get('encrypted_key') # Hibrit anahtar

                    print(f"\n--- YENİ MESAJ ({algo} - {mode}) ---")
                    
                    decrypted_text = ""
                    server_key = "Bilinmiyor"

                    # --- 1. HİBRİT ÇÖZME (AES / DES) ---
                    if algo in ['aes', 'des']:
                        print(f"Hibrit Şifreleme Algılandı ({algo}).")
                        print("1. Adım: Şifreli Session Key, RSA Private Key ile çözülüyor...")
                        
                        if not encrypted_key_b64:
                            decrypted_text = "Hata: Şifreli anahtar bulunamadı!"
                        else:
                            # Önce Anahtarı RSA ile Çöz
                            session_key = rsa.decrypt(encrypted_key_b64, PRIVATE_KEY)
                            
                            if "Hata" in session_key:
                                decrypted_text = f"Anahtar Çözülemedi: {session_key}"
                            else:
                                server_key = session_key # Log için sakla
                                print(f"2. Adım: Çözülen Anahtar ile Metin Deşifre Ediliyor... Key: {server_key}")
                                
                                # Şimdi o anahtarla metni çöz
                                if algo == 'aes':
                                    if mode == 'manual': decrypted_text = aes.decrypt_manual(cipher_text, server_key)
                                    else: decrypted_text = aes.decrypt_lib(cipher_text, server_key)
                                elif algo == 'des':
                                    if mode == 'manual': decrypted_text = des.decrypt_manual(cipher_text, server_key)
                                    else: decrypted_text = des.decrypt_lib(cipher_text, server_key)

                    # --- 2. RSA (Direkt Mesaj) ---
                    elif algo == 'rsa':
                        print("RSA Mesajı çözülüyor...")
                        decrypted_text = rsa.decrypt(cipher_text, PRIVATE_KEY)

                    # --- 3. KLASİK (Eski Usul - Elle Giriş) ---
                    else:
                        print(f"Lütfen {algo.upper()} Anahtarını Girin:")
                        server_key = input(">> ")
                        
                        if algo == 'sezar': decrypted_text = caesar.decrypt(cipher_text, server_key)
                        elif algo == 'vigenere': decrypted_text = vigenere.decrypt(cipher_text, server_key)
                        elif algo == 'affine': decrypted_text = affine.decrypt(cipher_text, server_key)
                        elif algo == 'rail_fence': decrypted_text = rail_fence.decrypt(cipher_text, server_key)
                        elif algo == 'substitution': decrypted_text = substitution.decrypt(cipher_text, server_key)
                        elif algo == 'columnar': decrypted_text = columnar.decrypt(cipher_text, server_key)
                        elif algo == 'hill': decrypted_text = hill.decrypt(cipher_text, server_key)
                        else: decrypted_text = f"Hata: Bilinmeyen Algoritma"

                    # Sonuç Gönder
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
                except Exception as e: print(f"Server Hatası: {e}")

if __name__ == "__main__":
    start_server()