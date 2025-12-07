import socket
import json
import sys
import os
import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ciphers import aes, des, rsa_algo

# Server başlatıldığında RSA anahtarlarını üret
print("RSA Anahtarları üretiliyor... Lütfen bekleyin.")
PRIVATE_KEY, PUBLIC_KEY = rsa_algo.generate_keys()
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
                data = conn.recv(8192) # RSA key büyük olabilir, buffer'ı artırdık
                if not data:
                    break
                
                try:
                    request = json.loads(data.decode('utf-8'))
                    req_type = request.get('type')
                    
                    # İstemci Public Key isterse
                    if req_type == 'GET_PUBLIC_KEY':
                        response = {
                            "status": "success",
                            "public_key": PUBLIC_KEY.decode('utf-8')
                        }
                        conn.sendall(json.dumps(response).encode('utf-8'))
                        continue
                    
                    # Şifre Çözme İsteği Geldiyse
                    algo = request.get('algorithm')
                    mode = request.get('mode') # 'lib' veya 'manual'
                    cipher_text = request.get('ciphertext')
                    
                    print(f"\n--- YENİ MESAJ ({algo} - {mode}) ---")
                    print(f"Şifreli: {cipher_text[:50]}...") # Çok uzunsa kes

                    decrypted_text = ""
                    server_key = "RSA Private Key (Gizli)"

                    # ALGORİTMA SEÇİMİ
                    if algo == 'aes':
                        print("AES Çözme Anahtarını Girin:")
                        server_key = input(">> ")
                        if mode == 'manual':
                            # Manuel decrypt implementasyonu yoksa uyarı ver
                            decrypted_text = "Manuel Decrypt Serverda Henüz Aktif Değil (Lib Kullanılıyor)"
                            decrypted_text = aes.decrypt_lib(cipher_text, server_key)
                        else:
                            decrypted_text = aes.decrypt_lib(cipher_text, server_key)

                    elif algo == 'des':
                        print("DES Çözme Anahtarını Girin:")
                        server_key = input(">> ")
                        decrypted_text = des.decrypt_lib(cipher_text, server_key)
                    
                    elif algo == 'rsa':
                        print("RSA Mesajı alınıyor, otomatik çözülüyor...")
                        decrypted_text = rsa_algo.decrypt(cipher_text, PRIVATE_KEY)

                    # Sonuç Gönderimi
                    if "Hata" in decrypted_text:
                        status = "Hata"
                        resp = {"status": "error", "message": decrypted_text}
                    else:
                        status = "Başarılı"
                        resp = {"status": "success", "plaintext": decrypted_text}
                    
                    print(f"Sonuç: {decrypted_text}")
                    log_to_file(f"{algo}_{mode}", cipher_text, server_key, decrypted_text, status)
                    conn.sendall(json.dumps(resp).encode('utf-8'))

                except json.JSONDecodeError:
                    print("Veri hatası")
                except Exception as e:
                    print(f"Server Hatası: {e}")

if __name__ == "__main__":
    start_server()