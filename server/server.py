import socket
import json
import sys
import os
import datetime
import secrets
import string
import time

# Üst klasördeki modülleri görebilmek için yol ekle
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# --- TÜM MODÜLLERİ EKSİKSİZ IMPORT ET ---
from ciphers import aes, des, rsa, caesar, vigenere, affine, rail_fence, substitution, columnar, hill, polybius, vernam, playfair, root

# RSA Key Üretimi
print("\n" + "="*50)
print("SERVER BAŞLATILIYOR...")
print("RSA Anahtarları üretiliyor... Lütfen bekleyin.")
PRIVATE_KEY, PUBLIC_KEY = rsa.generate_keys()
print("RSA Anahtarları Hazır! Client bekleniyor...")
print("="*50 + "\n")

HOST = '127.0.0.1'
PORT = 65432

def generate_server_key(algo, text_length=0):
    """Server cevabı için rastgele anahtar üretir"""
    try:
        if algo == 'aes': return secrets.token_urlsafe(16)[:16]
        elif algo == 'des': return secrets.token_urlsafe(8)[:8]
        elif algo == 'vernam': 
            return ''.join(secrets.choice(string.ascii_uppercase) for _ in range(text_length))
        elif algo == 'affine': return "5,8"
        elif algo == 'hill': return "6 24 1 13"
        elif algo == 'playfair': return "SERVERKEY"
        elif algo == 'polybius': return "SECRET"
        elif algo in ['rail_fence', 'sezar', 'rot', 'root']: 
            return str(secrets.randbelow(5) + 2)
        else: # Vigenere, Columnar vb.
            return ''.join(secrets.choice(string.ascii_uppercase) for _ in range(8))
    except:
        return "KEYERROR"

def log_to_file(algo, encrypted, key, decrypted, status):
    filename = f"logs_{algo}.txt"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(filename, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] Durum: {status}\n")
            f.write(f"Şifreli: {encrypted}\n")
            f.write(f"Anahtar: {key}\n")
            f.write(f"Çözülen: {decrypted}\n")
            f.write("-" * 30 + "\n")
    except Exception as e:
        print(f"Loglama Hatası: {e}")

def start_server():
    # Socket oluşturma
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # "Address already in use" hatasını önlemek için
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"✅  Server {HOST}:{PORT} üzerinde dinleniyor... (Kapatmak için Ctrl+C)")
        
        while True:
            try:
                conn, addr = server_socket.accept()
                with conn:
                    data = conn.recv(16384) 
                    if not data: break
                    
                    try:
                        request = json.loads(data.decode('utf-8'))
                        req_type = request.get('type')
                        
                        # Public Key İsteği
                        if req_type == 'GET_PUBLIC_KEY':
                            response = {"status": "success", "public_key": PUBLIC_KEY.decode('utf-8')}
                            conn.sendall(json.dumps(response).encode('utf-8'))
                            continue
                        
                        # --- MESAJ GELDİ ---
                        algo = request.get('algorithm')
                        mode = request.get('mode')
                        cipher_text = request.get('ciphertext')
                        encrypted_key_b64 = request.get('encrypted_key') 

                        print(f"\n{'='*20} YENİ MESAJ GELDİ ({algo.upper()}) {'='*20}")
                        
                        decrypted_text = ""
                        incoming_key = ""

                        # --- 1. DEŞİFRELEME (Mesajı Çöz) ---
                        # HİBRİT (AES / DES)
                        if algo in ['aes', 'des']:
                            if not encrypted_key_b64:
                                decrypted_text = "Hata: Şifreli anahtar pakette yok!"
                            else:
                                session_key = rsa.decrypt(encrypted_key_b64, PRIVATE_KEY)
                                if "Hata" in session_key:
                                    decrypted_text = f"RSA Anahtar Çözme Hatası: {session_key}"
                                else:
                                    incoming_key = session_key 
                                    if algo == 'aes':
                                        decrypted_text = aes.decrypt_manual(cipher_text, incoming_key) if mode == 'manual' else aes.decrypt_lib(cipher_text, incoming_key)
                                    elif algo == 'des':
                                        decrypted_text = des.decrypt_manual(cipher_text, incoming_key) if mode == 'manual' else des.decrypt_lib(cipher_text, incoming_key)
                        
                        # RSA (Direkt Mesaj)
                        elif algo == 'rsa':
                            decrypted_text = rsa.decrypt(cipher_text, PRIVATE_KEY)
                            incoming_key = "RSA Private Key"
                        
                        # KLASİK ŞİFRELEMELER
                        else:
                            print(f"⚠️  {algo.upper()} için anahtar gereklidir.")
                            incoming_key = input("   CLIENT'IN ANAHTARINI GİRİN >> ")
                            
                            if algo == 'sezar': decrypted_text = caesar.decrypt(cipher_text, incoming_key)
                            elif algo == 'vigenere': decrypted_text = vigenere.decrypt(cipher_text, incoming_key)
                            elif algo == 'affine': decrypted_text = affine.decrypt(cipher_text, incoming_key)
                            elif algo == 'rail_fence': decrypted_text = rail_fence.decrypt(cipher_text, incoming_key)
                            elif algo == 'substitution': decrypted_text = substitution.decrypt(cipher_text, incoming_key)
                            elif algo == 'columnar': decrypted_text = columnar.decrypt(cipher_text, incoming_key)
                            elif algo == 'hill': decrypted_text = hill.decrypt(cipher_text, incoming_key)
                            elif algo == 'polybius': decrypted_text = polybius.decrypt(cipher_text, incoming_key)
                            elif algo == 'vernam': decrypted_text = vernam.decrypt(cipher_text, incoming_key)
                            elif algo == 'playfair': decrypted_text = playfair.decrypt(cipher_text, incoming_key)
                            elif algo == 'root': decrypted_text = root.decrypt(cipher_text, incoming_key)
                            else: decrypted_text = f"Hata: Bilinmeyen Algoritma"

                        # --- SONUÇLARI YAZDIR ---
                        print("-" * 50)
                        print(f"📩  OKUNAN MESAJ       : {decrypted_text}")
                        print(f"🔑  KULLANILAN ANAHTAR : {incoming_key}")
                        print("-" * 50)
                        
                        log_to_file(f"{algo}", cipher_text, incoming_key, decrypted_text, "Alındı")

                        # --- 2. CEVAP GÖNDERME (Manuel Giriş + Yeni Random Key) ---
                        reply_msg = ""
                        server_ciphertext = ""
                        new_server_key = ""
                        duration = 0.0

                        if "Hata" not in decrypted_text:
                            print("\n💬  CLIENT'A CEVAP YAZIN:")
                            reply_msg = input("   MESAJINIZ >> ")
                            
                            if not reply_msg: reply_msg = "Mesaj Alındı (Otomatik)"

                            # YENİ ANAHTAR ÜRET
                            new_server_key = generate_server_key(algo, len(reply_msg))
                            print(f"   Yeni Anahtar Üretildi: {new_server_key}")
                            print("   Şifreleniyor ve Gönderiliyor...")

                            try:
                                start_time = time.perf_counter() # SÜRE ÖLÇÜMÜ BAŞLA

                                if algo == 'aes':
                                    server_ciphertext = aes.encrypt_manual(reply_msg, new_server_key) if mode == 'manual' else aes.encrypt_lib(reply_msg, new_server_key)
                                elif algo == 'des':
                                    server_ciphertext = des.encrypt_manual(reply_msg, new_server_key) if mode == 'manual' else des.encrypt_lib(reply_msg, new_server_key)
                                elif algo == 'rsa':
                                    server_ciphertext = "RSA ile cevap desteklenmiyor"
                                elif algo == 'sezar': server_ciphertext = caesar.encrypt(reply_msg, new_server_key)
                                elif algo == 'vigenere': server_ciphertext = vigenere.encrypt(reply_msg, new_server_key)
                                elif algo == 'affine': server_ciphertext = affine.encrypt(reply_msg, new_server_key)
                                elif algo == 'rail_fence': server_ciphertext = rail_fence.encrypt(reply_msg, new_server_key)
                                elif algo == 'substitution': server_ciphertext = substitution.encrypt(reply_msg, new_server_key)
                                elif algo == 'columnar': server_ciphertext = columnar.encrypt(reply_msg, new_server_key)
                                elif algo == 'hill': server_ciphertext = hill.encrypt(reply_msg, new_server_key)
                                elif algo == 'polybius': server_ciphertext = polybius.encrypt(reply_msg, new_server_key)
                                elif algo == 'vernam': server_ciphertext = vernam.encrypt(reply_msg, new_server_key)
                                elif algo == 'playfair': server_ciphertext = playfair.encrypt(reply_msg, new_server_key)
                                elif algo == 'root': server_ciphertext = root.encrypt(reply_msg, new_server_key)
                                
                                end_time = time.perf_counter() # SÜRE ÖLÇÜMÜ BİTİR
                                duration = round(end_time - start_time, 5)

                            except Exception as enc_err:
                                server_ciphertext = f"Cevap Şifreleme Hatası: {enc_err}"
                        
                        # Sonuç Paketi
                        resp = {
                            "status": "success", 
                            "plaintext": decrypted_text,
                            "server_ciphertext": server_ciphertext,
                            "server_key": new_server_key # Server'ın ürettiği yeni anahtar
                        }
                        
                        conn.sendall(json.dumps(resp).encode('utf-8'))
                        print(f"✅  Cevap Gönderildi. (Şifreleme Süresi: {duration}s)\n")

                    except json.JSONDecodeError: print("JSON Hatası: Geçersiz veri.")
                    except Exception as e: print(f"İşlem Hatası: {e}")

            except ConnectionResetError:
                print("⚠️  Client bağlantıyı kesti.")
            except Exception as e:
                print(f"⚠️  Bağlantı Hatası: {e}")

    except KeyboardInterrupt:
        print("\n\n🛑  Server kapatılıyor... (Ctrl+C Algılandı)")
    except Exception as e:
        print(f"\n❌  Server başlatılamadı: {e}")
    finally:
        server_socket.close()
        print("🔒  Socket kapatıldı. Çıkış yapıldı.")

if __name__ == "__main__":
    start_server()