import socket
import json
import sys
import os
import datetime
import secrets
import string
import time
import base64
import struct  # YENİ: Veri boyutunu paketlemek için şart

# Üst klasördeki modülleri görebilmek için yol ekle
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# --- TÜM MODÜLLERİ EKSİKSİZ IMPORT ET ---
from ciphers import aes, des, rsa, caesar, vigenere, affine, rail_fence, substitution, columnar, hill, polybius, vernam, playfair, root

# RSA Key Üretimi
print("\n" + "="*50)
print("SERVER BAŞLATILIYOR...")
print("RSA Anahtarları üretiliyor... Lütfen bekleyin.")
PRIVATE_KEY, PUBLIC_KEY = rsa.generate_keys()

# KAYIT ANA KLASÖRÜ
MAIN_SAVE_DIR = "server_received_files"
if not os.path.exists(MAIN_SAVE_DIR):
    os.makedirs(MAIN_SAVE_DIR)

print(f"RSA Hazır! Dosyalar '{MAIN_SAVE_DIR}' altındaki klasörlere kaydedilecek.")
print("="*50 + "\n")

HOST = '127.0.0.1'
PORT = 65432

# YARDIMCI FONKSİYON: Tam olarak n byte veri gelene kadar bekler (Büyük dosyalar için kritik)
def recv_all(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet: return None
        data += packet
    return data

def generate_server_key(algo, text_length=0):
    try:
        if algo == 'aes': return secrets.token_urlsafe(16)[:16]
        elif algo == 'des': return secrets.token_urlsafe(8)[:8]
        elif algo == 'vernam': return ''.join(secrets.choice(string.ascii_uppercase) for _ in range(text_length))
        elif algo == 'affine': return "5,8"
        elif algo == 'hill': return "6 24 1 13"
        elif algo == 'playfair': return "SERVERKEY"
        elif algo == 'polybius': return "SECRET"
        elif algo in ['rail_fence', 'sezar', 'rot', 'root']: return str(secrets.randbelow(5) + 2)
        else: return ''.join(secrets.choice(string.ascii_uppercase) for _ in range(8))
    except: return "KEYERROR"

def get_save_path(filename):
    """Dosya uzantısına göre klasör belirler"""
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    
    if ext in ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp']:
        subdir = 'images'
    elif ext in ['pdf', 'docx', 'doc', 'xlsx', 'pptx', 'odt']:
        subdir = 'documents'
    elif ext in ['txt', 'md', 'py', 'c', 'cpp', 'html', 'css', 'js', 'json']:
        subdir = 'text'
    else:
        subdir = 'others'
    
    full_path = os.path.join(MAIN_SAVE_DIR, subdir)
    if not os.path.exists(full_path):
        os.makedirs(full_path)
        
    return os.path.join(full_path, filename)

def log_to_file(algo, encrypted, key, decrypted, status):
    filename = f"logs_{algo}.txt"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(filename, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] Durum: {status}\n")
            f.write(f"Şifreli (Özet): {encrypted[:50]}...\n")
            f.write(f"Anahtar: {key}\n")
            f.write(f"Çözülen (Özet): {decrypted[:50]}...\n")
            f.write("-" * 30 + "\n")
    except Exception as e:
        print(f"Loglama Hatası: {e}")

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"✅  Server {HOST}:{PORT} üzerinde dinleniyor... (Kapatmak için Ctrl+C)")
        
        while True:
            try:
                conn, addr = server_socket.accept()
                with conn:
                    # 1. ADIM: İlk 4 byte'ı oku (Bu verinin uzunluğudur)
                    # struct.calcsize('>I') -> 4 byte
                    raw_msglen = recv_all(conn, 4)
                    if not raw_msglen: break
                    
                    # Verinin uzunluğunu çöz (Big Endian Integer)
                    msglen = struct.unpack('>I', raw_msglen)[0]
                    
                    # 2. ADIM: Belirtilen uzunluk kadar veriyi bekle
                    data = recv_all(conn, msglen)
                    if not data: break
                    
                    try:
                        request = json.loads(data.decode('utf-8'))
                        req_type = request.get('type')
                        
                        # Public Key İsteği
                        if req_type == 'GET_PUBLIC_KEY':
                            payload = json.dumps({"status": "success", "public_key": PUBLIC_KEY.decode('utf-8')}).encode('utf-8')
                            # Cevabı da uzunluk bilgisiyle gönder
                            conn.sendall(struct.pack('>I', len(payload)) + payload)
                            continue
                        
                        # --- MESAJ/DOSYA GELDİ ---
                        algo = request.get('algorithm')
                        mode = request.get('mode')
                        cipher_text = request.get('ciphertext')
                        encrypted_key_b64 = request.get('encrypted_key') 
                        filename = request.get('filename')

                        msg_type = "DOSYA" if filename else "MESAJ"
                        print(f"\n{'='*20} YENİ {msg_type} GELDİ ({algo.upper()}) {'='*20}")
                        if filename: print(f"📁  Dosya Adı: {filename}")
                        
                        decrypted_text = ""
                        incoming_key = ""

                        # --- 1. DEŞİFRELEME ---
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
                        
                        elif algo == 'rsa':
                            decrypted_text = rsa.decrypt(cipher_text, PRIVATE_KEY)
                            incoming_key = "RSA Private Key"
                        
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

                        # --- DOSYA KAYDETME VE KLASÖRLEME ---
                        if filename and "Hata" not in decrypted_text:
                            try:
                                # Base64 verisini binary'ye çevirip kaydet
                                file_data = base64.b64decode(decrypted_text)
                                save_path = get_save_path(filename) # Klasörü belirle
                                
                                with open(save_path, "wb") as f:
                                    f.write(file_data)
                                    
                                print(f"💾  DOSYA KAYDEDİLDİ: {save_path}")
                                decrypted_text = f"[Dosya '{save_path}' konumuna kaydedildi]"
                            except Exception as e:
                                print(f"❌  Dosya Kaydetme Hatası: {e}")
                                decrypted_text = f"Dosya bozuk çözüldü: {e}"

                        print("-" * 50)
                        print(f"📩  İÇERİK             : {decrypted_text[:100]}...")
                        print(f"🔑  KULLANILAN ANAHTAR : {incoming_key}")
                        print("-" * 50)
                        
                        log_to_file(f"{algo}", cipher_text, incoming_key, decrypted_text, "Alındı")

                        # --- 2. CEVAP GÖNDERME ---
                        reply_msg = ""
                        server_ciphertext = ""
                        new_server_key = ""
                        duration = 0.0

                        if "Hata" not in decrypted_text:
                            print("\n💬  CLIENT'A CEVAP YAZIN:")
                            reply_msg = input("   MESAJINIZ >> ")
                            if not reply_msg: reply_msg = "Alındı."

                            new_server_key = generate_server_key(algo, len(reply_msg))
                            print(f"   Yeni Anahtar: {new_server_key} | Şifreleniyor...")

                            try:
                                start_time = time.perf_counter()

                                if algo == 'aes':
                                    server_ciphertext = aes.encrypt_manual(reply_msg, new_server_key) if mode == 'manual' else aes.encrypt_lib(reply_msg, new_server_key)
                                elif algo == 'des':
                                    server_ciphertext = des.encrypt_manual(reply_msg, new_server_key) if mode == 'manual' else des.encrypt_lib(reply_msg, new_server_key)
                                elif algo == 'rsa': server_ciphertext = "RSA ile cevap yok"
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
                                
                                end_time = time.perf_counter()
                                duration = round(end_time - start_time, 5)

                            except Exception as enc_err:
                                server_ciphertext = f"Cevap Şifreleme Hatası: {enc_err}"
                        
                        # Cevabı hazırla
                        resp_dict = {
                            "status": "success", 
                            "plaintext": decrypted_text,
                            "server_ciphertext": server_ciphertext,
                            "server_key": new_server_key
                        }
                        
                        resp_bytes = json.dumps(resp_dict).encode('utf-8')
                        
                        # GÜVENLİ GÖNDERİM: [4 Byte Boyut] + [Veri]
                        conn.sendall(struct.pack('>I', len(resp_bytes)) + resp_bytes)
                        print(f"✅  Cevap Gönderildi. ({duration}s)\n")

                    except json.JSONDecodeError: print("JSON Hatası: Veri bozuk gelmiş olabilir.")
                    except Exception as e: print(f"İşlem Hatası: {e}")

            except ConnectionResetError: print("⚠️  Client bağlantıyı kesti (WinError 10054).")
            except Exception as e: print(f"⚠️  Bağlantı Hatası: {e}")

    except KeyboardInterrupt: print("\n🛑  Server Kapatılıyor...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()