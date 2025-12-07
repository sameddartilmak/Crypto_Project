import socket
import json
import sys
import os
import datetime

# Üst klasördeki 'ciphers' paketini görebilmek için yol ekliyoruz
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Şifreleme modüllerini içe aktar
from ciphers import caesar, vigenere, affine, rail_fence, substitution, columnar, des, aes

# Algoritma haritası (String isminden modüle erişmek için)
ALGO_MAP = {
    'sezar': caesar,
    'vigenere': vigenere,
    'affine': affine,
    'rail fence': rail_fence,
    'substitution': substitution,
    'columnar': columnar,
    'des': des,
    'aes': aes
}

HOST = '127.0.0.1'  # Localhost
PORT = 65432        # Port numarası

def log_to_file(algo, encrypted, key, decrypted, status):
    """Her işlemi kendi algoritma ismine göre dosyalar."""
    filename = f"logs_{algo.replace(' ', '_')}.txt"
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
        print("Web arayüzünden (Client) istek bekleniyor...")

        while True:
            conn, addr = s.accept()
            with conn:
                print(f"\nBağlantı kabul edildi: {addr}")
                data = conn.recv(4096)
                if not data:
                    break
                
                try:
                    # Gelen veriyi JSON olarak çözümle
                    request = json.loads(data.decode('utf-8'))
                    algo_name = request.get('algorithm')
                    cipher_text = request.get('ciphertext')
                    
                    print(f"\n--- YENİ İSTEK GELDİ ---")
                    print(f"Algoritma: {algo_name}")
                    print(f"Şifreli Metin: {cipher_text}")
                    
                    # Kullanıcıdan anahtar iste (Server tarafında manuel giriş)
                    print(f"Lütfen '{algo_name}' algoritması için çözme anahtarını girin:")
                    server_key = input(">> ")
                    
                    # İlgili modülü bul ve decrypt fonksiyonunu çağır
                    module = ALGO_MAP.get(algo_name)
                    
                    if module:
                        try:
                            decrypted_text = module.decrypt(cipher_text, server_key)
                            
                            # Basit bir hata kontrolü (String dönüyor mu?)
                            if "Hata" in decrypted_text:
                                status = "Başarısız"
                                response_data = {"status": "error", "message": decrypted_text}
                            else:
                                status = "Başarılı"
                                response_data = {"status": "success", "plaintext": decrypted_text}
                                
                            print(f"Sonuç ({status}): {decrypted_text}")
                            
                            # Dosyaya kaydet
                            log_to_file(algo_name, cipher_text, server_key, decrypted_text, status)
                            
                        except Exception as e:
                            print(f"Hata oluştu: {e}")
                            response_data = {"status": "error", "message": str(e)}
                            log_to_file(algo_name, cipher_text, server_key, str(e), "Kritik Hata")
                    else:
                        response_data = {"status": "error", "message": "Bilinmeyen Algoritma"}

                    # Client'a cevabı gönder
                    conn.sendall(json.dumps(response_data).encode('utf-8'))
                    print("Cevap gönderildi. Yeni istek bekleniyor...")
                    
                except json.JSONDecodeError:
                    print("Geçersiz veri formatı.")

if __name__ == "__main__":
    start_server()