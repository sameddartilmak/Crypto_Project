from flask import Flask, render_template, request, jsonify
import socket
import json
import sys
import os
import time
import secrets
import string

# Üst klasördeki modülleri görebilmek için yol ekle
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# --- TÜM ALGORİTMALARI EKSİKSİZ IMPORT ET ---
from ciphers import aes, des, rsa, caesar, vigenere, affine, rail_fence, substitution, columnar, hill, polybius, vernam, playfair, root

app = Flask(__name__)

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432

@app.route('/')
def index():
    return render_template('index.html')

# --- 1. RASTGELE ANAHTAR ÜRETME ---
@app.route('/generate_key', methods=['POST'])
def generate_key_route():
    data = request.json
    algo = data.get('algorithm')
    text_length = data.get('text_length', 0)

    key = ""
    try:
        if algo == 'aes': key = secrets.token_urlsafe(16)[:16] 
        elif algo == 'des': key = secrets.token_urlsafe(8)[:8]   
        elif algo == 'vernam':
            if text_length > 0: key = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(text_length))
            else: return jsonify({'status': 'error', 'message': 'Vernam için metin girmelisiniz!'})
        elif algo == 'affine': key = "5,8" 
        elif algo == 'hill': key = "6 24 1 13" 
        elif algo == 'playfair': key = "MONARCHY"
        elif algo == 'polybius': key = "SIFRE"
        elif algo in ['rail_fence', 'sezar', 'rot', 'root']: key = str(secrets.randbelow(5) + 2) 
        else: key = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(8))

        return jsonify({'status': 'success', 'key': key})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# --- 2. ŞİFRELEME VE SÜRE ÖLÇÜMÜ ---
@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    data = request.json
    algo = data.get('algorithm') 
    mode = data.get('mode')      
    text = data.get('text')
    key = data.get('key')        
    
    encrypted_text = ""
    encrypted_key = None 
    duration = 0

    try:
        # --- HİBRİT SİSTEM (AES ve DES) ---
        if algo in ['aes', 'des']:
            # 1. ADIM: Hassas Süre Ölçümü (Sadece Şifreleme)
            start_time = time.perf_counter() 
            
            if algo == 'aes':
                # Blokları açıkça ayırıyoruz
                if mode == 'manual':
                    # Manuel Mod (Yavaş Olmalı)
                    encrypted_text = aes.encrypt_manual(text, key)
                else:
                    # Kütüphane Modu (Hızlı Olmalı)
                    encrypted_text = aes.encrypt_lib(text, key)
                    
            elif algo == 'des':
                if mode == 'manual':
                    encrypted_text = des.encrypt_manual(text, key) 
                else:
                    encrypted_text = des.encrypt_lib(text, key)
            
            end_time = time.perf_counter()
            duration = round(end_time - start_time, 6) # Hassas ölçüm

            # 2. ADIM: RSA İşlemleri (Süreye dahil değil)
            public_key = get_server_public_key()
            if not public_key:
                return jsonify({'status': 'error', 'message': 'Server Public Key alınamadı!'})
            encrypted_key = rsa.encrypt(key, public_key)

        # --- RSA ---
        elif algo == 'rsa':
            public_key = get_server_public_key()
            if not public_key:
                return jsonify({'status': 'error', 'message': 'Server Public Key alınamadı!'})
            
            start_time = time.perf_counter()
            encrypted_text = rsa.encrypt(text, public_key)
            duration = round(time.perf_counter() - start_time, 6)

        # --- KLASİK ŞİFRELEMELER ---
        else:
            start_time = time.perf_counter()
            
            if algo == 'sezar': encrypted_text = caesar.encrypt(text, key)
            elif algo == 'vigenere': encrypted_text = vigenere.encrypt(text, key)
            elif algo == 'affine': encrypted_text = affine.encrypt(text, key)
            elif algo == 'rail_fence': encrypted_text = rail_fence.encrypt(text, key)
            elif algo == 'substitution': encrypted_text = substitution.encrypt(text, key)
            elif algo == 'columnar': encrypted_text = columnar.encrypt(text, key)
            elif algo == 'hill': encrypted_text = hill.encrypt(text, key)
            elif algo == 'polybius': encrypted_text = polybius.encrypt(text, key)
            elif algo == 'vernam':  encrypted_text = vernam.encrypt(text, key)
            elif algo == 'playfair': encrypted_text = playfair.encrypt(text, key)
            elif algo == 'root':  encrypted_text = root.encrypt(text, key)
            
            duration = round(time.perf_counter() - start_time, 6)

        return jsonify({
            'status': 'success', 
            'ciphertext': encrypted_text,
            'encrypted_key': encrypted_key,
            'duration': duration,
            'mode_used': mode # Hangi modun kullanıldığını client'a geri bildir (Test için)
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

def get_server_public_key():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_HOST, SERVER_PORT))
            payload = {"type": "GET_PUBLIC_KEY"}
            s.sendall(json.dumps(payload).encode('utf-8'))
            data = s.recv(4096)
            resp = json.loads(data.decode('utf-8'))
            return resp.get('public_key')
    except:
        return None

# --- 3. SERVER'A GÖNDER VE CEVABI ÇÖZ ---
@app.route('/send_to_server', methods=['POST'])
def send_server():
    data = request.json
    algo = data.get('algorithm')
    mode = data.get('mode')
    ciphertext = data.get('ciphertext')
    encrypted_key = data.get('encrypted_key')
    client_key = data.get('client_key')

    payload = {
        'type': 'MESSAGE',
        'algorithm': algo,
        'mode': mode,
        'ciphertext': ciphertext,
        'encrypted_key': encrypted_key
    }
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_HOST, SERVER_PORT))
            s.sendall(json.dumps(payload).encode('utf-8'))
            
            # Server'dan cevap bekle
            response_data = s.recv(16384)
            server_resp = json.loads(response_data.decode('utf-8'))
            
            if server_resp.get('status') == 'error':
                return jsonify(server_resp)

            server_ciphertext = server_resp.get('server_ciphertext', '')
            server_new_key = server_resp.get('server_key', '')
            
            decrypted_reply = "Çözülemedi"
            try:
                key_to_use = server_new_key if server_new_key else client_key

                if not server_ciphertext:
                    decrypted_reply = "Server boş cevap döndü."
                elif algo == 'aes':
                    if mode == 'manual': decrypted_reply = aes.decrypt_manual(server_ciphertext, key_to_use)
                    else: decrypted_reply = aes.decrypt_lib(server_ciphertext, key_to_use)
                elif algo == 'des':
                    if mode == 'manual': decrypted_reply = des.decrypt_manual(server_ciphertext, key_to_use)
                    else: decrypted_reply = des.decrypt_lib(server_ciphertext, key_to_use)
                elif algo == 'rsa': decrypted_reply = "RSA desteklenmiyor."
                elif algo == 'sezar': decrypted_reply = caesar.decrypt(server_ciphertext, key_to_use)
                elif algo == 'vigenere': decrypted_reply = vigenere.decrypt(server_ciphertext, key_to_use)
                elif algo == 'affine': decrypted_reply = affine.decrypt(server_ciphertext, key_to_use)
                elif algo == 'rail_fence': decrypted_reply = rail_fence.decrypt(server_ciphertext, key_to_use)
                elif algo == 'substitution': decrypted_reply = substitution.decrypt(server_ciphertext, key_to_use)
                elif algo == 'columnar': decrypted_reply = columnar.decrypt(server_ciphertext, key_to_use)
                elif algo == 'hill': decrypted_reply = hill.decrypt(server_ciphertext, key_to_use)
                elif algo == 'polybius': decrypted_reply = polybius.decrypt(server_ciphertext, key_to_use)
                elif algo == 'vernam': decrypted_reply = vernam.decrypt(server_ciphertext, key_to_use)
                elif algo == 'playfair': decrypted_reply = playfair.decrypt(server_ciphertext, key_to_use)
                elif algo == 'root': decrypted_reply = root.decrypt(server_ciphertext, key_to_use)
                else: decrypted_reply = "Algoritma tanınmadı."

            except Exception as dec_err:
                decrypted_reply = f"Cevap Deşifre Hatası: {str(dec_err)}"

            return jsonify({
                'status': 'success',
                'plaintext': server_resp.get('plaintext'),
                'server_reply_decrypted': decrypted_reply,
                'server_key_used': server_new_key
            })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    app.run(debug=True, port=5000)