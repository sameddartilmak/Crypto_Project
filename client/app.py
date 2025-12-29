from flask import Flask, render_template, request, jsonify
import socket
import json
import sys
import os
import time
import secrets
import string
import struct 

# Üst klasördeki modülleri görebilmek için yol ekle
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# --- TÜM ALGORİTMALARI IMPORT ET ---
from ciphers import aes, des, rsa, ecc, caesar, vigenere, affine, rail_fence, substitution, columnar, hill, polybius, vernam, playfair, root

app = Flask(__name__)
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432

def recv_all(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet: return None
        data += packet
    return data

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_key', methods=['POST'])
def generate_key_route():
    data = request.json
    algo = data.get('algorithm')
    text_length = data.get('text_length', 0)

    key = ""
    try:
        if algo == 'aes': key = secrets.token_urlsafe(16)[:16] 
        elif algo == 'des': key = secrets.token_urlsafe(8)[:8]
        elif algo == 'ecc': key = "ECC-AUTO-KEY" 
        elif algo == 'vernam':
            if text_length > 0: key = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(text_length))
            else: return jsonify({'status': 'error', 'message': 'Vernam için metin/dosya girin!'})
        elif algo == 'affine': key = "5,8" 
        elif algo == 'hill': key = "6 24 1 13" 
        elif algo == 'playfair': key = "MONARCHY"
        elif algo == 'polybius': key = "SIFRE"
        elif algo in ['rail_fence', 'sezar', 'rot', 'root']: key = str(secrets.randbelow(5) + 2) 
        else: key = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(8))

        return jsonify({'status': 'success', 'key': key})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

def get_server_keys():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_HOST, SERVER_PORT))
            msg = json.dumps({"type": "GET_PUBLIC_KEY"}).encode('utf-8')
            s.sendall(struct.pack('>I', len(msg)) + msg)
            
            raw_msglen = recv_all(s, 4)
            if not raw_msglen: return None
            
            msglen = struct.unpack('>I', raw_msglen)[0]
            data = recv_all(s, msglen)
            
            if not data: return None
            return json.loads(data.decode('utf-8'))
    except:
        return None

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
            start_time = time.perf_counter() 
            
            if algo == 'aes':
                if mode == 'manual': encrypted_text = aes.encrypt_manual(text, key)
                else: encrypted_text = aes.encrypt_lib(text, key)
            elif algo == 'des':
                if mode == 'manual': encrypted_text = des.encrypt_manual(text, key) 
                else: encrypted_text = des.encrypt_lib(text, key)
            
            duration = round(time.perf_counter() - start_time, 6)

            keys = get_server_keys()
            if not keys or 'public_key' not in keys:
                return jsonify({'status': 'error', 'message': 'Server RSA Anahtarı Vermedi!'})
            
            encrypted_key = rsa.encrypt(key, keys.get('public_key'))

        # --- ECC (DÜZELTİLDİ: MOD KONTROLÜ EKLENDİ) ---
        elif algo == 'ecc':
            keys = get_server_keys()
            if not keys: 
                return jsonify({'status': 'error', 'message': 'Server Anahtarı Vermedi!'})
            
            start_time = time.perf_counter()
            
            if mode == 'manual':
                # Manuel Mod için 'ecc_manual_key' kullan
                server_pub = keys.get('ecc_manual_key')
                if not server_pub: return jsonify({'status': 'error', 'message': 'Server Manual ECC Key Vermedi!'})
                encrypted_text = ecc.encrypt_manual(text, server_pub)
            else:
                # Lib Modu için 'ecc_lib_key' kullan
                server_pub = keys.get('ecc_lib_key')
                if not server_pub: return jsonify({'status': 'error', 'message': 'Server Lib ECC Key Vermedi!'})
                encrypted_text = ecc.encrypt_lib(text, server_pub)
                
            duration = round(time.perf_counter() - start_time, 6)

        # --- RSA (Legacy) ---
        elif algo == 'rsa':
            keys = get_server_keys()
            if not keys: return jsonify({'status': 'error', 'message': 'Server Kapalı!'})
            
            start_time = time.perf_counter()
            encrypted_text = rsa.encrypt(text, keys.get('public_key'))
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
            'mode_used': mode
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# --- 3. SERVER'A GÖNDER VE CEVABI ÇÖZ ---
@app.route('/send_to_server', methods=['POST'])
def send_server():
    data = request.json
    client_key = data.get('client_key')
    algo = data.get('algorithm')
    mode = data.get('mode')

    payload = json.dumps({
        'type': 'MESSAGE',
        'algorithm': algo,
        'mode': mode,
        'ciphertext': data.get('ciphertext'),
        'encrypted_key': data.get('encrypted_key'),
        'filename': data.get('filename')
    }).encode('utf-8')
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_HOST, SERVER_PORT))
            s.sendall(struct.pack('>I', len(payload)) + payload)
            
            raw_msglen = recv_all(s, 4)
            if not raw_msglen:
                return jsonify({'status': 'error', 'message': 'Server cevap vermedi'})
            
            msglen = struct.unpack('>I', raw_msglen)[0]
            response_data = recv_all(s, msglen)
            
            server_resp = json.loads(response_data.decode('utf-8'))
            
            if server_resp.get('status') == 'error':
                return jsonify(server_resp)

            server_cipher = server_resp.get('server_ciphertext', '')
            server_key = server_resp.get('server_key', '')
            
            decrypted_reply = "Çözülemedi"
            try:
                use_key = server_key if server_key else client_key

                if not server_cipher: decrypted_reply = "Server boş cevap döndü."
                
                elif algo == 'aes':
                    if mode == 'manual': decrypted_reply = aes.decrypt_manual(server_cipher, use_key)
                    else: decrypted_reply = aes.decrypt_lib(server_cipher, use_key)
                elif algo == 'des':
                    if mode == 'manual': decrypted_reply = des.decrypt_manual(server_cipher, use_key)
                    else: decrypted_reply = des.decrypt_lib(server_cipher, use_key)
                
                elif algo == 'ecc': decrypted_reply = "ECC modunda server cevabı şifreli değildir."
                elif algo == 'rsa': decrypted_reply = "RSA desteklenmiyor."
                
                # Klasikler
                elif algo == 'sezar': decrypted_reply = caesar.decrypt(server_cipher, use_key)
                elif algo == 'vigenere': decrypted_reply = vigenere.decrypt(server_cipher, use_key)
                elif algo == 'affine': decrypted_reply = affine.decrypt(server_cipher, use_key)
                elif algo == 'rail_fence': decrypted_reply = rail_fence.decrypt(server_cipher, use_key)
                elif algo == 'substitution': decrypted_reply = substitution.decrypt(server_cipher, use_key)
                elif algo == 'columnar': decrypted_reply = columnar.decrypt(server_cipher, use_key)
                elif algo == 'hill': decrypted_reply = hill.decrypt(server_cipher, use_key)
                elif algo == 'polybius': decrypted_reply = polybius.decrypt(server_cipher, use_key)
                elif algo == 'vernam': decrypted_reply = vernam.decrypt(server_cipher, use_key)
                elif algo == 'playfair': decrypted_reply = playfair.decrypt(server_cipher, use_key)
                elif algo == 'root': decrypted_reply = root.decrypt(server_cipher, use_key)

            except: pass

            return jsonify({
                'status': 'success',
                'plaintext': server_resp.get('plaintext'),
                'server_reply_decrypted': decrypted_reply,
                'server_key_used': server_key
            })

    except Exception as e:
        return jsonify({'status': 'error', 'message': f"Bağlantı Hatası: {str(e)}"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)