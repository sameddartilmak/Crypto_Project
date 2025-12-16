from flask import Flask, render_template, request, jsonify
import socket
import json
import sys
import os

# Üst klasördeki modülleri görebilmek için yol ekle
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# --- TÜM ALGORİTMALARI IMPORT ET ---
from ciphers import aes, des, rsa, caesar, vigenere, affine, rail_fence, substitution, columnar, hill

app = Flask(__name__)

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    data = request.json
    algo = data.get('algorithm') 
    mode = data.get('mode')      
    text = data.get('text')
    key = data.get('key')        
    
    encrypted_text = ""
    encrypted_key = None # RSA ile şifrelenmiş anahtar (AES/DES için)

    try:
        # --- HİBRİT SİSTEM (AES ve DES) ---
        if algo in ['aes', 'des']:
            # 1. Önce Mesajı Şifrele (Kullanıcının girdiği anahtarla)
            if algo == 'aes':
                if mode == 'manual': encrypted_text = aes.encrypt_manual(text, key)
                else: encrypted_text = aes.encrypt_lib(text, key)
            elif algo == 'des':
                if mode == 'manual': encrypted_text = des.encrypt_manual(text, key) 
                else: encrypted_text = des.encrypt_lib(text, key)
            
            # 2. Sonra ANAHTARI Şifrele (RSA ile) - Hibrit Kısım
            public_key = get_server_public_key()
            if not public_key:
                return jsonify({'status': 'error', 'message': 'Server Public Key alınamadı!'})
            
            # Anahtarı RSA ile şifreliyoruz
            encrypted_key = rsa.encrypt(key, public_key)

        # --- RSA (Sadece Mesaj) ---
        elif algo == 'rsa':
            public_key = get_server_public_key()
            if not public_key:
                return jsonify({'status': 'error', 'message': 'Server Public Key alınamadı!'})
            encrypted_text = rsa.encrypt(text, public_key)

        # --- KLASİK ŞİFRELEMELER (Key şifrelenmez) ---
        else:
            if algo == 'sezar': encrypted_text = caesar.encrypt(text, key)
            elif algo == 'vigenere': encrypted_text = vigenere.encrypt(text, key)
            elif algo == 'affine': encrypted_text = affine.encrypt(text, key)
            elif algo == 'rail_fence': encrypted_text = rail_fence.encrypt(text, key)
            elif algo == 'substitution': encrypted_text = substitution.encrypt(text, key)
            elif algo == 'columnar': encrypted_text = columnar.encrypt(text, key)
            elif algo == 'hill': encrypted_text = hill.encrypt(text, key)

        return jsonify({
            'status': 'success', 
            'ciphertext': encrypted_text,
            'encrypted_key': encrypted_key # AES/DES ise dolu, diğerlerinde null döner
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

@app.route('/send_to_server', methods=['POST'])
def send_server():
    data = request.json
    payload = {
        'type': 'MESSAGE',
        'algorithm': data.get('algorithm'),
        'mode': data.get('mode'),
        'ciphertext': data.get('ciphertext'),
        'encrypted_key': data.get('encrypted_key') # Şifreli anahtarı da gönderiyoruz
    }
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_HOST, SERVER_PORT))
            s.sendall(json.dumps(payload).encode('utf-8'))
            response = s.recv(8192)
            return jsonify(json.loads(response.decode('utf-8')))
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    app.run(debug=True, port=5000)