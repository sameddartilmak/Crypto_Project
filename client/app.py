from flask import Flask, render_template, request, jsonify
import socket
import json
import sys
import os

# Üst klasördeki modülleri görebilmek için
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ciphers import caesar, vigenere, affine, rail_fence, substitution, columnar, des, aes

app = Flask(__name__)

# Algoritma haritası
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

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    data = request.json
    algo_name = data.get('algorithm')
    plaintext = data.get('text')
    key = data.get('key')
    
    module = ALGO_MAP.get(algo_name)
    
    if not module:
        return jsonify({'error': 'Algoritma bulunamadı'})
    
    try:
        # Şifreleme işlemini yap
        encrypted_text = module.encrypt(plaintext, key)
        
        # Sonuçta hata mesajı var mı kontrol et
        if "Hata" in encrypted_text:
             return jsonify({'status': 'error', 'message': encrypted_text})
             
        return jsonify({'status': 'success', 'ciphertext': encrypted_text})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/send_to_server', methods=['POST'])
def send_server():
    data = request.json
    # Server'a gönderilecek paket
    payload = {
        'algorithm': data.get('algorithm'),
        'ciphertext': data.get('ciphertext')
    }
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_HOST, SERVER_PORT))
            s.sendall(json.dumps(payload).encode('utf-8'))
            
            # Server'dan cevap bekle
            response = s.recv(4096)
            response_data = json.loads(response.decode('utf-8'))
            
            return jsonify(response_data)
    except ConnectionRefusedError:
        return jsonify({'status': 'error', 'message': 'Server kapalı veya ulaşılamıyor.'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    app.run(debug=True, port=5000)