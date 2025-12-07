from flask import Flask, render_template, request, jsonify
import socket
import json
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ciphers import aes, des, rsa_algo

app = Flask(__name__)

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    data = request.json
    algo = data.get('algorithm') # aes, des, rsa
    mode = data.get('mode')      # lib, manual
    text = data.get('text')
    key = data.get('key')        # AES/DES için key
    
    encrypted_text = ""

    try:
        if algo == 'aes':
            if mode == 'manual':
                encrypted_text = aes.encrypt_manual(text, key)
            else:
                encrypted_text = aes.encrypt_lib(text, key)
                
        elif algo == 'des':
            if mode == 'manual':
                # des.py içinde encrypt_manual ismini düzelttiysen burası çalışır
                encrypted_text = des.encrypt_manual(text, key) 
            else:
                encrypted_text = des.encrypt_lib(text, key)
                
        elif algo == 'rsa':
            # RSA için Server'dan Public Key istemeliyiz
            public_key = get_server_public_key()
            if not public_key:
                return jsonify({'status': 'error', 'message': 'Server Public Key alınamadı!'})
            
            encrypted_text = rsa_algo.encrypt(text, public_key)

        return jsonify({'status': 'success', 'ciphertext': encrypted_text})

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

def get_server_public_key():
    """Socket ile servera bağlanıp Public Key ister"""
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
        'ciphertext': data.get('ciphertext')
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