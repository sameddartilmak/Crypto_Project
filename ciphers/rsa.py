# ciphers/rsa_algo.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def generate_keys(key_size=2048):
    """
    Server başlatıldığında çağrılır.
    2048 bitlik RSA anahtar çifti (Public ve Private) üretir.
    """
    try:
        key = RSA.generate(key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key
    except Exception as e:
        print(f"Anahtar Üretme Hatası: {e}")
        return None, None

def encrypt(text, public_key_pem):
    """
    Client tarafında kullanılır.
    Metni, Server'dan alınan Public Key ile şifreler.
    """
    try:
        # Public Key formatını yükle
        recipient_key = RSA.import_key(public_key_pem)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        
        # RSA ile şifrele (Metni byte'a çevir)
        encrypted_bytes = cipher_rsa.encrypt(text.encode('utf-8'))
        
        # Sonucu transfer edebilmek için Base64 string'e çevir
        return base64.b64encode(encrypted_bytes).decode('utf-8')
    except Exception as e:
        return f"RSA Şifreleme Hatası: {str(e)}"

def decrypt(encrypted_text_b64, private_key_pem):
    """
    Server tarafında kullanılır.
    Gelen şifreli Base64 metni, Server'ın Private Key'i ile çözer.
    """
    try:
        # Private Key'i yükle
        private_key = RSA.import_key(private_key_pem)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        
        # Base64'ten byte'a geri çevir
        encrypted_bytes = base64.b64decode(encrypted_text_b64)
        
        # Deşifrele
        decrypted_text = cipher_rsa.decrypt(encrypted_bytes)
        return decrypted_text.decode('utf-8')
    except Exception as e:
        return f"RSA Deşifre Hatası: {str(e)}"