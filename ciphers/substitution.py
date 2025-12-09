
def encrypt(text, key):
    """
    Substitution (Yerine Koyma) Şifreleme
    Anahtar: 26 harflik karışık bir alfabe stringi olmalıdır.
    """
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key = key.upper()
    
    # Anahtar kontrolü
    if len(key) != 26 or not key.isalpha() or len(set(key)) != 26:
        return "Hata: Anahtar 26 farklı harften oluşan bir alfabe olmalıdır."

    # Çeviri tablosu oluştur
    # str.maketrans: Hangi harfin neye dönüşeceğini belirler
    table = str.maketrans(alphabet + alphabet.lower(), key + key.lower())
    
    return text.translate(table)

def decrypt(text, key):
    """
    Substitution Deşifreleme
    """
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key = key.upper()
    
    if len(key) != 26 or not key.isalpha() or len(set(key)) != 26:
        return "Hata: Anahtar 26 farklı harften oluşan bir alfabe olmalıdır."

    # Deşifreleme için tablonun tersini (Key -> Alfabe) oluşturuyoruz
    table = str.maketrans(key + key.lower(), alphabet + alphabet.lower())
    
    return text.translate(table)