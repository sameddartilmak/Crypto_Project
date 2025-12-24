# ciphers/rail_fence.py

def encrypt(text, key):
    """
    Rail Fence Şifreleme
    Anahtar (Key) Türü: Integer (Ray sayısı)
    """
    try:
        rail_count = int(key)
    except:
        return "Hata: Ray sayısı tam sayı olmalıdır."
        
    if rail_count <= 1: return text

    fence = [[] for _ in range(rail_count)]
    rail = 0
    direction = 1

    for char in text:
        fence[rail].append(char)
        rail += direction

        if rail == rail_count - 1 or rail == 0:
            direction *= -1

    return "".join(["".join(rail) for rail in fence])

def decrypt(text, key):
    """
    Rail Fence Deşifreleme
    """
    try:
        rail_count = int(key)
    except:
        return "Hata: Ray sayısı tam sayı olmalıdır."
        
    if rail_count <= 1: return text

    fence = [['\n' for _ in range(len(text))] for _ in range(rail_count)]
    direction = -1
    row, col = 0, 0

    for i in range(len(text)):
        if row == 0 or row == rail_count - 1:
            direction *= -1
        
        fence[row][col] = '*'
        col += 1
        row += direction

    index = 0
    for i in range(rail_count):
        for j in range(len(text)):
            if ((fence[i][j] == '*') and (index < len(text))):
                fence[i][j] = text[index]
                index += 1

    result = []
    row, col = 0, 0
    direction = -1
    for i in range(len(text)):
        if row == 0 or row == rail_count - 1:
            direction *= -1
            
        if fence[row][col] != '\n':
            result.append(fence[row][col])
            col += 1
            row += direction
            
    return "".join(result)