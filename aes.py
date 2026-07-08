from aes_helpers import Sbox,Rcon

def normalize_key(key: str, size: int = 16) -> bytes:
    if size not in (16, 24, 32):
        raise ValueError("size must be 16, 24, or 32 bytes (128/192/256-bit key)")

    key = key.encode('ascii')

    if len(key) < size:
        key = key.ljust(size, b'\0')   # pad with null bytes
    elif len(key) > size:
        key = key[:size]               # truncate

    return key

def rotate_word(word:bytes)->bytes:
    return word[1:]+word[:1]

def substitute_bytes(word:bytes)->bytes:
    word1=[]
    for i in word:
        word1.append(Sbox[i])
        
    return bytes(word1)

def shift_rows(word:bytes)->bytes:
    result = bytearray(16)
    
        
def g(word:bytes,round:int)->bytes:
    #rotate
    word=rotate_word(word)
    #substitute
    word=substitute_bytes(word)
    
    word = bytes([
        word[0] ^ Rcon[round],
        word[1],
        word[2],
        word[3]
    ])

    return word

def expand_key_round(words: list, i: int, word_count: int) -> bytes:
    temp = words[i - 1]

    if i % word_count == 0:
        temp = g(temp, i // word_count)
    elif word_count > 6 and i % word_count == 4:
        temp = substitute_bytes(temp)

    return add_round_key(words[i - word_count], temp)

def expand_key(key: bytes) -> list:
    Nk = len(key) // 4  # 4 for AES-128, 6 for AES-192, 8 for AES-256

    if Nk == 4:
        Nr = 10
    elif Nk == 6:
        Nr = 12
    elif Nk == 8:
        Nr = 14
    else:
        raise ValueError(f"Invalid key length: {len(key)} bytes (expected 16, 24, or 32)")
    
    
    total_words = 4 * (Nr + 1)
    words = []
    for i in range(Nk):
        words.append(key[4*i : 4*i + 4])

    for round in range(Nk, total_words):
        next_words = expand_key_round(words, i, Nk)
        words.extend(next_words)

    return words




def add_round_key(plain:bytes, key: bytes) -> bytes:
    result = []
    for x, y in zip(plain, key):
        result.append(x ^ y)

    return bytes(result)

