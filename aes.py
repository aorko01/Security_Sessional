from aes_helpers import Sbox,Rcon

def normalize_key(key: str) -> bytes:
    key = key.encode('ascii')

    if len(key) < 16:
        key = key.ljust(16, b'\0')   # pad with null bytes
    elif len(key) > 16:
        key = key[:16]               # truncate

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

def expand_key_round(prev_words: list, round: int) -> list:
    w0, w1, w2, w3 = prev_words

    temp = g(w3, round)

    w4 = add_round_key(w0, temp)
    w5 = add_round_key(w1, w4)
    w6 = add_round_key(w2, w5)
    w7 = add_round_key(w3, w6)

    return [w4, w5, w6, w7]

def expand_key(key: bytes) -> list:
    words = []
    for i in range(4):
        word = key[4*i : 4*i + 4]
        words.append(word)

    for round in range(1, 11):
        next_words = expand_key_round(words[-4:], round)
        words.extend(next_words)

    return words




def add_round_key(plain:bytes, key: bytes) -> bytes:
    result = []
    for x, y in zip(plain, key):
        result.append(x ^ y)

    return bytes(result)

