from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16

def _int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")

def _int_to_bytes(i: int, length: int) -> bytes:
    return i.to_bytes(length, byteorder="big")

def _aes_ebc_encrypt(key: bytes, block: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block)

def xor_bytes(plain_block: bytes, keystream_block: bytes) -> bytes:
    # a^b XORs, zip returns touples so pairing the plaintext block xi to the keystream block yi and for each pair (a,b) we xor
    return bytes(a^b for a, b in zip(plain_block, keystream_block))

def KeyGen() -> bytes:
    return get_random_bytes(BLOCK_SIZE)

def CustomEncrypt(plaintext: bytes, key: bytes) -> bytes:
    #Generate nonceand and convert to int
    nonce = get_random_bytes(BLOCK_SIZE)
    nonce_int = _int_from_bytes(nonce)

    ct = bytearray()

    # Encrypt plaintext in blocks // Handle last block if not multiple of block size = 16
    for block_index in range((len(plaintext) + BLOCK_SIZE-1) // BLOCK_SIZE):
        #Create counter = nonce + block_index mod 2^128 where the modulo is implemented using 1<< 128 -1 using bitwise AND
        counter = (nonce_int + block_index) & ((1 << 128) - 1)
        counter_block = _int_to_bytes(counter, BLOCK_SIZE)

        keystream = _aes_ebc_encrypt(key, counter_block)
        
        start = block_index * BLOCK_SIZE
        end = min(start + BLOCK_SIZE, len(plaintext))
        plain_block = plaintext[start:end]
        
        ct_block = xor_bytes(plain_block, keystream[: end-start])
        ct.extend(ct_block)

    return (nonce, bytes(ct))
    
def CustomDecrypt(cipherText: tuple, key: bytes) -> bytes:
    nonce = cipherText[0]
    ciphertext = cipherText[1]
    nonce_int = _int_from_bytes(nonce)
    
    pt = bytearray()
    
    for block_index in range((len(ciphertext) + BLOCK_SIZE - 1) // BLOCK_SIZE):
        #Create counter = nonce + block_index mod 2^128 where the modulo is implemented using 1<< 128 -1 using bitwise AND
        counter = (nonce_int + block_index) & ((1 << 128) - 1)
        counter_block = _int_to_bytes(counter, BLOCK_SIZE)
        
        keystream = _aes_ebc_encrypt(key, counter_block)
        
        start = block_index * BLOCK_SIZE
        end = min(start + BLOCK_SIZE, len(ciphertext))
        ct_block = ciphertext[start:end]
        
        pt_block = xor_bytes(ct_block, keystream[: end-start])
        pt.extend(pt_block)
    
    return bytes(pt)
        
if __name__ == "__main__":
    key = KeyGen()
    message = b"Hello, World! This is a test message for encryption, to test the length variations."
    for i in range(len(message)):
        cipherText = CustomEncrypt(message[:i], key)
        print()
        print("Cipher Text: ", cipherText)
        decryptedMessage = CustomDecrypt(cipherText, key)
        print("Decrypted Message: ", decryptedMessage)

