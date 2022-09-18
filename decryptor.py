from os import walk, rename
from os.path import join, exists
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from base64 import b64decode

class Decryptor:
    def __init__(self) -> None:
        # checking if decrypted session keyd (decrypted AES symmetric keys) exists or not
        if not exists("ransomkey.txt"):
            print("'ransomkey.txt' not found..")
            exit(1)
        
        self.file_types = ['.pdf', '.doc', '.txt']
        self.session_key = {}
        self.iv = {}
        
        # loading decrypted AES symmetric key and IVs against files that are encrypted
        with open("ransomkey.txt", "rb") as f:
            for key in self.file_types:
                self.session_key[key] = b64decode(f.readline())
            data = f.read().splitlines()

        # parsing IVs
        for eachIV in data:
            IV_List = eachIV.decode().split(':')
            file_name = IV_List[0]
            iv = IV_List[1]

            file_name = b64decode(file_name.encode('ascii')).decode('ascii')
            iv = b64decode(iv)

            self.iv[file_name] = iv
        
    # to decrypt a file
    def decrypt_file(self, file_path: str, file_name: str, file_type: str) -> None:
        # reading content of file
        with open(file_path, "r") as f:
            data = b64decode(f.read())
        
        # removing .enc from file name
        new_file_name = file_name[:-4]

        # checking if IVs against file is stored or not
        if new_file_name in self.iv:
            iv = self.iv[new_file_name]
        else:
            return

        # instantiating AES cipher
        cipher_aes = AES.new(self.session_key[file_type], AES.MODE_CBC, iv)
        plaintext = unpad(cipher_aes.decrypt(data), AES.block_size)

        # storing decrypted binary to file
        try:
            with open(file_path, "wb") as f:
                f.write(plaintext)
            rename(file_path, file_path[:-4]) # renaming file (to avaid re-decryption)
            print(new_file_name, "decrypted")
        except:
            print(new_file_name, "not decrypted")

    # to find type of file
    def find_file_type(self, file_name: str) -> str:
        for file_type in self.file_types:
            if file_type in file_name:
                return file_type
        return ""

    def decrypt_files(self, directory: str):
        # finding all the files in the directory recursively
        system = walk(directory, topdown=True)
        for root, dir, files in system:
            for file in files:
                if ".enc" in file: # if file is encrypted
                    file_path = join(root, file)
                    file_type = self.find_file_type(file)
                    if file_type != "":
                        self.decrypt_file(file_path, file, file_type)
                    
dec = Decryptor()
dec.decrypt_files("mydirectory")