# Ransomware-AES-CBC-RSA

# This ransomware is implemented using pycryptodome module

**Hierarchy**
    
    1. Firstly, generate public and private keys RSA
    2. Then, change the directory in the encryptor.py and decryptor.py
    3. To encrypt files, run encryptor.py
    4. For decryption, run ransom_keys_decryptor.py to decrypt AES symmetric key (that was used for encryption of files) with private key (that was generated in the first step)
    5. Now, just run decryptor.py to decrypt files in the specified directory
     
