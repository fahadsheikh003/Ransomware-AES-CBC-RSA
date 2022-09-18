from Crypto.PublicKey import RSA

# generating private key
key = RSA.generate(2048)

# exporting private key
private_key = key.export_key()
with open("ransomprvkey.pem", "wb") as f:
    f.write(private_key)

# exporting public key corresponding to generated private key
public_key = key.publickey().export_key()
with open("ransompubkey.pem", "wb") as f:
    f.write(public_key)