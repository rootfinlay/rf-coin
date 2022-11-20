from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import hashlib

def Main(private_key_password):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size = 2048
    )

    encrypted_pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(bytes(private_key_password, encoding='utf8'))
    )

    pem_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_key_file = open("privkey-file.pem", "w+")
    private_key_file.write(encrypted_pem_private_key.decode())
    private_key_file.close()

    public_key_file = open("pubkey-file.pub", "w+")
    public_key_file.write(pem_public_key.decode())
    public_key_file.close()

    wallet_addr = hashlib.sha256(pem_public_key).hexdigest()
    print(wallet_addr)

if __name__ == '__main__':
    private_key_password = input("Please input a private key password:\n> ")
    Main(private_key_password)