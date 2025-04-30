"""
Module for generating RSA key pairs in PEM format.

This script creates a 4096-bit RSA private/public key pair using Python's cryptography library.
The keys are serialized and saved in PEM format to the specified file paths.

Example usage:
    python generate_keys.py

Output files:
    - Private key (e.g., 'private.pem')
    - Public key (e.g., 'public.pem')
"""

from pathlib import Path
from typing import NoReturn
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keys(private_key_path: str, public_key_path: str, key_size: int = 4096)-> NoReturn:
    """
    Generate an RSA key pair and store them in PEM format.

    The function creates a private and public RSA key with a specified key length,
    serializes them to PEM format, and writes them to the provided file paths.

    Args:
        private_key_path (str): File path to save the private key (e.g., "keys/private.pem").
        public_key_path (str): File path to save the public key (e.g., "keys/public.pem").
        key_size (int): RSA key size in bits (default is 4096).

    Returns:
        NoReturn: This function does not return any value.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    private_pem: bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    Path(private_key_path).write_bytes(private_pem)

    public_key = private_key.public_key()
    public_pem: bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    Path(public_key_path).write_bytes(public_pem)

    print(
        "Keys successfully generated:\n"
        f"Private: {private_key_path}\n"
        f"Public:  {public_key_path}"
    )


if __name__ == "__main__":
    generate_rsa_keys(
        private_key_path="keys/private.pem",
        public_key_path="keys/public.pem",
        key_size=4096,
    )
