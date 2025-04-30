"""
Module for digitally signing image files using RSA cryptography and steganography.

This script reads an image file, computes its SHA-256 hash,
creates a digital signature using the sender's private RSA key,
and embeds the signature into the image using LSB (Least Significant Bit) steganography.
The output is a signed image visually identical to the original, compatible with standard viewers.

Example usage:
    python sign.py

Required files:
    - An input image file (e.g., 'melone.png')
    - A private RSA key in PEM format (e.g., 'private.pem')

The signed image will be saved with the embedded signature (e.g., 'example_signed_melon.png').
"""

from typing import Any
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from stegano import lsb


def load_private_key(path: str) -> rsa.RSAPrivateKey:
    """
    Load a private RSA key from a PEM file.

    Args:
        path (str): Path to the private key file in PEM format.

    Returns:
        rsa.RSAPrivateKey: A loaded RSA private key object.
    """
    with open(path, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )


def sign_image(image_path: str, private_key_path: str, output_path: str) -> None:
    """
    Digitally sign an image and embed the signature using LSB steganography.

    The function reads an image file as binary, signs it using the RSA private key,
    converts the signature to hexadecimal format, and hides it inside the image using LSB.

    Args:
        image_path (str): Path to the original image file.
        private_key_path (str): Path to the RSA private key in PEM format.
        output_path (str): Path to save the signed (output) image.
    """
    private_key: rsa.RSAPrivateKey = load_private_key(private_key_path)

    with open(image_path, "rb") as file:
        image_data: bytes = file.read()

    signature: bytes = private_key.sign(
        image_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    signature_hex: str = signature.hex()
    secret_image: Any = lsb.hide(image_path, signature_hex)
    secret_image.save(output_path)
    print(f"Image successfully signed and saved to: {output_path}")

if __name__ == "__main__":
    sign_image(
        image_path="test_photos/melon.png",
        private_key_path="keys/private.pem",
        output_path="test_photos/example_signed_melon.png",
    )
