"""
Module for verifying RSA-signed image files using a public key.

This script extracts a hidden digital signature from an image using LSB steganography,
computes the SHA-256 hash of the original image, and verifies the signature
against a public RSA key.

Example usage:
    python verify.py

Required files:
    - The signed image file (e.g., 'example_signed_melon.png')
    - The original unsigned image file (e.g., 'melone.png')
    - The public RSA key in PEM format (e.g., 'public.pem')

The result will be printed: valid (authentic image) or invalid (tampered or forged).
"""

from typing import Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from stegano import lsb


def load_public_key(path: str) -> rsa.RSAPublicKey:
    """
    Load an RSA public key from a PEM file.

    Args:
        path (str): Path to the public key PEM file.

    Returns:
        rsa.RSAPublicKey: The loaded RSA public key object.
    """
    with open(path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())


def verify_image(image_path: str, original_image_path: str, public_key_path: str) -> None:
    """
    Verify the digital signature hidden in an image using the original image and public key.

    The function reads the original image data and retrieves a hidden signature (in hex format)
    from the signed image using LSB steganography. It then uses the public key to verify whether
    the signature matches the original image.

    Args:
        image_path (str): Path to the signed image (with hidden signature).
        original_image_path (str): Path to the original unsigned image.
        public_key_path (str): Path to the public RSA key in PEM format.

    Prints:
        Result of the verification: valid or tampered image.
    """
    public_key: rsa.RSAPublicKey = load_public_key(public_key_path)

    with open(original_image_path, "rb") as file:
        original_data: bytes = file.read()

    signature_hex: Optional[str] = lsb.reveal(image_path)
    if not signature_hex:
        print("Signature not found in the image.")
        return

    signature: bytes = bytes.fromhex(signature_hex)

    try:
        public_key.verify(
            signature,
            original_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        print("Signature is valid. Image is authentic.")
    except InvalidSignature:
        print("Signature is invalid or the image has been modified.")
    except (ValueError, TypeError) as error:
        print("Signature verification failed due to malformed data.")
        print(f"Details: {error}")


if __name__ == "__main__":
    verify_image(
        image_path="test_photos/example_signed_melon.png",
        original_image_path="test_photos/melon.png",
        public_key_path="keys/public.pem",
    )
