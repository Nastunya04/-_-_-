"""
Module for digitally signing image files using RSA cryptography.

This script reads an image file, computes its SHA-256 hash,
creates a digital signature using the sender's private RSA key,
and appends the signature to the image file in a way that remains
compatible with standard image viewers.

Example usage:
    python sign_image.py

Required files:
    - An image file (e.g., 'image.jpg')
    - A private RSA key in PEM format (e.g., 'private.pem')

The signed image will be saved as a new file with the RSA signature
appended after a unique delimiter.
"""

import base64
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

SIGNATURE_TAG: bytes = b'<<<SIGNATURE>>>'

def sign_image(image_path: str, private_key_path: str, output_path: str) -> None:
    """
    Digitally signs an image using an RSA private key and appends the signature
    to the image file. The resulting file remains viewable as a valid image.

    Args:
        image_path (str): Path to the original image file (JPG, PNG, etc.).
        private_key_path (str): Path to the private RSA key in PEM format.
        output_path (str): Path to save the signed image with the appended signature.

    Raises:
        FileNotFoundError: If the image or key file does not exist.
        ValueError: If the private key file is invalid.
    """
    image_bytes: bytes = Path(image_path).read_bytes()
    image_hash: bytes = hashlib.sha256(image_bytes).digest()

    private_key = serialization.load_pem_private_key(
        Path(private_key_path).read_bytes(),
        password=None,
    )

    signature: bytes = private_key.sign(
        image_hash,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    encoded_signature: bytes = base64.b64encode(signature)
    signed_image: bytes = image_bytes + SIGNATURE_TAG + encoded_signature

    Path(output_path).write_bytes(signed_image)
    print(f"Signed image saved as: {output_path}")


if __name__ == "__main__":
    sign_image(
        image_path="test_photos/melon.jpg",
        private_key_path="keys/private.pem",
        output_path="test_photos/example_signed_melon.jpg"
    )
