"""
Module for verifying the RSA digital signature of an image file.

This script reads an image file that has been digitally signed by appending
a signature to its binary content. It then extracts the signature, computes
the SHA-256 hash of the image data, and verifies the signature using
the sender's public RSA key.

Example usage:
    python verify_signature.py

Required files:
    - A signed image file with an embedded signature after a delimiter.
    - A public RSA key in PEM format (e.g., 'public.pem').
"""

import base64
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

SIGNATURE_TAG: bytes = b'<<<SIGNATURE>>>'

def verify_image_signature(image_path: str, public_key_path: str) -> None:
    """
    Verifies the RSA digital signature appended to an image file.

    The function expects a signature to be appended to the image file
    after a predefined delimiter (SIGNATURE_TAG). It computes the SHA-256
    hash of the original image data and verifies the signature using the
    provided public RSA key.

    Args:
        image_path (str): Path to the signed image file.
        public_key_path (str): Path to the public RSA key in PEM format.

    Returns:
        None

    Raises:
        FileNotFoundError: If the image or key file does not exist.
        ValueError: If the key is malformed or the signature is missing.
    """
    full_data: bytes = Path(image_path).read_bytes()

    if SIGNATURE_TAG not in full_data:
        print("Signature not found.")
        return

    img_data, b64_signature = full_data.split(SIGNATURE_TAG)
    image_hash: bytes = hashlib.sha256(img_data).digest()
    signature: bytes = base64.b64decode(b64_signature)

    public_key = serialization.load_pem_public_key(
        Path(public_key_path).read_bytes()
    )

    try:
        public_key.verify(
            signature,
            image_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Signature is valid. The image is authentic.")
    except InvalidSignature:
        print("Signature is invalid or the image was modified.")


if __name__ == "__main__":
    verify_image_signature(
        image_path="test_photos/example_signed_melon.jpg",
        public_key_path="keys/public.pem"
    )
