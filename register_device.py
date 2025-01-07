import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import Name, NameAttribute
from cryptography.x509 import CertificateSigningRequestBuilder
from cryptography.x509.oid import NameOID
import datetime
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
import base64
import time
import json
import sys
from lxml import etree

# Shout out to the following resources which were invaluable in creating this script:
## @DrAzureAd - https://aadinternals.com/post/devices/
## @dirkjanm - https://github.com/dirkjanm/ROADtools/

def generate_transport_key():
    cert = X509Certificate2(subject='cn=somewhere', keySize=2048, notBefore=(-40*365), notAfter=(40*365))
    pubKey = cert.ExportRSAPublicKeyBCrypt()
    cert.ExportPFX('output/transport_key', '')
    print("[*] Transport key saved to output/transport_key.pfx (empty password)")
    return base64.b64encode(pubKey.toRawBytes())

def generate_device_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    subject = Name([
        NameAttribute(NameOID.COUNTRY_NAME, "US"),
        NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        NameAttribute(NameOID.ORGANIZATION_NAME, "My Organization"),
        NameAttribute(NameOID.COMMON_NAME, "mydomain.com"),
    ])
    
    csr_builder = CertificateSigningRequestBuilder()
    csr_builder = csr_builder.subject_name(subject)

    # Sign CSR with the private key
    csr = csr_builder.sign(
        private_key, hashes.SHA256()
    )
    
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    csr_pem = csr.public_bytes(
        encoding=serialization.Encoding.PEM
    )

    # Save to files
    with open("output/private_key.pem", "wb") as f:
        f.write(private_key_pem)

    with open("output/csr.pem", "wb") as f:
        f.write(csr_pem)
        
    print("[*] Private key for Device saved to output/private_key.pem")
    print("[*] CSR for Device saved to output/csr.pem")
        
    return csr_pem

def register_device_soap(hostname, csr):
    
    # Device Auth Flow
    device_code_url = f"https://{hostname}/adfs/oauth2/devicecode"
    response = requests.post(device_code_url, data="client_id=dd762716-544d-4aeb-a526-687b73838a22&resource=urn:ms-drs:434DF4A9-3CF2-4C1D-917E-2CD2B72F515A", verify=False)
    csr = csr.replace(b"\n", b"").replace(b"\r", b"").replace(b"-----BEGIN CERTIFICATE REQUEST-----", b"").replace(b"-----END CERTIFICATE REQUEST-----", b"")
    
    print("Please authenticate with the following code: " + response.json()["verification_uri_complete"])
    
    # Wait until the user authenticates
    token = ""
    while token == "":
        time.sleep(response.json()["interval"])
        response_poll = requests.post(f"https://{hostname}/adfs/oauth2/token", data="client_id=dd762716-544d-4aeb-a526-687b73838a22&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&resource=urn:ms-drs:434DF4A9-3CF2-4C1D-917E-2CD2B72F515A&code=" + response.json()["device_code"], verify=False)
        if "access_token" in response_poll.json():
            token = response_poll.json()["access_token"]
            
    with open("./data/DeviceEnrollmentWebService.xml", "rb") as f:
        xml = f.read()
        
    xml = xml.replace(b"{access_token}", base64.b64encode(token.encode('ascii')))
    xml = xml.replace(b"{csr}", csr)
    
    # Make the registration request
    response_registration = requests.post(f"https://{hostname}/EnrollmentServer/DeviceEnrollmentWebService.svc", headers={ "Content-Type": "application/soap+xml; charset=utf-8" }, data=xml, verify=False)
    #print(response_registration.text)
    
    # Parse XML for response
    root = etree.fromstring(response_registration.text)
    items = root.xpath("//*[local-name()='BinarySecurityToken']")
    if len(items) == 1:
        print("[*] Device registered successfully")
        # Save the key to a file
        registration_cert_xml = base64.b64decode(items[0].text)
        with open("output/device_registration.xml", "wb") as f:
            f.write(registration_cert_xml)
            
    root = etree.fromstring(response_registration.text)
    items = root.xpath("//*[local-name()='parm']")
    if len(items) == 1:
        cert = items.get("value")
        with open("output/device_registration.crt", "wb") as f:
            f.write(base64.b64decode(cert))
            
    print("[*] Device Registration certificate written to output/device_registration.crt")
    
def register_device_rest(hostname, csr, transport_key):
    
    # Device Auth Flow
    device_code_url = f"https://{hostname}/adfs/oauth2/devicecode"
    response = requests.post(device_code_url, data="client_id=dd762716-544d-4aeb-a526-687b73838a22&resource=urn:ms-drs:434DF4A9-3CF2-4C1D-917E-2CD2B72F515A", verify=False)
    csr = csr.replace(b"\n", b"").replace(b"\r", b"").replace(b"-----BEGIN CERTIFICATE REQUEST-----", b"").replace(b"-----END CERTIFICATE REQUEST-----", b"")
    
    print("Please authenticate with the following code: " + response.json()["verification_uri_complete"])
    
    # Wait until the user authenticates
    token = ""
    while token == "":
        time.sleep(response.json()["interval"])
        response_poll = requests.post(f"https://{hostname}/adfs/oauth2/token", data="client_id=dd762716-544d-4aeb-a526-687b73838a22&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&resource=urn:ms-drs:434DF4A9-3CF2-4C1D-917E-2CD2B72F515A&code=" + response.json()["device_code"], verify=False)
        if "access_token" in response_poll.json():
            token = response_poll.json()["access_token"]
            
    with open("./data/enroll.json", "rb") as f:
        request = json.load(f)
        
    request["CertificateRequest"]["Data"] = csr.decode("utf-8")
    request["TransportKey"] = transport_key.decode("utf-8")
    
    # Make the registration request
    response_registration = requests.post(f"https://{hostname}/EnrollmentServer/device/?api-version=1.0", headers={ "Content-Type": "application/json", "Authorization": "Bearer " + token }, data=json.dumps(request), verify=False)
    reg_response = response_registration.json()
    cert = reg_response["Certificate"]["RawBody"]
    with open("output/device_registration.crt", "wb") as f:
        f.write(base64.b64decode(cert))
        
    print("[*] Device Registration certificate written to output/device_registration.crt")

if __name__ == "__main__":
    
    if len(sys.argv) != 3:
        print("Usage: python3 register_device.py (soap/rest) <hostname>")
        sys.exit(1)
    
    device_public_key = generate_device_key()
    device_transport_key = generate_transport_key()
    
    if sys.argv[1].lower().startswith("rest"):
        register_device_rest(sys.argv[2], device_public_key, device_transport_key)
    else:
        register_device_soap(sys.argv[2], device_public_key)