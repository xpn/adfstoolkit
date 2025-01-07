## ADFSToolkit

A collection of scripts to support the blog post "ADFS - Living in the Legacy of DRS"

### register_device.py

This script allows registering a new device using ADFS DRS with either the SOAP method (DeviceEnrollmentWebService.svc) or REST method (EnrollmentServer/device/):

```
# Register using SOAP method of DeviceEnrollmentWebService.svc
python ./register_device.py soap adfs.lab.local

# Register using REST method of EnrollmentServer/device/?api-version=1.0
python ./register_device.py rest adfs.lab.local
```

Two new keys will be written to the `output` directory:

* transport_key.pfx - Key registered to be added to `msDS-KeyCredentialLink`
* private_key.pem - Device Registration private key
* csr.pem - CSR used for Device Registration request
* device_registration.crt - Signed Device Registration certificate

### eprt.py

This script uses the transport key and device private key generated in `register_device.py` to generate a new Enterprise PRT

Two methods of authentication are supported:

* Password - Takes a username / password combination to associate the account to the EPRT
* Refresh Token - Takes a refresh token for a user account to associate to the EPRT

```
# Use Password authentication
python ./eprt.py adfs.lab.local ./output/device_registration.crt ./output/private_key.pem ./output/transport_key.pfx 'itadmin@lab.local' 'Pass@word1'

# Use Refresh Token authentication
python ./eprt.py adfs.lab.local ./output/device_registration.crt ./output/private_key.pem ./output/transport_key.pfx REFRESH_TOKEN_GOES_HERE
```

Both a PRT and Session Token will be outputted from this script for use with `access_token.py`

### access_token.py

This script uses the generated Enterprise PRT from `eprt.py` to request either an access token for a target OAuth2 provider, or a value for the `x-ms-RefreshTokenCredential` HTTP header:

```
# Request an access token
python ./access_token.py adfs.lab.local prt EPRT SESSION_KEY <CLIENT_ID> <RESOURCE_ID> scope1,scope2,scope3

# Request a header for `x-ms-RefreshTokenCredential`
python ./access_token.py adfs.lab.local header EPRT SESSION_KEY
```

### golden_jwt.py

This script takes an example JWT and signs it using a compromised ADFS signing key:

```
python ./golden_jwt.py <private_key_path> <cert_path> <claims_path>
```