import jwt
import os
import base64
import time
import uuid
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

PRIVATE_KEY_NAME =  'TEST_PRIVATE_KEY'
PRIVATE_KEY_PASS_NAME =  'TEST_PRIVATE_KEY_PASS'
REQUIRED_KEYS =  ['aud', 'email', 'name', 'roles']
REQUIRED_KEYS_TYPES =  ['str', 'str', 'str', 'list']
ISSUER_KEY =  'iss'
ISSUER_VALUE =  'ref-codes-python'
ISSUED_AT_KEY = "iat"
EXPIRES_AT_KEY = "exp"
EXPIRY_DURATION_MINS = 30
TOKEN_ID_KEY = "jti"

_pk_B64 = os.environ[PRIVATE_KEY_NAME]
if not _pk_B64:
    raise ValueError(f'Private key ({PRIVATE_KEY_NAME}) not set')

_pk = base64.b64decode(_pk_B64) 
_pk_pass_B64 = os.environ[PRIVATE_KEY_PASS_NAME]
_pk_pass = base64.b64decode(_pk_pass_B64) 

PRIVATE_KEY = serialization.load_pem_private_key(
    _pk, password=_pk_pass, backend=default_backend())

def createJwt(values:dict):
    for i, k in enumerate(REQUIRED_KEYS):
        if k not in values:
            raise ValueError(f'Values does not contain {k}', k)
        if type(values[k]).__name__ !=  REQUIRED_KEYS_TYPES[i]:
            raise ValueError(f'Values does not contain {k} in the correct format', k)

    payload = values.copy()
    payload[ISSUER_KEY] = ISSUER_VALUE

    ct = round(time.time() * 1000)
    payload[ISSUED_AT_KEY] = ct
    payload[EXPIRES_AT_KEY] = ct + (EXPIRY_DURATION_MINS * 60 * 1000)

    payload[TOKEN_ID_KEY] = str(uuid.uuid4())

    print(f"Payload - {payload}")
    return jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")

