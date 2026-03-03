import json
import base64
import requests
import base58
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

# Load signed metadata.json and proof
with open("metadata.json", "r") as f:
    metadata = json.load(f)

proof = metadata["data"]["proof"]
signature_b64url = proof["signatureValue"]

# Convert base64url -> raw r||s bytes
raw_sig = base64.urlsafe_b64decode(signature_b64url + "==")  # pad if needed
r = int.from_bytes(raw_sig[:32], "big")
s = int.from_bytes(raw_sig[32:], "big")

# Resolve the DID document from did:web
did_url = "https://hashtag.terrasphere.space/.well-known/did.json"
did_doc = requests.get(did_url).json()

# Extract the Multikey public key
vm = did_doc["verificationMethod"][0]
pk_multibase = vm["publicKeyMultibase"]

# Decode multibase (remove 'z' prefix)
multicodec_bytes = base58.b58decode(pk_multibase[1:])

# Remove multicodec prefix for P-256 (0x80 0x24)
compressed_pub = multicodec_bytes[2:]

# Reconstruct public key
public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), compressed_pub)

# Recreate DER signature from raw r||s
der_sig = encode_dss_signature(r, s)

# Prepare the data that was signed (only metadata values)
signed_data = metadata.copy()
# select only the metadata
metadata_values = signed_data["data"]['metadata']
data_bytes = json.dumps(metadata_values, separators=(",", ":"), sort_keys=True).encode()

# Verify the signature
try:
    public_key.verify(
        der_sig,
        data_bytes,
        ec.ECDSA(hashes.SHA256())
    )
    print("Signature verified successfully!")
except Exception as e:
    print("Signature verification failed:", e)