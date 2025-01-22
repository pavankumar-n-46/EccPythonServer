from flask import Flask, request, jsonify
from base64 import b64decode, b64encode
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import os
import base64

app = Flask(__name__)

# Generate a new private key (for testing)
private_key = ec.generate_private_key(ec.SECP256R1())  
public_key = private_key.public_key()

# Global variable for storing the peer's public key
global_public_key = None
PUBLIC_KEY_FILE = "public_key.pem"

def save_public_key_to_file(public_key):
    """Save public key to a PEM file"""
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_public_key_from_file():
    """Load public key from PEM file if available"""
    global global_public_key
    if os.path.exists(PUBLIC_KEY_FILE):
        with open(PUBLIC_KEY_FILE, "rb") as f:
            public_key_pem = f.read()
            global_public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
            print("✅ Loaded public key from file.")

# Load public key at startup
load_public_key_from_file()

@app.route('/exchange', methods=['POST'])
def exchange():
    global global_public_key
    try:
        data = request.get_json()
        print(f"\n🔹 Received Data: {data}")

        public_key_pem = data['publicKey']
        print(f"🔹 Received Public Key (Base64): {public_key_pem}")

        # Convert base64 to bytes
        public_key_bytes = base64.b64decode(public_key_pem)

        # Ensure it's a valid compressed public key (33 bytes, starts with 02 or 03)
        if len(public_key_bytes) != 33 or public_key_bytes[0] not in [2, 3]:
            raise ValueError("Invalid compressed public key format")

        # Load the received public key
        peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_bytes)
        print(f"✅ Decoded Peer Public Key")

        # Store the public key globally and persist it
        global_public_key = peer_public_key
        save_public_key_to_file(peer_public_key)

        # Perform ECDH key agreement
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

        # Derive a shared symmetric key using HKDF
        symmetric_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'',
            backend=default_backend()
        ).derive(shared_secret)

        # Send back a derived symmetric key
        shared_secret_b64 = base64.b64encode(symmetric_key).decode('utf-8')
        print(f"✅ Shared Secret (Base64): {shared_secret_b64}")
        return jsonify({'sharedSecret': shared_secret_b64})

    except Exception as e:
        print(f"❌ Error in /exchange: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/verify', methods=['POST'])
def verify():
    try:
        # Get the request data
        data = request.json.get("data")
        signature_base64 = request.json.get("signature")
        public_key_base64 = request.json.get("publicKey")

        print(f"\n🔹 Received Data: {data}")
        print(f"🔹 Received Signature (Base64): {signature_base64}")
        print(f"🔹 Received Public Key (Base64): {public_key_base64}")

        # Decode the received public key (DER format)
        public_key_bytes = base64.b64decode(public_key_base64)
        print(f"🔹 Decoded Public Key Bytes (DER): {public_key_bytes.hex()}")

        # Load the public key from the DER-encoded format
        peer_public_key = serialization.load_der_public_key(public_key_bytes, backend=default_backend())
        print(f"🔹 Loaded Public Key: {peer_public_key}")

        # Decode the signature
        signature_der = base64.b64decode(signature_base64)
        print(f"🔹 Signature (DER Bytes): {signature_der.hex()}")

        # Verify the signature using the received public key
        peer_public_key.verify(
            signature_der,
            data.encode("utf-8"),
            ec.ECDSA(hashes.SHA256())
        )

        print("✅ Signature verified successfully")
        return jsonify({"status": "verified"})

    except Exception as e:
        print(f"❌ Signature verification failed: {e}")
        return jsonify({"status": "failed", "error": str(e)}), 400

@app.route('/sign', methods=['POST'])
def sign_data():
    try:
        data = request.json.get('data')
        print(f"\n🔹 Data to sign: {data}")

        signature = private_key.sign(
            data.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )

        signature_b64 = b64encode(signature).decode('utf-8')
        print(f"✅ Generated Signature (Base64): {signature_b64}")
        return jsonify({"signature": signature_b64})

    except Exception as e:
        print(f"❌ Signing failed: {e}")
        return jsonify({"error": "Signing failed", "details": str(e)}), 400
    
@app.route('/encrypt', methods=['POST'])
def encrypt():
    global shared_symmetric_key
    try:
        if shared_symmetric_key is None:
            print("❌ Encryption failed: Shared secret not established.")
            return jsonify({"error": "Shared secret not established. Call /exchange first."}), 400

        data = request.json.get("data")
        print(f"\n🔹 Encrypting Data: {data}")

        plaintext_bytes = data.encode('utf-8')

        # Generate a 12-byte nonce for AES-GCM
        nonce = os.urandom(12)
        print(f"🔹 Generated Nonce (Base64): {b64encode(nonce).decode()}")

        # Encrypt using AES-GCM
        aesgcm = AESGCM(shared_symmetric_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)

        ciphertext_b64 = b64encode(ciphertext).decode('utf-8')
        nonce_b64 = b64encode(nonce).decode('utf-8')

        print(f"✅ Encrypted Ciphertext (Base64): {ciphertext_b64}")
        print(f"✅ Encrypted Nonce (Base64): {nonce_b64}")

        response = {
            "ciphertext": ciphertext_b64,
            "nonce": nonce_b64
        }
        return jsonify(response)

    except Exception as e:
        print(f"❌ Encryption failed: {e}")
        return jsonify({"error": f"Encryption failed: {str(e)}"}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    global shared_symmetric_key
    try:
        if shared_symmetric_key is None:
            print("❌ Decryption failed: Shared secret not established.")
            return jsonify({"error": "Shared secret not established. Call /exchange first."}), 400

        ciphertext_b64 = request.json.get("ciphertext")
        nonce_b64 = request.json.get("nonce")

        print(f"\n🔹 Received Ciphertext (Base64): {ciphertext_b64}")
        print(f"🔹 Received Nonce (Base64): {nonce_b64}")

        ciphertext = b64decode(ciphertext_b64)
        nonce = b64decode(nonce_b64)

        # Decrypt using AES-GCM
        aesgcm = AESGCM(shared_symmetric_key)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        plaintext = plaintext_bytes.decode('utf-8')

        print(f"✅ Decrypted Plaintext: {plaintext}")
        return jsonify({"plaintext": plaintext})

    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)