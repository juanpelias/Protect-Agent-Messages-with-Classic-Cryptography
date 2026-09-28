import os
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# RFC 7919 / RFC 3526 3072-bit MODP Group (ffdhe3072)
FFDHE3072_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF", 16
)
FFDHE3072_G = 2

# Standard DH parameter setup for ffdhe3072
dh_params = dh.DHParameterNumbers(FFDHE3072_P, FFDHE3072_G).parameters()


def encode_field(data: bytes) -> bytes:
    """Length-prefix encoding: 4-byte big-endian length + field bytes."""
    return len(data).to_bytes(4, byteorder="big") + data


def parse_field(stream: bytes, offset: int) -> tuple[bytes, int]:
    """Parse a length-prefixed field and validate length boundaries."""
    if offset + 4 > len(stream):
        raise ValueError("Malformed transcript: Truncated length prefix")
    
    length = int.from_bytes(stream[offset:offset + 4], byteorder="big")
    offset += 4
    
    if offset + length > len(stream):
        raise ValueError("Malformed transcript: Declared field length exceeds data boundary")
    
    val = stream[offset:offset + length]
    return val, offset + length


def build_transcript(
    label: bytes,
    group_id: bytes,
    id_g: bytes,
    id_n: bytes,
    y_g: bytes,
    y_n: bytes,
    nonce_g: bytes,
    nonce_n: bytes
) -> bytes:
    """Constructs the canonical length-prefixed transcript."""
    # Enforce field length checks
    if len(y_g) != 384 or len(y_n) != 384:
        raise ValueError("DH public values must be exactly 384 bytes.")
    if len(nonce_g) != 16 or len(nonce_n) != 16:
        raise ValueError("Nonces must be exactly 16 bytes.")

    return (
        encode_field(label) +
        encode_field(group_id) +
        encode_field(id_g) +
        encode_field(id_n) +
        encode_field(y_g) +
        encode_field(y_n) +
        encode_field(nonce_g) +
        encode_field(nonce_n)
    )


def verify_transcript_structure(transcript_bytes: bytes) -> list[bytes]:
    """Parses and validates all fields of a canonical transcript."""
    offset = 0
    fields = []
    while offset < len(transcript_bytes):
        field, offset = parse_field(transcript_bytes, offset)
        fields.append(field)
    
    if len(fields) != 8:
        raise ValueError("Malformed transcript: Incorrect field count")
        
    return fields


def derive_keys(z_bytes: bytes, th: bytes) -> dict:
    """Executes the specified CSCE465 KDF pipeline."""
    # Master Key
    k_master = hashlib.sha256(b"CSCE465-KDF-v1" + z_bytes + th).digest()

    # Session Keys via HMAC-SHA256
    def hmac_derivation(label: bytes) -> bytes:
        return hmac.new(k_master, label + th, hashlib.sha256).digest()

    k_g2n_enc = hmac_derivation(b"gateway-to-node encryption")
    k_g2n_mac = hmac_derivation(b"gateway-to-node MAC")
    k_n2g_enc = hmac_derivation(b"node-to-gateway encryption")
    k_n2g_mac = hmac_derivation(b"node-to-gateway MAC")
    session_id = hmac_derivation(b"session identifier")[:8]

    return {
        "k_master": k_master,
        "k_g2n_enc": k_g2n_enc,
        "k_g2n_mac": k_g2n_mac,
        "k_n2g_enc": k_n2g_enc,
        "k_n2g_mac": k_n2g_mac,
        "session_id": session_id,
    }


class HandshakeParty:
    def __init__(self, identity: str, peer_identity: str):
        self.identity = identity.encode("utf-8")
        self.peer_identity = peer_identity.encode("utf-8")
        
        #  Long-term 3072-bit RSA key pair
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
        
        # Peer RSA Public Key (loaded out-of-band)
        self.peer_rsa_public_key = None

    def set_peer_public_key(self, peer_pub_key):
        self.peer_rsa_public_key = peer_pub_key

    def generate_ephemeral_dh(self):
        #  Generate fresh DH private key and 16-byte nonce
        self.dh_private_key = dh_params.generate_private_key()
        self.dh_pub_int = self.dh_private_key.public_key().public_numbers().y
        
        #  Public value encoded as 384-byte big-endian string
        self.dh_pub_bytes = self.dh_pub_int.to_bytes(384, byteorder="big")
        self.nonce = os.urandom(16)

    def sign_transcript(self, th: bytes) -> bytes:
        #  Sign role || SHA-256(transcript) using RSA-PSS
        payload = self.identity + th
        return self.rsa_private_key.sign(
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify_peer_signature(self, signature: bytes, peer_role: bytes, th: bytes):
        payload = peer_role + th
        self.peer_rsa_public_key.verify(
            signature,
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )


def execute_handshake():
    # Setup Parties
    gateway = HandshakeParty(identity="gateway", peer_identity="node")
    node = HandshakeParty(identity="node", peer_identity="gateway")

    # Exchange Long-term RSA Public Keys
    gateway.set_peer_public_key(node.rsa_public_key)
    node.set_peer_public_key(gateway.rsa_public_key)

    # Generate ephemeral parameters and nonces
    gateway.generate_ephemeral_dh()
    node.generate_ephemeral_dh()

    # Both construct the canonical length-prefixed transcript
    transcript = build_transcript(
        label=b"CSCE465-HS-v2",
        group_id=b"ffdhe3072",
        id_g=gateway.identity,
        id_n=node.identity,
        y_g=gateway.dh_pub_bytes,
        y_n=node.dh_pub_bytes,
        nonce_g=gateway.nonce,
        nonce_n=node.nonce
    )

    #  Validate transcript structure and TLV constraints
    verify_transcript_structure(transcript)
    th = hashlib.sha256(transcript).digest()

    # Create signatures
    sig_g = gateway.sign_transcript(th)
    sig_n = node.sign_transcript(th)

    # Verification and identity checks
    # Reflection attack check: Ensure role identities are distinct
    if gateway.identity == node.identity:
        raise ValueError("Reflected handshake message detected.")

    gateway.verify_peer_signature(sig_n, peer_role=node.identity, th=th)
    node.verify_peer_signature(sig_g, peer_role=gateway.identity, th=th)

    # Derive DH shared secret Z
    # Gateway computes Z = Y_n ^ x_g mod p
    dh_pub_n = dh.DHPublicNumbers(
        int.from_bytes(node.dh_pub_bytes, byteorder="big"),
        dh_params.parameter_numbers()
    ).public_key()
    shared_secret_g = gateway.dh_private_key.exchange(dh_pub_n)

    # Node computes Z = Y_g ^ x_n mod p
    dh_pub_g = dh.DHPublicNumbers(
        int.from_bytes(gateway.dh_pub_bytes, byteorder="big"),
        dh_params.parameter_numbers()
    ).public_key()
    shared_secret_n = node.dh_private_key.exchange(dh_pub_g)

    assert shared_secret_g == shared_secret_n, "Shared secrets do not match!"

    # Left-pad shared secret Z to 384 bytes
    z_bytes = shared_secret_g.rjust(384, b"\x00")

    #  Key Derivation
    gateway_keys = derive_keys(z_bytes, th)
    node_keys = derive_keys(z_bytes, th)

    assert gateway_keys == node_keys, "Derived key sets do not match!"

    print("Handshake completed successfully!")
    print(f"Session ID (hex): {gateway_keys['session_id'].hex()}")
    print(f"Gateway-to-Node Enc Key: {gateway_keys['k_g2n_enc'].hex()[:16]}...")
    print(f"Node-to-Gateway Enc Key: {gateway_keys['k_n2g_enc'].hex()[:16]}...")


if __name__ == "__main__":
    execute_handshake()
