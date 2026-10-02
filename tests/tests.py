import hashlib
import os
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Import record layer and handshake logic
from secure_record import ChannelState, open_record, seal
from baseline_ctr import AESCTRReceiver  # If applicable or inline functions


# ---------------------------------------------------------------------------
# Handshake Helper Class for Testing
# ---------------------------------------------------------------------------
class SimulatedPeer:

    def __init__(self, identity: str):
        self.identity = identity.encode("utf-8")
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=3072
        )
        self.rsa_public_key = self.rsa_private_key.public_key()

    def sign_hash(self, digest: bytes) -> bytes:
        payload = self.identity + digest
        return self.rsa_private_key.sign(
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    def verify_peer(
        self,
        peer_public_key,
        peer_role: bytes,
        digest: bytes,
        signature: bytes,
    ):
        payload = peer_role + digest
        peer_public_key.verify(
            signature,
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )


# ---------------------------------------------------------------------------
# Test Case 1: Valid Handshake and Bidirectional Messages
# ---------------------------------------------------------------------------
def test_1_valid_handshake_and_bidirectional_messaging():
    """Verifies normal execution: Handshake key exchange and two-way record transmission."""
    session_id = os.urandom(8)
    k_g2n_enc, k_g2n_mac = os.urandom(32), os.urandom(32)
    k_n2g_enc, k_n2g_mac = os.urandom(32), os.urandom(32)

    # Instantiate Channel State for both ends
    gateway = ChannelState(
        k_g2n_enc,
        k_g2n_mac,
        k_n2g_enc,
        k_n2g_mac,
        session_id,
        tx_direction=1,
        rx_direction=2,
    )
    node = ChannelState(
        k_n2g_enc,
        k_n2g_mac,
        k_g2n_enc,
        k_g2n_mac,
        session_id,
        tx_direction=2,
        rx_direction=1,
    )

    # 1. Gateway -> Node
    gw_msg = gateway.send(message_type=1, plaintext=b"COMMAND: READ_TEMP")
    msg_type, payload = node.receive(gw_msg)
    assert msg_type == 1
    assert payload == b"COMMAND: READ_TEMP"
    assert node.rx_seq == 1

    # 2. Node -> Gateway
    node_reply = node.send(message_type=1, plaintext=b"RESPONSE: 22.5C")
    msg_type, payload = gateway.receive(node_reply)
    assert msg_type == 1
    assert payload == b"RESPONSE: 22.5C"
    assert gateway.rx_seq == 1


# ---------------------------------------------------------------------------
# Test Case 2: Modified Ciphertext
# ---------------------------------------------------------------------------
def test_2_modified_ciphertext():
    """Asserts that modifying a single byte of ciphertext causes MAC rejection before decryption."""
    k_enc, k_mac = os.urandom(32), os.urandom(32)
    session_id = os.urandom(8)

    record = seal(
        k_enc,
        k_mac,
        session_id,
        direction=1,
        sequence=0,
        message_type=1,
        plaintext=b"Sensitive Data",
    )

    # Tamper with ciphertext byte (offset 31 = start of ciphertext)
    tampered_record = bytearray(record)
    tampered_record[32] ^= 0xFF

    # Safe failure check: Exception raised, zero plaintext released
    with pytest.raises(ValueError, match="HMAC verification failed"):
        open_record(
            k_enc,
            k_mac,
            expected_session_id=session_id,
            expected_direction=1,
            expected_sequence=0,
            record=bytes(tampered_record),
        )


# ---------------------------------------------------------------------------
# Test Case 3: Modified Authenticated Header
# ---------------------------------------------------------------------------
def test_3_modified_authenticated_header():
    """Asserts that tampering with header metadata (e.g., message_type or sequence) invalidates the record."""
    k_enc, k_mac = os.urandom(32), os.urandom(32)
    session_id = os.urandom(8)

    record = seal(
        k_enc,
        k_mac,
        session_id,
        direction=1,
        sequence=0,
        message_type=1,
        plaintext=b"Authentic Payload",
    )

    # Tamper message_type byte at header index 10
    tampered_header_record = bytearray(record)
    tampered_header_record[10] = 0xFF  # Changed from 0x01

    with pytest.raises(ValueError, match="HMAC verification failed"):
        open_record(
            k_enc,
            k_mac,
            expected_session_id=session_id,
            expected_direction=1,
            expected_sequence=0,
            record=bytes(tampered_header_record),
        )


# ---------------------------------------------------------------------------
# Test Case 4: Replayed Record
# ---------------------------------------------------------------------------
def test_4_replayed_record():
    """Asserts that re-transmitting an identical valid record is rejected due to sequence state enforcement."""
    session_id = os.urandom(8)
    k_enc, k_mac = os.urandom(32), os.urandom(32)

    receiver = ChannelState(
        k_enc,
        k_mac,
        k_enc,
        k_mac,
        session_id,
        tx_direction=2,
        rx_direction=1,
    )

    record = seal(
        k_enc,
        k_mac,
        session_id,
        direction=1,
        sequence=0,
        message_type=1,
        plaintext=b"Execute Payment",
    )

    # First delivery succeeds
    receiver.receive(record)
    assert receiver.rx_seq == 1

    # Replay attack: Re-sending sequence 0 when receiver expects sequence 1
    with pytest.raises(
        ValueError, match="Sequence mismatch / Replay attack"
    ):
        receiver.receive(record)


# ---------------------------------------------------------------------------
# Test Case 5: Record Reflected into Opposite Direction
# ---------------------------------------------------------------------------
def test_5_reflected_record_opposite_direction():
    """Asserts that an outgoing record reflected back to the sender is rejected due to direction validation."""
    session_id = os.urandom(8)
    k_g2n_enc, k_g2n_mac = os.urandom(32), os.urandom(32)
    k_n2g_enc, k_n2g_mac = os.urandom(32), os.urandom(32)

    gateway = ChannelState(
        k_g2n_enc,
        k_g2n_mac,
        k_n2g_enc,
        k_n2g_mac,
        session_id,
        tx_direction=1,
        rx_direction=2,
    )

    # Gateway sends outbound record (Direction 1)
    outbound_record = gateway.send(
        message_type=1, plaintext=b"Outgoing Command"
    )

    # Attacker reflects Gateway's record back into Gateway's receiver (expects Direction 2 & N2G keys)
    with pytest.raises(ValueError, match="Direction mismatch"):
        gateway.receive(outbound_record)


# ---------------------------------------------------------------------------
# Test Case 6: Handshake Adversarial Failures
# ---------------------------------------------------------------------------
def test_6a_incorrect_rsa_public_key():
    """Asserts handshake failure when peer signature is verified against an untrusted/wrong RSA public key."""
    gateway = SimulatedPeer("gateway")
    node = SimulatedPeer("node")
    impostor = SimulatedPeer("impostor")

    transcript_hash = hashlib.sha256(b"dummy_transcript").digest()
    signature_by_node = node.sign_hash(transcript_hash)

    # Gateway attempts to verify Node's signature using Impostor's public key
    with pytest.raises(InvalidSignature):
        gateway.verify_peer(
            peer_public_key=impostor.rsa_public_key,
            peer_role=node.identity,
            digest=transcript_hash,
            signature=signature_by_node,
        )


def test_6b_invalid_rsa_pss_transcript_signature():
    """Asserts handshake failure when an active MitM alters transcript data after signing."""
    gateway = SimulatedPeer("gateway")
    node = SimulatedPeer("node")

    orig_hash = hashlib.sha256(b"original_transcript").digest()
    signature = node.sign_hash(orig_hash)

    tampered_hash = hashlib.sha256(b"tampered_transcript").digest()

    # Verification fails because transcript hash was altered in transit
    with pytest.raises(InvalidSignature):
        gateway.verify_peer(
            peer_public_key=node.rsa_public_key,
            peer_role=node.identity,
            digest=tampered_hash,
            signature=signature,
        )


def test_6c_reflected_handshake_message():
    """Asserts failure when an attacker reflects a peer's handshake signature to masquerade as the peer."""
    gateway = SimulatedPeer("gateway")

    transcript_hash = hashlib.sha256(b"transcript_data").digest()

    # Gateway signs as "gateway"
    gateway_sig = gateway.sign_hash(transcript_hash)

    # Gateway receives its own signature back, expecting it to come from "node"
    with pytest.raises(InvalidSignature):
        gateway.verify_peer(
            peer_public_key=gateway.rsa_public_key,
            peer_role=b"node",  # Expecting node role
            digest=transcript_hash,
            signature=gateway_sig,
        )
