import hmac
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HEADER_LEN = 15  # 1 (version) + 1 (direction) + 8 (seq) + 1 (type) + 4 (ct_len)
IV_LEN = 16      # 8 (session_id) + 8 (sequence)
TAG_LEN = 32     # HMAC-SHA-256 tag length in bytes


def seal(
    k_enc: bytes,
    k_mac: bytes,
    session_id: bytes,
    direction: int,
    sequence: int,
    message_type: int,
    plaintext: bytes,
    version: int = 1,
) -> bytes:
    """
    Seals (encrypts then MACs) a plaintext record.

    Format:
    header = version(1B) || direction(1B) || sequence(8B) || message_type(1B) || ciphertext_length(4B)
    iv = session_id(8B) || sequence(8B)
    ciphertext = AES-256-CTR(K_enc, iv, plaintext)
    tag = HMAC-SHA-256(K_mac, header || iv || ciphertext)
    """
    if len(session_id) != 8:
        raise ValueError("Session ID must be exactly 8 bytes")
    if direction not in (1, 2):
        raise ValueError("Direction must be 1 (Gateway->Node) or 2 (Node->Gateway)")
    if sequence < 0 or sequence > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Sequence number out of 64-bit uint bounds")
    if not (0 <= message_type <= 255):
        raise ValueError("Message type must be a single byte (0-255)")

    # Derive IV: session_id (8B) || sequence (8B)
    iv = session_id + sequence.to_bytes(8, byteorder="big")

    # Encrypt plaintext using AES-256-CTR
    cipher = Cipher(algorithms.AES(k_enc), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Construct Header
    header = (
        version.to_bytes(1, byteorder="big")
        + direction.to_bytes(1, byteorder="big")
        + sequence.to_bytes(8, byteorder="big")
        + message_type.to_bytes(1, byteorder="big")
        + len(ciphertext).to_bytes(4, byteorder="big")
    )

    # Compute Encrypt-then-MAC tag over header || iv || ciphertext
    mac_input = header + iv + ciphertext
    tag = hmac.new(k_mac, mac_input, hashlib.sha256).digest()

    # Wire format: header || iv || ciphertext || tag
    return header + iv + ciphertext + tag


def open_record(
    k_enc: bytes,
    k_mac: bytes,
    expected_session_id: bytes,
    expected_direction: int,
    expected_sequence: int,
    record: bytes,
    expected_version: int = 1,
) -> tuple[int, bytes]:
    """
    Verifies MAC first, then decrypts record. Returns (message_type, plaintext).
    Raises ValueError on any header/MAC/replay/direction mismatch without leaking plaintext.
    """
    min_len = HEADER_LEN + IV_LEN + TAG_LEN
    if len(record) < min_len:
        raise ValueError("Record is truncated or smaller than minimum length")

    # Parse components
    header = record[:HEADER_LEN]
    version = header[0]
    direction = header[1]
    sequence = int.from_bytes(header[2:10], byteorder="big")
    message_type = header[10]
    ciphertext_len = int.from_bytes(header[11:15], byteorder="big")

    expected_record_len = HEADER_LEN + IV_LEN + ciphertext_len + TAG_LEN
    if len(record) != expected_record_len:
        raise ValueError("Record length does not match length declared in header")

    iv = record[HEADER_LEN : HEADER_LEN + IV_LEN]
    ciphertext_start = HEADER_LEN + IV_LEN
    ciphertext_end = ciphertext_start + ciphertext_len
    ciphertext = record[ciphertext_start:ciphertext_end]
    received_tag = record[ciphertext_end:]

    # Early Header/Metadata validation before cryptographic operations
    if version != expected_version:
        raise ValueError(f"Version mismatch: expected {expected_version}, got {version}")
    if direction != expected_direction:
        raise ValueError(f"Direction mismatch: expected {expected_direction}, got {direction}")
    if sequence != expected_sequence:
        raise ValueError(f"Sequence mismatch / Replay attack: expected {expected_sequence}, got {sequence}")

    expected_iv = expected_session_id + expected_sequence.to_bytes(8, byteorder="big")
    if not hmac.compare_digest(iv, expected_iv):
        raise ValueError("IV mismatch for expected session_id and sequence")

    # CONSTANT-TIME HMAC VERIFICATION (MAC BEFORE DECRYPTION)
    mac_input = header + iv + ciphertext
    computed_tag = hmac.new(k_mac, mac_input, hashlib.sha256).digest()

    if not hmac.compare_digest(received_tag, computed_tag):
        # Do not decrypt or return plaintext on HMAC failure
        raise ValueError("HMAC verification failed: header/ciphertext tampered or invalid key")

    # Decrypt payload ONLY after HMAC is verified successfully
    cipher = Cipher(algorithms.AES(k_enc), modes.CTR(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return message_type, plaintext


class ChannelState:
    """Manages sequence state and key sets for bidirectional communication."""

    def __init__(
        self,
        k_enc_tx: bytes,
        k_mac_tx: bytes,
        k_enc_rx: bytes,
        k_mac_rx: bytes,
        session_id: bytes,
        tx_direction: int,
        rx_direction: int,
    ):
        self.k_enc_tx = k_enc_tx
        self.k_mac_tx = k_mac_tx
        self.k_enc_rx = k_enc_rx
        self.k_mac_rx = k_mac_rx
        self.session_id = session_id
        self.tx_direction = tx_direction
        self.rx_direction = rx_direction
        self.tx_seq = 0
        self.rx_seq = 0

    def send(self, message_type: int, plaintext: bytes) -> bytes:
        record = seal(
            k_enc=self.k_enc_tx,
            k_mac=self.k_mac_tx,
            session_id=self.session_id,
            direction=self.tx_direction,
            sequence=self.tx_seq,
            message_type=message_type,
            plaintext=plaintext,
        )
        self.tx_seq += 1  # Increment sequence to prevent IV reuse
        return record

    def receive(self, record: bytes) -> tuple[int, bytes]:
        msg_type, plaintext = open_record(
            k_enc=self.k_enc_rx,
            k_mac=self.k_mac_rx,
            expected_session_id=self.session_id,
            expected_direction=self.rx_direction,
            expected_sequence=self.rx_seq,
            record=record,
        )
        self.rx_seq += 1  # Increment expected sequence upon success
        return msg_type, plaintext
