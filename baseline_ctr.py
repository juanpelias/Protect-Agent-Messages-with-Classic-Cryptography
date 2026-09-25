import json
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AESCTRReceiver:
    """Simulates a network receiver processing incoming encrypted commands."""

    def __init__(self, key: bytes):
        self.key = key
        self.processed_count = 0

    def process_message(self, nonce: bytes, ciphertext: bytes) -> dict:
        # Decrypt ciphertext using AES-CTR without authentication
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(nonce))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Parse JSON command
        command = json.loads(plaintext.decode("utf-8"))
        self.processed_count += 1
        print(f"[Receiver] Successfully processed command #{self.processed_count}: {command}")
        return command


def relay_bit_flip_attack(
    ciphertext: bytes,
    offset: int,
    original_val: bytes,
    target_val: bytes,
) -> bytes:
    """
    Relay/mitm function: Modifies ciphertext bytes without knowing the secret key
    by applying the XOR delta between original_val and target_val.
    """
    modified_ct = bytearray(ciphertext)
    xor_mask = bytes([o ^ t for o, t in zip(original_val, target_val)])

    print("\n--- XOR Bit-Flipping Analysis ---")
    print(f"Original Text: {original_val.decode('utf-8')} -> Bytes: {list(original_val)}")
    print(f"Target Text:   {target_val.decode('utf-8')} -> Bytes: {list(target_val)}")
    print(f"XOR Mask:      {[hex(b) for b in xor_mask]}")
    print("-" * 50)

    for i, mask_byte in enumerate(xor_mask):
        idx = offset + i
        orig_ct_byte = modified_ct[idx]
        modified_ct[idx] ^= mask_byte
        mod_ct_byte = modified_ct[idx]
        print(
            f"Index {idx:2d} | Original CT Byte: 0x{orig_ct_byte:02x} "
            f"^ Mask: 0x{mask_byte:02x} => Modified CT Byte: 0x{mod_ct_byte:02x}"
        )

    return bytes(modified_ct)


def main():
    # Setup shared secret key and random initial counter/nonce
    shared_key = os.urandom(32)  # AES-256
    nonce = os.urandom(16)
    receiver = AESCTRReceiver(shared_key)

    # Original message payload
    original_payload = b'{"action":"READ","path":"notes.txt"}'
    print(f"Original Plaintext: {original_payload.decode('utf-8')}")

    # 1. Sender encrypts original payload
    cipher = Cipher(algorithms.AES(shared_key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    original_ciphertext = encryptor.update(original_payload) + encryptor.finalize()
    print(f"Original Ciphertext: {original_ciphertext.hex()}")

    # 2. Relay modifies 'READ' (index 11, 4 bytes) to 'EXEC' (4 bytes)
    target_offset = original_payload.find(b"READ")
    modified_ciphertext = relay_bit_flip_attack(
        ciphertext=original_ciphertext,
        offset=target_offset,
        original_val=b"READ",
        target_val=b"EXEC",
    )

    # 3. Receiver receives and processes tampered ciphertext
    print("\n--- [Transmission 1] Receiver Processing Tampered Message ---")
    receiver.process_message(nonce, modified_ciphertext)

    # 4. Replay Attack: Relay re-sends the exact same ciphertext
    print("\n--- [Transmission 2] Replay Attack Executed ---")
    receiver.process_message(nonce, modified_ciphertext)


if __name__ == "__main__":
    main()
