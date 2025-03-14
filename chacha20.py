import os
import secrets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import ChaCha20_Poly1305

# --------------------------------------------------------------------
# 1. Generate ephemeral ECC key pairs for Alice and Bob
# --------------------------------------------------------------------
def generate_ecc_key_pair(curve=ec.SECP256R1()):
    """
    Generates an ECC private key and its corresponding public key for the given curve.
    Returns (private_key, public_key).
    """
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    return private_key, public_key

# --------------------------------------------------------------------
# 2. Derive a shared secret & a symmetric key using ECDH + HKDF
# --------------------------------------------------------------------
def derive_shared_key(private_key, peer_public_key, salt=None, info=b"handshake data"):
    """
    Performs ECDH key exchange with a peer's public key, then uses HKDF-SHA256
    to derive a 256-bit (32-byte) symmetric key.
    """
    # 1) ECDH to get shared_secret
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    # 2) HKDF to expand shared_secret into a 32-byte key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,         # 256-bit key for ChaCha20-Poly1305
        salt=salt,         # Optionally provide a random salt
        info=info          # "Handshake data" or context
    ).derive(shared_secret)

    return derived_key

# --------------------------------------------------------------------
# 3. Encrypt / Decrypt using ChaCha20-Poly1305
# --------------------------------------------------------------------
def chacha20_poly1305_encrypt(plaintext: bytes, key: bytes, aad: bytes = b"") -> tuple:
    """
    Encrypts `plaintext` with ChaCha20-Poly1305 using the given 256-bit key.
    Returns (nonce, ciphertext, tag).
    - aad (Associated Authenticated Data) can be used to authenticate headers.
    """
    # 1) 96-bit nonce (12 bytes) – recommended size for ChaCha20-Poly1305
    nonce = secrets.token_bytes(12)

    # 2) Create ChaCha20-Poly1305 cipher
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)

    # 3) Add AAD if needed
    cipher.update(aad)

    # 4) Encrypt
    ciphertext = cipher.encrypt_and_digest(plaintext)
    return nonce, ciphertext[0], ciphertext[1]  # ciphertext[0] = actual ciphertext, ciphertext[1] = tag


def chacha20_poly1305_decrypt(nonce: bytes, ciphertext: bytes, tag: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """
    Decrypts `ciphertext` with ChaCha20-Poly1305 using the given 256-bit key and nonce.
    Verifies the authentication tag and returns the original plaintext if valid.
    Raises ValueError if tag does not match.
    """
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(aad)
    # Decrypt + verify
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

# --------------------------------------------------------------------
# Demonstration: ECDH + ChaCha20-Poly1305
# --------------------------------------------------------------------
def main():
    # -----------------------
    # Setup: Alice & Bob
    # -----------------------
    # Each side generates an ephemeral ECC key pair
    alice_private_key, alice_public_key = generate_ecc_key_pair()
    bob_private_key, bob_public_key = generate_ecc_key_pair()

    # Serialize their public keys to simulate exchange over a network
    # (In real usage, you'd also provide signatures/certificates to prevent MITM).
    alice_public_bytes = alice_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    bob_public_bytes = bob_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Each side now deserializes the other's public key
    # This simulates receiving the peer's public key from the network
    peer_public_key_for_alice = serialization.load_pem_public_key(bob_public_bytes)
    peer_public_key_for_bob = serialization.load_pem_public_key(alice_public_bytes)

    # -----------------------
    # ECDH Key Agreement
    # -----------------------
    # Alice derives shared key
    alice_derived_key = derive_shared_key(alice_private_key, peer_public_key_for_alice)

    # Bob derives the same shared key
    bob_derived_key = derive_shared_key(bob_private_key, peer_public_key_for_bob)

    # They should match if everything is correct
    assert alice_derived_key == bob_derived_key, "Error: Shared keys do not match!"
    shared_key = alice_derived_key  # both sides have the same

    print("ECDH-derived shared key (hex):", shared_key.hex())

    # -----------------------
    # Encryption (Alice -> Bob)
    # -----------------------
    message = b"Hello from Alice to Bob!"
    # Alice encrypts with ChaCha20-Poly1305 using the shared key
    nonce, ciphertext, tag = chacha20_poly1305_encrypt(message, shared_key)
    print("\nAlice -> Bob:")
    print("  Original Message:", message)
    print("  Nonce (hex):", nonce.hex())
    print("  Ciphertext (hex):", ciphertext.hex())
    print("  Tag (hex):", tag.hex())

    # -----------------------
    # Decryption (Bob receives)
    # -----------------------
    try:
        recovered_message = chacha20_poly1305_decrypt(nonce, ciphertext, tag, bob_derived_key)
        print("  Bob Decrypted Message:", recovered_message)
    except ValueError:
        print("  Bob: Decryption failed! Tag mismatch (tampering or wrong key).")

    # -----------------------
    # Bob -> Alice example
    # -----------------------
    message_bob = b"Hello from Bob to Alice!"
    nonce_b, ciphertext_b, tag_b = chacha20_poly1305_encrypt(message_bob, shared_key)
    print("\nBob -> Alice:")
    print("  Original Message:", message_bob)
    print("  Nonce (hex):", nonce_b.hex())
    print("  Ciphertext (hex):", ciphertext_b.hex())
    print("  Tag (hex):", tag_b.hex())

    # Alice decrypts
    try:
        recovered_bob_message = chacha20_poly1305_decrypt(nonce_b, ciphertext_b, tag_b, alice_derived_key)
        print("  Alice Decrypted Message:", recovered_bob_message)
    except ValueError:
        print("  Alice: Decryption failed! Tag mismatch (tampering or wrong key).")


if __name__ == "__main__":
    main()
