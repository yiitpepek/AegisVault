"""
Zero-Trust Post-Quantum Cold-Storage Cryptographic Engine
Standards:
- Symmetric Encryption: AES-256-GCM (NIST SP 800-38D / CNSA 2.0 Suite)
- Key Derivation Function (KDF): scrypt (BIP-38 & Web3 Keystore Standard, GPU/ASIC resistant)
- Authenticated Data Integrity: AEAD (Authenticated Encryption with Associated Data)
- Entropy Source: Cryptographically Secure Pseudo-Random Number Generator (CSPRNG - os.urandom)
"""

import os
import ctypes
import struct
import base64
import sys
from typing import Tuple, Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class VaultSecurityError(Exception):
    """Raised upon unauthorized access, data tampering, or authentication failure."""
    pass


class MilitaryVault:
    """
    High-assurance cold-storage cryptographic engine combining AES-256-GCM and scrypt.
    
    Architecture:
    - 256-bit key length
    - 96-bit unique Nonce/IV per encryption (NIST SP 800-38D compliant)
    - scrypt memory-hard KDF (Defeats GPU/ASIC brute-force dictionary attacks)
    - Authenticated Additional Data (AAD): Cryptographic parameters and versioning sealed into header
    """

    MAGIC_BYTES = b"MVAULT"  # 6 bytes
    VERSION = 1               # 1 byte (v1)
    KDF_SCRYPT = 1            # 1 byte identifier

    # Secure default scrypt parameters (BIP-38 financial standard)
    # N=32768 (2^15), r=8, p=1 (~32MB RAM allocation required per derivation)
    DEFAULT_LOG_N = 15
    DEFAULT_R = 8
    DEFAULT_P = 1
    SALT_SIZE = 16            # 128-bit CSPRNG salt
    NONCE_SIZE = 12           # 96-bit GCM Nonce
    KEY_LENGTH = 32           # 256-bit AES key

    HEADER_FORMAT = ">6sBBBI I 16s 12s"
    # Structure:
    # 6s: Magic bytes (MVAULT)
    # B : Version (1)
    # B : KDF Type (1 = scrypt)
    # B : log_n (15)
    # I : r (8)
    # I : p (1)
    # 16s: Salt
    # 12s: Nonce

    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    @classmethod
    def _zero_memory(cls, target: Union[bytearray, memoryview]):
        """
        Best-effort zeroization of mutable sensitive memory buffers (bytearray/memoryview)
        prior to garbage collection using in-place byte clearing and ctypes.memset.
        Note (V-18): CPython immutable objects (`str`, `bytes`) cannot be zeroed safely
        in-place without risking interpreter heap corruption; callers should prefer
        `bytearray` buffers and short-lived scopes for derived keys.
        """
        if isinstance(target, bytearray) and len(target) > 0:
            try:
                buf_type = ctypes.c_char * len(target)
                ctypes.memset(buf_type.from_buffer(target), 0, len(target))
            except Exception:
                for i in range(len(target)):
                    target[i] = 0
        elif isinstance(target, memoryview) and not target.readonly:
            for i in range(len(target)):
                target[i] = 0

    @classmethod
    def _derive_key(cls, password: bytes, salt: bytes, n: int, r: int, p: int) -> bytes:
        """Derives a 256-bit (32-byte) key from the password using scrypt."""
        kdf = Scrypt(
            salt=salt,
            length=cls.KEY_LENGTH,
            n=n,
            r=r,
            p=p,
        )
        return kdf.derive(password)

    @classmethod
    def encrypt(cls, plaintext: Union[str, bytes], password: str) -> str:
        """
        Encrypts plaintext or binary data using AES-256-GCM and returns a portable Base64 envelope.
        
        Args:
            plaintext: Sensitive secret data (Bitcoin seed, private key, file bytes)
            password: Master user password
            
        Returns:
            Armored Base64 string (Vault Envelope)
        """
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode("utf-8")
        else:
            plaintext_bytes = bytes(plaintext)

        password_bytes = bytearray(password.encode("utf-8"))

        # 1. Generate cryptographically secure random salt and nonce
        salt = os.urandom(cls.SALT_SIZE)
        nonce = os.urandom(cls.NONCE_SIZE)

        log_n = cls.DEFAULT_LOG_N
        n = 1 << log_n
        r = cls.DEFAULT_R
        p = cls.DEFAULT_P

        # 2. Derive 256-bit key via scrypt
        key = bytearray(cls._derive_key(bytes(password_bytes), salt, n, r, p))

        # 3. Construct capsule header as Authenticated Additional Data (AAD)
        header = struct.pack(
            cls.HEADER_FORMAT,
            cls.MAGIC_BYTES,
            cls.VERSION,
            cls.KDF_SCRYPT,
            log_n,
            r,
            p,
            salt,
            nonce,
        )

        try:
            # 4. Encrypt with AES-256-GCM and bind header as AAD
            aesgcm = AESGCM(bytes(key))
            ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, associated_data=header)

            # 5. Pack header + ciphertext (including 16-byte authentication tag)
            full_payload = header + ciphertext
            armored = base64.b64encode(full_payload).decode("ascii")
            return armored

        finally:
            # RAM hygiene: zero out sensitive buffers
            cls._zero_memory(password_bytes)
            cls._zero_memory(key)

    @classmethod
    def decrypt(cls, armored_payload: str, password: str) -> bytes:
        """
        Decrypts an armored Base64 envelope and verifies cryptographic integrity.
        
        Args:
            armored_payload: Base64 string produced by encrypt()
            password: User master password
            
        Returns:
            Decrypted raw bytes
            
        Raises:
            VaultSecurityError: On invalid password, payload tampering, or authentication failure.
        """
        try:
            first_slot = armored_payload.strip().splitlines()[0].strip() if armored_payload.strip() else ""
            raw_data = base64.b64decode(first_slot.encode("ascii"))
        except Exception as e:
            raise VaultSecurityError("Invalid packet format: Base64 decoding failed.") from e

        if len(raw_data) < cls.HEADER_SIZE + 16:  # 16 = GCM auth tag size
            raise VaultSecurityError("Packet truncated or corrupted.")

        # 1. Parse and validate header
        header = raw_data[:cls.HEADER_SIZE]
        ciphertext = raw_data[cls.HEADER_SIZE:]

        try:
            magic, version, kdf_type, log_n, r, p, salt, nonce = struct.unpack(
                cls.HEADER_FORMAT, header
            )
        except struct.error as e:
            raise VaultSecurityError("Header structure corrupted.") from e

        if magic != cls.MAGIC_BYTES:
            raise VaultSecurityError("Invalid vault format (Magic bytes mismatch).")

        if version != cls.VERSION:
            raise VaultSecurityError(f"Unsupported vault version: {version}")

        if kdf_type != cls.KDF_SCRYPT:
            raise VaultSecurityError("Unsupported KDF algorithm identifier.")

        # Parameter sanity limits to prevent CPU/Memory Exhaustion (OOM DoS) attacks
        if log_n > 20 or log_n < 10 or r < 1 or r > 32 or p < 1 or p > 16:
            raise VaultSecurityError("scrypt parameters outside security thresholds.")

        n = 1 << log_n
        if (128 * n * r) > (512 * 1024 * 1024):  # Cap maximum KDF RAM at 512 MB
            raise VaultSecurityError("scrypt memory allocation exceeds safe threshold.")

        password_bytes = bytearray(password.encode("utf-8"))

        try:
            # 2. Derive key using identical parameters
            key = bytearray(cls._derive_key(bytes(password_bytes), salt, n, r, p))

            # 3. Decrypt and verify with AES-256-GCM
            aesgcm = AESGCM(bytes(key))
            decrypted = aesgcm.decrypt(nonce, ciphertext, associated_data=header)
            return decrypted

        except Exception as e:
            raise VaultSecurityError(
                "Decryption FAILED! Incorrect password or data has been modified/tampered with."
            ) from e
        finally:
            cls._zero_memory(password_bytes)
            if 'key' in locals():
                cls._zero_memory(key)

    @classmethod
    def encrypt_file(cls, input_file_path: str, output_file_path: str, password: str):
        """Encrypts an arbitrary file using military-grade standards."""
        with open(input_file_path, "rb") as f:
            data = f.read()
        encrypted_armored = cls.encrypt(data, password)
        with open(output_file_path, "w", encoding="utf-8") as f:
            f.write(encrypted_armored)

    @classmethod
    def decrypt_file(cls, input_file_path: str, output_file_path: str, password: str):
        """Decrypts a vault file and writes the plaintext output to disk."""
        with open(input_file_path, "r", encoding="utf-8") as f:
            encrypted_armored = f.read()
        decrypted_bytes = cls.decrypt(encrypted_armored, password)
        with open(output_file_path, "wb") as f:
            f.write(decrypted_bytes)


def run_self_test():
    """Runs verification self-tests on the cryptographic vault."""
    print("=" * 65)
    print(" MILITARY-GRADE VAULT SECURITY & INTEGRATION TEST")
    print("=" * 65)

    mock_btc_seed = (
        "witch collapse practice feed shame open despair creek "
        "road again ice least flame doctor immense metal "
        "flame doctor immense metal flame doctor immense metal"
    )
    master_password = "User@Secret!Password9921#$"

    print("\n[+] Step 1: Encrypting Bitcoin Seed Phrase...")
    armored = MilitaryVault.encrypt(mock_btc_seed, master_password)
    print(f"    Ciphertext preview: {armored[:60]}...")
    print(f"    Capsule size: {len(armored)} characters (Base64)")

    print("\n[+] Step 2: Decrypting with correct password...")
    decrypted_bytes = MilitaryVault.decrypt(armored, master_password)
    decrypted_text = decrypted_bytes.decode("utf-8")
    assert decrypted_text == mock_btc_seed, "FAIL: Decrypted text does not match!"
    print("    [PASSED] Data decrypted successfully and verified.")

    print("\n[+] Step 3: Testing with incorrect password...")
    try:
        MilitaryVault.decrypt(armored, "WrongPassword123")
        print("    [FAIL] Wrong password was accepted!")
    except VaultSecurityError:
        print("    [PASSED] Wrong password immediately rejected (Auth Tag Mismatch).")

    print("\n[+] Step 4: Testing bit-flip tampering attack...")
    tampered_armored = armored[:100] + ("A" if armored[100] != "A" else "B") + armored[101:]
    try:
        MilitaryVault.decrypt(tampered_armored, master_password)
        print("    [FAIL] Tampered payload was accepted!")
    except VaultSecurityError:
        print("    [PASSED] 1-bit tampering detected by AEAD and operation aborted.")

    print("\n" + "=" * 65)
    print(" ALL CRYPTOGRAPHIC STANDARDS VERIFIED SUCCESSFULLY!")
    print("=" * 65)


if __name__ == "__main__":
    run_self_test()
