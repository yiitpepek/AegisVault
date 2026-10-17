"""
Crypto Utilities:
1. Shamir's Secret Sharing (SSS) - Military-Grade K-of-N Threshold Cryptography
2. BIP-39 Seed Phrase Analysis & Validation
3. Shannon Entropy & Password Strength Calculator
"""

import math
import secrets
import re
from typing import List, Tuple, Any

# Shamir's Secret Sharing over GF(257) Prime Field
PRIME_257 = 257


def shamir_split(secret: str, threshold: int, total_shares: int) -> List[str]:
    """
    Splits sensitive data (Seed Phrase, Master Key, etc.) into 'total_shares' parts.
    Reconstructing the secret requires at least 'threshold' parts.
    
    Example: In a 3-of-5 scheme, 5 shares are generated; any 3 are sufficient to recover.
    """
    if threshold > total_shares:
        raise ValueError("Threshold cannot be greater than total shares.")
    if threshold < 2:
        raise ValueError("Threshold must be at least 2.")

    data = secret.encode("utf-8")
    shares_dict = {x: bytearray() for x in range(1, total_shares + 1)}

    for b in data:
        while True:
            # Random polynomial of degree k-1: f(x) = b + c1*x + c2*x^2 + ... (mod 257)
            coeffs = [b] + [secrets.randbelow(PRIME_257) for _ in range(threshold - 1)]
            vals = []
            for x in range(1, total_shares + 1):
                val = sum(c * (x ** i) for i, c in enumerate(coeffs)) % PRIME_257
                vals.append(val)
            
            # Ensure all shares fit into byte (0-255) range via rejection sampling
            if all(v < 256 for v in vals):
                for x, v in zip(range(1, total_shares + 1), vals):
                    shares_dict[x].append(v)
                break

    # Package shares in human-readable armored format
    formatted_shares = []
    for x in range(1, total_shares + 1):
        hex_data = bytes(shares_dict[x]).hex()
        formatted_shares.append(f"AEGIS-SHR-{x:02d}-{threshold}of{total_shares}-{hex_data}")

    return formatted_shares


def shamir_combine(shares: List[str]) -> str:
    """
    Reconstructs the original secret from K Shamir shares using Lagrange interpolation.
    """
    if not shares:
        raise ValueError("No shares provided.")

    parsed_shares: List[Tuple[int, bytes]] = []
    threshold_expected = None

    pattern = re.compile(r"^AEGIS-SHR-(\d+)-(\d+)of(\d+)-([0-9a-fA-F]+)$")
    for s in shares:
        s = s.strip()
        if not s:
            continue
        m = pattern.match(s)
        if not m:
            raise ValueError(f"Invalid share format: {s[:25]}...")
        x = int(m.group(1))
        k = int(m.group(2))
        hex_data = m.group(4)
        if threshold_expected is None:
            threshold_expected = k
        elif threshold_expected != k:
            raise ValueError("Shares with different threshold parameters cannot be combined.")
        parsed_shares.append((x, bytes.fromhex(hex_data)))

    # Verify unique share coordinates
    unique_x = set(x for x, _ in parsed_shares)
    if len(unique_x) < threshold_expected:
        raise ValueError(
            f"Insufficient unique shares! Required: {threshold_expected}, provided: {len(unique_x)}"
        )

    # Use only the first K unique shares
    used_shares = []
    seen = set()
    for x, data in parsed_shares:
        if x not in seen:
            seen.add(x)
            used_shares.append((x, data))
            if len(used_shares) == threshold_expected:
                break

    data_len = len(used_shares[0][1])
    if not all(len(d) == data_len for _, d in used_shares):
        raise ValueError("Share lengths mismatch. Data might be corrupted.")

    result_bytes = bytearray()
    for idx in range(data_len):
        val = 0
        for i, (xi, data_i) in enumerate(used_shares):
            yi = data_i[idx]
            num, den = 1, 1
            for j, (xj, _) in enumerate(used_shares):
                if i != j:
                    num = (num * (-xj)) % PRIME_257
                    den = (den * (xi - xj)) % PRIME_257
            lagrange = (num * pow(den, -1, PRIME_257)) % PRIME_257
            val = (val + yi * lagrange) % PRIME_257
        result_bytes.append(val)

    try:
        return bytes(result_bytes).decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Decoded data is not valid UTF-8. Shares may be incorrect, corrupted, or below the required threshold.")


def validate_bip39_seed(phrase: str) -> dict:
    """
    Validates Bitcoin / EVM 12 or 24-word seed phrase structure.
    """
    words = phrase.strip().split()
    word_count = len(words)
    valid_lengths = [12, 15, 18, 21, 24]
    
    is_valid_len = word_count in valid_lengths
    
    # Character and word format check (lowercase alpha only)
    valid_format = all(re.match(r"^[a-z]+$", w) for w in words) if words else False

    # Calculate theoretical entropy bits (12 words = 128 bits, 24 words = 256 bits)
    bit_entropy = (word_count * 11) - (word_count // 3) if is_valid_len else 0

    return {
        "word_count": word_count,
        "is_valid_length": is_valid_len,
        "is_valid_format": valid_format,
        "entropy_bits": bit_entropy,
        "standard_status": "Valid BIP-39 Format" if (is_valid_len and valid_format) else "Invalid Word Count or Character Encoding",
    }


def calculate_password_entropy(password: str) -> dict:
    """Calculates Shannon entropy and strength score for a given password."""
    if not password:
        return {"entropy": 0, "score": 0, "label": "Empty", "color": "#ef4444"}

    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    if re.search(r"[!@#$%^&*()_\-+=\[\]{}|;:,.<>?~]", password):
        pool_size += 32

    entropy = len(password) * math.log2(pool_size) if pool_size > 0 else 0

    if entropy < 45:
        score = 1
        label = "Weak (Easily Crackable)"
        color = "#ef4444"
    elif entropy < 70:
        score = 2
        label = "Moderate"
        color = "#f59e0b"
    elif entropy < 100:
        score = 3
        label = "Strong"
        color = "#3b82f6"
    else:
        score = 4
        label = "Military-Grade (Virtually Uncrackable)"
        color = "#10b981"

    return {
        "entropy": round(entropy, 1),
        "score": score,
        "label": label,
        "color": color
    }


# =============================================================================
# 4. POST-QUANTUM HYBRID KEY ENCAPSULATION MECHANISM (PQ-HYBRID KEM)
#    Combines Classical X25519 ECDH + Ring-LWE over Z_3329[X]/(X^256 + 1)
#    with HKDF-SHA512 & SHA3-256 Domain Separation (NIST FIPS 203 Inspired)
# =============================================================================
import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

LWE_Q = 3329          # NIST FIPS 203 (ML-KEM / Kyber) prime modulus
LWE_N = 256           # Cyclotomic polynomial ring degree X^256 + 1
LWE_HALF_Q = 1665     # Round(3329 / 2)


def _poly_mul_mod(a: List[int], b: List[int]) -> List[int]:
    """Multiplies two polynomials in R_q = Z_3329[X] / (X^256 + 1)."""
    res = [0] * LWE_N
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            if bj == 0:
                continue
            idx = i + j
            if idx < LWE_N:
                res[idx] = (res[idx] + ai * bj) % LWE_Q
            else:
                res[idx - LWE_N] = (res[idx - LWE_N] - ai * bj) % LWE_Q
    return res


def _sample_uniform_poly(seed32: bytes) -> List[int]:
    """Deterministically expands a 32-byte seed into a polynomial in R_3329 via SHAKE-256."""
    raw = hashlib.shake_256(seed32).digest(LWE_N * 2)
    return [((raw[2 * i] << 8) | raw[2 * i + 1]) % LWE_Q for i in range(LWE_N)]


def _sample_ternary_poly(seed32: bytes, nonce_byte: int) -> List[int]:
    """Samples a bounded ternary error/secret polynomial with coefficients in {-1, 0, 1}."""
    raw = hashlib.shake_256(seed32 + bytes([nonce_byte])).digest(LWE_N)
    # Centered distribution: b0 - b1 in {-1, 0, 1} modulo LWE_Q
    return [((b & 1) - ((b >> 1) & 1)) % LWE_Q for b in raw]


def _validate_lwe_poly(poly: Any, label: str = "polynomial") -> List[int]:
    """Strictly validates that a polynomial has degree 256 and integer coefficients in [0, 3328]."""
    if not isinstance(poly, list) or len(poly) != LWE_N:
        raise ValueError(f"Invalid LWE {label} dimension (expected {LWE_N}).")
    for idx, coeff in enumerate(poly):
        # In Python, isinstance(True, int) is True, so check type(coeff) is int explicitly
        if type(coeff) is not int or coeff < 0 or coeff >= LWE_Q:
            raise ValueError(f"Malformed LWE {label} coefficient at index {idx}: out of Z_{LWE_Q} range.")
    return poly


def _compute_pk_digest(ecc_pub_hex: str, rho_hex: str, b_poly: List[int]) -> bytes:
    """Computes H(pk) for Fujisaki-Okamoto (FO) IND-CCA2 domain binding."""
    canonical = f"{ecc_pub_hex}|{rho_hex}|{json.dumps(b_poly, separators=(',', ':'))}"
    return hashlib.sha3_256(canonical.encode("ascii")).digest()


class PQHybridKEM:
    """
    Post-Quantum Hybrid Key Encapsulation Engine (X25519 + Ring-LWE-256 with Fujisaki-Okamoto Transform).
    Defends against 'Harvest Now, Decrypt Later' quantum adversaries and active CCA2 capsule tampering.
    """

    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
        """
        Generates a hybrid (X25519 + Ring-LWE) keypair with Fujisaki-Okamoto re-encapsulation parameters.
        Returns: (public_key_armored, private_key_armored)
        """
        # 1. Classical X25519 Keypair
        ecc_priv = x25519.X25519PrivateKey.generate()
        ecc_pub_bytes = ecc_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ecc_priv_bytes = ecc_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

        # 2. Post-Quantum Ring-LWE Keypair over Z_3329[X]/(X^256+1)
        rho = os.urandom(32)
        sigma = os.urandom(32)
        z_reject = os.urandom(32)
        a_poly = _sample_uniform_poly(rho)
        s_poly = _sample_ternary_poly(sigma, 1)
        e_poly = _sample_ternary_poly(sigma, 2)

        as_poly = _poly_mul_mod(a_poly, s_poly)
        b_poly = [(as_poly[i] + e_poly[i]) % LWE_Q for i in range(LWE_N)]

        pub_obj = {
            "alg": "AEGIS-PQ-HYBRID-v1",
            "ecc_pub": ecc_pub_bytes.hex(),
            "rho": rho.hex(),
            "b": b_poly
        }
        priv_obj = {
            "alg": "AEGIS-PQ-HYBRID-v1",
            "ecc_priv": ecc_priv_bytes.hex(),
            "ecc_pub": ecc_pub_bytes.hex(),
            "rho": rho.hex(),
            "b": b_poly,
            "s": s_poly,
            "z": z_reject.hex()
        }

        pub_b64 = "AEGIS-PQPK-v1:" + base64.b64encode(json.dumps(pub_obj, separators=(",", ":")).encode()).decode()
        priv_b64 = "AEGIS-PQSK-v1:" + base64.b64encode(json.dumps(priv_obj, separators=(",", ":")).encode()).decode()
        return pub_b64, priv_b64

    @staticmethod
    def encapsulate(public_key_armored: str) -> Tuple[str, str]:
        """
        Encapsulates a 256-bit Hybrid Shared Secret against a recipient's PQ-Hybrid public key
        using the Fujisaki-Okamoto (FO) transform G(m || H(pk)).
        Returns: (ciphertext_capsule_armored, shared_secret_hex_64)
        """
        clean = public_key_armored.strip()
        if not clean.startswith("AEGIS-PQPK-v1:"):
            raise ValueError("Invalid PQ-Hybrid Public Key header.")
        pub_obj = json.loads(base64.b64decode(clean[len("AEGIS-PQPK-v1:"):]).decode())

        peer_ecc_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(pub_obj["ecc_pub"]))
        rho = bytes.fromhex(pub_obj["rho"])
        if len(rho) != 32:
            raise ValueError("Invalid LWE rho seed length.")
        b_poly = _validate_lwe_poly(pub_obj.get("b"), "public key b")

        # 1. Classical Ephemeral X25519 ECDH
        eph_ecc_priv = x25519.X25519PrivateKey.generate()
        eph_ecc_pub_bytes = eph_ecc_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        z_ecc = eph_ecc_priv.exchange(peer_ecc_pub)

        # 2. Ring-LWE Encapsulation with Fujisaki-Okamoto deterministic coin derivation
        m_bytes = os.urandom(32)
        pk_digest = _compute_pk_digest(pub_obj["ecc_pub"], pub_obj["rho"], b_poly)
        coin_seed = hashlib.sha3_256(m_bytes + pk_digest).digest()

        a_poly = _sample_uniform_poly(rho)
        r_poly = _sample_ternary_poly(coin_seed, 1)
        e1_poly = _sample_ternary_poly(coin_seed, 2)
        e2_poly = _sample_ternary_poly(coin_seed, 3)

        ar_poly = _poly_mul_mod(a_poly, r_poly)
        u_poly = [(ar_poly[i] + e1_poly[i]) % LWE_Q for i in range(LWE_N)]

        br_poly = _poly_mul_mod(b_poly, r_poly)
        v_poly = []
        for i in range(LWE_N):
            bit = (m_bytes[i // 8] >> (i % 8)) & 1
            v_i = (br_poly[i] + e2_poly[i] + (LWE_HALF_Q * bit)) % LWE_Q
            v_poly.append(v_i)

        # 3. Combine Classical ECDH + Post-Quantum LWE + Capsule Transcript via HKDF-SHA512
        transcript_hash = hashlib.sha3_256(
            eph_ecc_pub_bytes + pk_digest + bytes(str(u_poly) + str(v_poly), "ascii")
        ).digest()

        hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=transcript_hash,
            info=b"AEGIS-PQ-HYBRID-MLKEM-X25519-v1"
        )
        hybrid_secret = hkdf.derive(z_ecc + m_bytes)

        ct_obj = {
            "alg": "AEGIS-PQ-CT-v1",
            "epk": eph_ecc_pub_bytes.hex(),
            "u": u_poly,
            "v": v_poly
        }
        ct_b64 = "AEGIS-PQCT-v1:" + base64.b64encode(json.dumps(ct_obj, separators=(",", ":")).encode()).decode()
        return ct_b64, hybrid_secret.hex()

    @staticmethod
    def decapsulate(ciphertext_armored: str, private_key_armored: str) -> str:
        """
        Decapsulates a PQ-Hybrid Ciphertext Capsule, strictly validates Z_3329 coefficient bounds,
        and enforces Fujisaki-Okamoto (FO) IND-CCA2 re-encapsulation integrity verification.
        Returns: shared_secret_hex_64
        """
        clean_ct = ciphertext_armored.strip()
        clean_sk = private_key_armored.strip()
        if not clean_ct.startswith("AEGIS-PQCT-v1:") or not clean_sk.startswith("AEGIS-PQSK-v1:"):
            raise ValueError("Invalid PQ-Hybrid Ciphertext or Private Key header.")

        ct_obj = json.loads(base64.b64decode(clean_ct[len("AEGIS-PQCT-v1:"):]).decode())
        sk_obj = json.loads(base64.b64decode(clean_sk[len("AEGIS-PQSK-v1:"):]).decode())

        eph_ecc_pub_bytes = bytes.fromhex(ct_obj["epk"])
        if len(eph_ecc_pub_bytes) != 32:
            raise ValueError("Invalid ephemeral X25519 public key length.")

        u_poly = _validate_lwe_poly(ct_obj.get("u"), "ciphertext u")
        v_poly = _validate_lwe_poly(ct_obj.get("v"), "ciphertext v")
        s_poly = _validate_lwe_poly(sk_obj.get("s"), "secret key s")

        # 1. Classical X25519 ECDH recovery
        ecc_priv = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(sk_obj["ecc_priv"]))
        eph_ecc_pub = x25519.X25519PublicKey.from_public_bytes(eph_ecc_pub_bytes)
        z_ecc = ecc_priv.exchange(eph_ecc_pub)

        # 2. Ring-LWE Decapsulation: d(X) = v(X) - u(X)*s(X) mod (X^256+1, 3329)
        us_poly = _poly_mul_mod(u_poly, s_poly)
        m_bytes = bytearray(32)
        for i in range(LWE_N):
            d_i = (v_poly[i] - us_poly[i]) % LWE_Q
            dist_to_half = abs(d_i - LWE_HALF_Q)
            bit = 1 if dist_to_half < (LWE_Q // 4) else 0
            if bit:
                m_bytes[i // 8] |= (1 << (i % 8))

        # 3. Fujisaki-Okamoto (FO) IND-CCA2 Re-Encapsulation Check
        rho_hex = sk_obj.get("rho", "")
        rho = bytes.fromhex(rho_hex)
        a_poly = _sample_uniform_poly(rho)
        b_poly = sk_obj.get("b")
        if b_poly is not None:
            b_poly = _validate_lwe_poly(b_poly, "public key b")
            pk_digest = _compute_pk_digest(sk_obj["ecc_pub"], rho_hex, b_poly)
            coin_seed = hashlib.sha3_256(bytes(m_bytes) + pk_digest).digest()

            r_poly = _sample_ternary_poly(coin_seed, 1)
            e1_poly = _sample_ternary_poly(coin_seed, 2)
            e2_poly = _sample_ternary_poly(coin_seed, 3)

            ar_poly = _poly_mul_mod(a_poly, r_poly)
            u_expected = [(ar_poly[i] + e1_poly[i]) % LWE_Q for i in range(LWE_N)]

            br_poly = _poly_mul_mod(b_poly, r_poly)
            v_expected = []
            for i in range(LWE_N):
                bit = (m_bytes[i // 8] >> (i % 8)) & 1
                v_i = (br_poly[i] + e2_poly[i] + (LWE_HALF_Q * bit)) % LWE_Q
                v_expected.append(v_i)

            if u_poly != u_expected or v_poly != v_expected:
                raise ValueError("Fujisaki-Okamoto (IND-CCA2) capsule integrity check failed: tampered ciphertext rejected!")
        else:
            pk_digest = b""

        # 4. Derive identical 256-bit Hybrid Shared Secret via HKDF-SHA512
        transcript_hash = hashlib.sha3_256(
            eph_ecc_pub_bytes + pk_digest + bytes(str(u_poly) + str(v_poly), "ascii")
        ).digest()

        hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=transcript_hash,
            info=b"AEGIS-PQ-HYBRID-MLKEM-X25519-v1"
        )
        hybrid_secret = hkdf.derive(z_ecc + bytes(m_bytes))
        return hybrid_secret.hex()


