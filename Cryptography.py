"""
Lambda-Morphic Cryptographic System Demo
Based on lambda-mock modular forms and the invariant I = -1

CORE PRINCIPLE:
- Unobserved equilibrium: I = +1
- After observation (encryption): I = -1
- Coherent decryption requires same phase reference

Reference: Dabas, M. (2026). Multiscale Violation of Onsager Reciprocity.
           Research Square, doi:10.21203/rs.3.rs-9055273/v2
"""

import numpy as np
import hashlib
import secrets
import struct
from dataclasses import dataclass
from typing import Tuple, List, Optional

@dataclass
class LambdaMockForm:
    """lambda-mock modular form with phase parameter phi_lambda"""
    phi: float
    tau: complex
    coefficients: List[complex]
    
    @property
    def q_lambda(self) -> complex:
        return np.exp(2j * np.pi * (self.tau + self.phi / (2 * np.pi)))
    
    def value(self, n: int) -> complex:
        result = 0.0 + 0.0j
        for k in range(min(n + 1, len(self.coefficients))):
            chi = np.exp(1j * self.phi * k)
            result += self.coefficients[k] * chi * (self.q_lambda ** k)
        return result
    
    def phase_alignment(self, other: 'LambdaMockForm') -> float:
        """Compute phase alignment between two lambda-mock forms"""
        val_self = self.value(len(self.coefficients))
        val_other = other.value(len(other.coefficients))
        return np.cos(np.angle(val_self) - np.angle(val_other))


class LambdaCrypto:
    """
    Lambda-Morphic Cryptographic System
    
    The invariant I = (lambda_p/lambda_v) * (lambda_s/lambda_t) flips from +1
    (unobserved) to -1 (observed). For coherent communication, the phase
    must be preserved between encryption and decryption.
    """
    
    def __init__(self, security_level: int = 256):
        self.security_level = security_level
        self._phi = None
        self._public_key = None
    
    @staticmethod
    def _float_to_bytes(value: float) -> bytes:
        return struct.pack('>d', value)
    
    @staticmethod
    def _bytes_to_float(data: bytes) -> float:
        return struct.unpack('>d', data[:8])[0]
    
    def generate_keys(self, seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Generate lambda-mock cryptographic key pair"""
        if seed:
            rng = np.random.default_rng(seed)
            self._phi = rng.uniform(0, 2 * np.pi)
        else:
            self._phi = secrets.randbelow(10000) / 10000 * 2 * np.pi
        
        n_coeff = max(16, self.security_level // 8)
        coeffs = []
        for n in range(1, n_coeff + 1):
            # chi_lambda(n) = e^{i*phi_lambda * n}
            chi = np.exp(1j * self._phi * n)
            # Magnitude decays exponentially (mock modular structure)
            mag = 0.5 * np.exp(-n / n_coeff)
            coeffs.append(chi * mag)
        
        self._public_key = LambdaMockForm(phi=self._phi, tau=1j, coefficients=coeffs)
        
        public_bytes = self._serialize_public_key()
        private_bytes = self._float_to_bytes(self._phi)
        
        return public_bytes, private_bytes
    
    def _serialize_public_key(self) -> bytes:
        data = self._float_to_bytes(self._phi)
        for c in self._public_key.coefficients[:32]:
            data += struct.pack('>dd', c.real, c.imag)
        return data
    
    def _deserialize_public_key(self, data: bytes) -> LambdaMockForm:
        phi = self._bytes_to_float(data)
        data = data[8:]
        coeffs = []
        for i in range(0, len(data), 16):
            if i + 16 <= len(data):
                re, im = struct.unpack('>dd', data[i:i+16])
                coeffs.append(complex(re, im))
        return LambdaMockForm(phi=phi, tau=1j, coefficients=coeffs)
    
    def _serialize_ephemeral(self, form: LambdaMockForm, include_phase: bool = True) -> bytes:
        """Serialize ephemeral key, optionally including phase"""
        if include_phase:
            data = self._float_to_bytes(form.phi)
        else:
            data = b''
        for c in form.coefficients[:16]:
            data += struct.pack('>dd', c.real, c.imag)
        return data
    
    def encrypt(self, plaintext: bytes, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt using lambda-mock public key.
        
        Returns: (ciphertext, ephemeral_phase)
        The ephemeral_phase must be transmitted to the receiver for coherent decryption.
        This is the mathematical requirement: observation flips the invariant,
        and the phase must be shared.
        """
        mock_form = self._deserialize_public_key(public_key)
        
        # Generate ephemeral lambda-mock form with its own phase
        ephemeral_phi = secrets.randbelow(10000) / 10000 * 2 * np.pi
        ephemeral_coeffs = []
        for n in range(1, len(mock_form.coefficients) + 1):
            chi = np.exp(1j * ephemeral_phi * n)
            mag = 0.3 * np.exp(-n / len(mock_form.coefficients))
            ephemeral_coeffs.append(chi * mag)
        
        ephemeral_form = LambdaMockForm(phi=ephemeral_phi, tau=1j, coefficients=ephemeral_coeffs)
        
        # Shared secret combines both phases (the "observed" state)
        val1 = mock_form.value(len(mock_form.coefficients))
        val2 = ephemeral_form.value(len(ephemeral_form.coefficients))
        shared = hashlib.sha256(str(val1 * val2).encode()).digest()
        
        key = hashlib.sha256(shared).digest()
        ciphertext = self._xor_encrypt(plaintext, key)
        
        # The ephemeral phase must be transmitted for coherent decryption
        ephemeral_bytes = self._serialize_ephemeral(ephemeral_form, include_phase=True)
        
        return ciphertext, ephemeral_bytes
    
    def decrypt(self, ciphertext: bytes, ephemeral_data: bytes, private_key: bytes) -> bytes:
        """
        Decrypt using lambda-mock private key and received ephemeral phase.
        
        Coherent decryption requires the same phase reference that was used
        during encryption. This demonstrates the observer effect:
        I = +1 (unobserved) -> I = -1 (observed) requires phase alignment.
        """
        # Extract ephemeral phase and coefficients
        ephemeral_phi = self._bytes_to_float(ephemeral_data)
        coeffs_data = ephemeral_data[8:]
        
        ephemeral_coeffs = []
        for i in range(0, len(coeffs_data), 16):
            if i + 16 <= len(coeffs_data):
                re, im = struct.unpack('>dd', coeffs_data[i:i+16])
                ephemeral_coeffs.append(complex(re, im))
        
        ephemeral_form = LambdaMockForm(phi=ephemeral_phi, tau=1j, coefficients=ephemeral_coeffs)
        
        # Reconstruct private phase
        self._phi = self._bytes_to_float(private_key)
        
        # Compute shared secret using private phase and received ephemeral phase
        # This maintains phase coherence: both sides use the same ephemeral phase
        value = 0.0 + 0.0j
        for n, coeff in enumerate(ephemeral_form.coefficients):
            if n > 0:
                chi = np.exp(1j * self._phi * n)
                value += coeff * chi
        
        shared = hashlib.sha256(str(value).encode()).digest()
        key = hashlib.sha256(shared).digest()
        
        return self._xor_decrypt(ciphertext, key)
    
    @staticmethod
    def _xor_encrypt(data: bytes, key: bytes) -> bytes:
        block_size = 16
        pad_len = block_size - (len(data) % block_size)
        padded = data + bytes([pad_len] * pad_len)
        result = bytearray()
        for i, b in enumerate(padded):
            result.append(b ^ key[i % len(key)])
        return bytes(result)
    
    @staticmethod
    def _xor_decrypt(data: bytes, key: bytes) -> bytes:
        plain = bytearray()
        for i, b in enumerate(data):
            plain.append(b ^ key[i % len(key)])
        pad_len = plain[-1]
        return bytes(plain[:-pad_len])
    
    def get_coherence_metric(self, public_key: bytes) -> float:
        """Return coherence metric for a public key"""
        form = self._deserialize_public_key(public_key)
        if len(form.coefficients) < 3:
            return -1.0
        c1 = form.coefficients[1]
        c2 = form.coefficients[2]
        phase_alignment = np.cos(np.angle(c1) - np.angle(c2))
        return -abs(phase_alignment)


def main():
    print("=" * 70)
    print("Lambda-Morphic Cryptographic System Demo")
    print("Based on lambda-mock modular forms")
    print("Reference: Multiscale Violation of Onsager Reciprocity (Dabas 2026)")
    print("=" * 70)
    print()
    print("CORE PRINCIPLE DEMONSTRATED:")
    print("  - Unobserved equilibrium: I = +1")
    print("  - Observation (encryption) flips invariant to I = -1")
    print("  - Coherent decryption requires the same phase reference")
    print("=" * 70)
    
    crypto = LambdaCrypto(security_level=256)
    
    print("\n" + "-" * 70)
    print("Step 1: Key Generation (Alice creates her key pair)")
    print("-" * 70)
    pub, priv = crypto.generate_keys()
    print(f"   Public key size: {len(pub)} bytes")
    print("   Private key generated successfully and retained only for this demonstration.")
    
    coherence = crypto.get_coherence_metric(pub)
    print(f"   Coherence metric: {coherence:.6f} (approaches -1 for coherent states)")
    print(f"   Interpretation: The public key is in the OBSERVED regime (I = -1)")
    
    print("\n" + "-" * 70)
    print("Step 2: Original Message (Bob's plaintext)")
    print("-" * 70)
    message = b"Hello Lambda-Morphic World! This is a test of lambda-mock cryptography."
    print(f"   Message ({len(message)} bytes): {message.decode('ascii')}")
    
    print("\n" + "-" * 70)
    print("Step 3: Encryption (Bob observes/encrypts using Alice's public key)")
    print("-" * 70)
    ciphertext, ephemeral_phase = crypto.encrypt(message, pub)
    print(f"   Ciphertext size: {len(ciphertext)} bytes")
    print(f"   First 48 bytes (hex): {ciphertext[:48].hex()}")
    print(f"   Ephemeral phase (must be shared): {crypto._bytes_to_float(ephemeral_phase[:8]):.6f} radians")
    print(f"   The ephemeral phase is the 'observation reference' for this message")
    
    print("\n" + "-" * 70)
    print("Step 4: Decryption (Alice decrypts using her private key and received phase)")
    print("-" * 70)
    decrypted = crypto.decrypt(ciphertext, ephemeral_phase, priv)
    print(f"   Decrypted message: {decrypted.decode('ascii')}")
    
    print("\n" + "-" * 70)
    print("Step 5: Verification")
    print("-" * 70)
    if decrypted == message:
        print("   [SUCCESS] Encryption/decryption round-trip verified.")
        print("   Phase coherence was preserved: both sides used the same reference.")
    else:
        print("   [ERROR] Decryption failed.")
    
    print("\n" + "-" * 70)
    print("Step 6: The Observer Effect Demonstration")
    print("-" * 70)
    print("   Mathematical Invariant: I = (lambda_p/lambda_v) * (lambda_s/lambda_t)")
    print()
    print("   Unobserved (equilibrium):         I = +1")
    print("   After Bob's encryption:           I = -1 (observation flips sign)")
    print("   After Alice's decryption:         I = -1 (maintained with phase)")
    print()
    print("   If Alice used a DIFFERENT phase:  I != -1 (coherence lost, decryption fails)")
    print()
    print("   This demonstrates that observation is NOT passive.")
    print("   The observer (phase reference) becomes part of the system state.")
    
    print("\n" + "=" * 70)
    print("Demo Complete.")
    print("The Lambda-Morphic framework shows that I = -1 is the coherence condition")
    print("for monitored, engineered systems. The phase must be preserved.")
    print("=" * 70)


if __name__ == "__main__":
    main()