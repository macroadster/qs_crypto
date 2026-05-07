import hashlib
import os
import base64
from starlight_entropy import StarlightEntropyPool

# --- THE STARLIGHT CIPHER (AES-Strength Stream Cipher) ---
# Implements a CTR-mode stream cipher using SHA-256 as the PRF.
# This allows us to perform strong encryption using only standard libraries.

class StarlightCipher:
    def __init__(self, key_bytes):
        if len(key_bytes) != 32:
            raise ValueError("Key must be 256-bit (32 bytes)")
        self.key = key_bytes

    def _xor_bytes(self, a, b):
        """XORs two byte strings together."""
        return bytes(x ^ y for x, y in zip(a, b))

    def _generate_keystream_block(self, nonce, counter):
        """
        Generates a 32-byte keystream block.
        Block = SHA256(Key + Nonce + Counter)
        """
        sha = hashlib.sha256()
        sha.update(self.key)
        sha.update(nonce)
        # Pack counter as 8-byte Big Endian
        sha.update(counter.to_bytes(8, byteorder='big')) 
        return sha.digest()

    def encrypt(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
            
        # 1. Generate a random Nonce (IV)
        nonce = os.urandom(16)
        
        ciphertext = bytearray()
        # Prepend Nonce to ciphertext (needed for decryption)
        ciphertext.extend(nonce)
        
        # 2. Stream Encryption (CTR Mode)
        # We process the plaintext in 32-byte chunks (size of SHA256 hash)
        block_size = 32
        for i in range(0, len(plaintext), block_size):
            chunk = plaintext[i:i+block_size]
            counter = i // block_size
            
            # Generate XOR mask
            keystream = self._generate_keystream_block(nonce, counter)
            
            # Encrypt chunk
            encrypted_chunk = self._xor_bytes(chunk, keystream)
            ciphertext.extend(encrypted_chunk)
            
        # Return base64 encoded string for easy handling
        return base64.b64encode(ciphertext).decode('utf-8')

    def decrypt(self, b64_ciphertext):
        raw_data = base64.b64decode(b64_ciphertext)
        
        # 1. Extract Nonce (First 16 bytes)
        nonce = raw_data[:16]
        ciphertext_body = raw_data[16:]
        
        plaintext = bytearray()
        
        # 2. Stream Decryption (Identical to Encryption in CTR mode)
        block_size = 32
        for i in range(0, len(ciphertext_body), block_size):
            chunk = ciphertext_body[i:i+block_size]
            counter = i // block_size
            
            keystream = self._generate_keystream_block(nonce, counter)
            
            decrypted_chunk = self._xor_bytes(chunk, keystream)
            plaintext.extend(decrypted_chunk)
            
        return plaintext.decode('utf-8')

# --- THE DEMO ---

def run_demo():
    print("--- Project Starlight: Secure Comms Demo ---")
    
    # 1. KEY GENERATION
    print("\n[1] Initializing Starlight Entropy Engine...")
    print("    (Harvesting entropy from 'quantum_ground_state.png' + OS Jitter)")
    
    entropy_pool = StarlightEntropyPool("quantum_ground_state.png")
    
    # Generate a 256-bit Master Key
    master_key = entropy_pool.get_random_bytes(32)
    print(f"    > Generated Master Key: {master_key.hex()}")

    # 2. ENCRYPTION
    cipher = StarlightCipher(master_key)
    
    secret_message = "Operation Starlight is a go. The carrier image is secure."
    print(f"\n[2] Encrypting Secret Message: '{secret_message}'")
    
    encrypted_msg = cipher.encrypt(secret_message)
    print(f"    > Ciphertext: {encrypted_msg}")
    
    # 3. DECRYPTION
    print(f"\n[3] Decrypting...")
    
    # Note: We simply reuse the cipher instance here, but in a real scenario,
    # the receiver would need the 'master_key' to initialize their own cipher.
    decrypted_msg = cipher.decrypt(encrypted_msg)
    
    print(f"    > Plaintext: '{decrypted_msg}'")
    
    if secret_message == decrypted_msg:
        print("\n[SUCCESS] Cycle complete. Integrity verified.")
    else:
        print("\n[FAILURE] Decryption mismatch.")

if __name__ == "__main__":
    run_demo()
