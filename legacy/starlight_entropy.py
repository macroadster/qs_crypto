import hashlib
import time
import struct
import os
from PIL import Image

# Use the image we generated previously
CARRIER_IMAGE = "quantum_ground_state.png"

class StarlightEntropyPool:
    def __init__(self, image_path):
        try:
            self.img = Image.open(image_path).convert("RGBA")
            self.pixels = self.img.load()
            self.width, self.height = self.img.size
            self.frame_counter = 0
            print(f"Starlight Entropy Pool initialized from {image_path}")
        except FileNotFoundError:
            print("Error: Quantum Ground State not found. Run the quantum simulation first.")
            exit()

    def _get_chaos_zone_state(self):
        """
        Reads the RGB values from the Antiferromagnetic Zone (Bottom Right).
        """
        state_bytes = bytearray()
        start_x = self.width // 2
        start_y = self.height // 2
        
        for y in range(start_y, self.height):
            for x in range(start_x, self.width):
                r, g, b, alpha = self.pixels[x, y]
                if alpha > 128: 
                    state_bytes.append(r)
                    state_bytes.append(g)
                    state_bytes.append(b)
        return state_bytes

    def _perturb_system(self):
        """
        SECURITY UPGRADE:
        Introduces a perturbation using Operating System Entropy (os.urandom).
        This makes the state transition unpredictable even if the attacker
        has the image and the timestamp.
        """
        # 1. Harvest TRNG from OS (Non-deterministic)
        # We get 4 bytes of random noise from the OS kernel
        os_noise = os.urandom(4)
        noise_int = struct.unpack("I", os_noise)[0]
        
        # 2. Mix with Time for spatial variation
        t = time.time_ns()
        
        # 3. Target a random spot in the Chaos Zone
        # We use the OS noise to decide WHERE to hit
        target_x = (self.width // 2) + (noise_int % (self.width // 2))
        target_y = (self.height // 2) + ((noise_int >> 16) % (self.height // 2))
        
        # 4. Force a "Spin Flip" with noise injection
        r, g, b, a = self.pixels[target_x, target_y]
        
        # We XOR the pixel color with the OS noise, injecting external entropy 
        # directly into the lattice state.
        new_r = r ^ os_noise[0]
        new_g = g ^ os_noise[1]
        new_b = b ^ os_noise[2]
        
        self.pixels[target_x, target_y] = (new_r, new_g, new_b, a)

    def get_random_bytes(self, num_bytes=32):
        """
        Generates random bytes by hashing the chaotic lattice state.
        """
        result = bytearray()
        
        while len(result) < num_bytes:
            self._perturb_system()
            
            lattice_state = self._get_chaos_zone_state()
            
            hasher = hashlib.sha256()
            hasher.update(lattice_state)
            hasher.update(struct.pack("Q", self.frame_counter))
            # Mix in more OS entropy during hashing for good measure
            hasher.update(os.urandom(8)) 
            
            digest = hasher.digest()
            result.extend(digest)
            self.frame_counter += 1
            
        return result[:num_bytes]
