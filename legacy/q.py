from PIL import Image
import types
import time
import sys

def extract_kernel(img):
    pixels = img.load()
    w, h = img.size
    extracted = bytearray()
    for i in range(w * h):
        x = i % w
        y = i // w
        alpha = pixels[x, y][3]
        if alpha == 0: break
        extracted.append(alpha)
    return extracted.decode('utf-8')

def get_neighbors(pixels, x, y, w, h):
    # Von Neumann neighborhood (Up, Down, Left, Right)
    neighbors = []
    dirs = [(0, 1), (0, -1), (1, 0), (-1, 0)]
    for dx, dy in dirs:
        nx, ny = (x + dx) % w, (y + dy) % h # Toroidal (Wrap-around) space
        r, g, b, _ = pixels[nx, ny]
        neighbors.append((r, g, b))
    return neighbors

def run_simulation(img_path, steps=50):
    try:
        img = Image.open(img_path).convert("RGBA")
    except:
        print("Lattice file not found. Run encoder first.")
        return

    # 1. Extract Physics
    kernel_code = extract_kernel(img)
    physics = types.ModuleType("quantum_physics")
    exec(kernel_code, physics.__dict__)
    
    if not hasattr(physics, 'process_state'):
        print("Invalid Quantum Kernel.")
        return

    w, h = img.size
    pixels = img.load()
    
    print(f"Simulating Heisenberg Model on {w}x{h} lattice...")
    print("Cooling down system (Annealing)...")

    # Temperature Schedule (Annealing)
    # Start hot (random), cool to zero (ground state)
    start_temp = 10.0
    end_temp = 0.1
    
    for step in range(steps):
        # Linear cooling
        current_temp = start_temp - ((start_temp - end_temp) * (step / steps))
        
        # Create buffer for next state (Synchronous update)
        new_img = Image.new("RGBA", (w, h))
        new_pixels = new_img.load()
        
        changes = 0
        
        for y in range(h):
            for x in range(w):
                r, g, b, alpha = pixels[x, y]
                
                # Skip the code storage area (approx first 1500 pixels)
                # In a real app, we'd be more precise.
                if (y * w + x) < 1500:
                    new_pixels[x, y] = (r, g, b, alpha)
                    continue

                neighbors = get_neighbors(pixels, x, y, w, h)
                
                # RUN THE EXTRACTED PHYSICS
                nr, ng, nb = physics.process_state(r, g, b, neighbors, alpha, current_temp)
                
                new_pixels[x, y] = (nr, ng, nb, alpha)
                
                if (nr, ng, nb) != (r, g, b):
                    changes += 1
        
        # Update main image
        img = new_img
        pixels = img.load()
        
        # visualize progress bar
        bar = "=" * int((step / steps) * 20)
        space = " " * (20 - len(bar))
        sys.stdout.write(f"\r[{bar}{space}] Temp: {current_temp:.2f} | Spins Flipped: {changes}")
        sys.stdout.flush()

    print("\nSimulation Complete.")
    img.save("quantum_ground_state.png")
    print("Result saved to 'quantum_ground_state.png'")

if __name__ == "__main__":
    run_simulation("quantum_lattice.png", steps=60)
