import os
import time
import hashlib

TARGET_LS = "../ls_infected"
GRAPH_DIR = "../graphs"
CAVE_OFFSET = 0x14f00 

def get_binary_hash(filepath):
    
    if not os.path.exists(filepath):
        return "unknown"
    with open(filepath, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()[:6]

def generate_live_cfg():
    
    if not os.path.exists(GRAPH_DIR):
        print(f"[*] Creating {GRAPH_DIR} directory...")
        os.makedirs(GRAPH_DIR)

    
    if not os.path.exists(TARGET_LS):
        print(f"[!] Error: {TARGET_LS} not found! run epo.py?")
        return

    
    timestamp = time.strftime("%H%M%S")
    v_hash = get_binary_hash(TARGET_LS)
    
    
    base_name = f"cfg_{timestamp}_hash_{v_hash}"
    temp_dot = os.path.join(GRAPH_DIR, f"{base_name}.dot")
    output_png = os.path.join(GRAPH_DIR, f"{base_name}.png")

    print(f"[*] Analyzing Variant MD5 (short): {v_hash}")
    print(f"[*] Output Target: {output_png}")
    
    # exec radare2 via system call
    # We use hex(CAVE_OFFSET) to ensure r2 seeks to the right spot
    # 'af' analyzes function, 'agfd' generates the DOT graphviz data
    r2_cmd = f'r2 -batch -qc "s {hex(CAVE_OFFSET)}; af; agfd" {TARGET_LS} > "{temp_dot}"'
    os.system(r2_cmd)
    
   
    if os.path.exists(temp_dot) and os.path.getsize(temp_dot) > 0:
        os.system(f'dot -Tpng "{temp_dot}" -o "{output_png}"')
        
        
        os.remove(temp_dot)
        print(f"[+] Success! CFG Visualization saved to {output_png}")
    else:
        print(f"[!] Error: radare2 failed to generate graph data at {hex(CAVE_OFFSET)}.")

if __name__ == "__main__":
    generate_live_cfg()