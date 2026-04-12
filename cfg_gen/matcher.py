import angr
import networkx as nx
from networkx.algorithms import isomorphism
import os

TARGET_LS = "../ls_infected"
MALWARE_START = 0x414f00 

def get_semantic_label(block):
    asm_text = str(block.capstone).lower()
    if "syscall" in asm_text: return "SYSTEM_CALL"
    if any(op in asm_text for op in ["xor", "sub", "add", "inc"]): return "ARITHMETIC"
    if any(op in asm_text for op in ["jmp", "jnz", "jz", "call"]): return "CONTROL_FLOW"
    if any(op in asm_text for op in ["mov", "push", "pop"]): return "DATA_TRANSFER"
    return "GENERIC"

def run_detection():
    if not os.path.exists(TARGET_LS):
        print(f"[!] Error: {TARGET_LS} not found!")
        return

    print("[*] Loading Binary for Structural Analysis...")
    proj = angr.Project(TARGET_LS, auto_load_libs=False)
    cfg_obj = proj.analyses.CFGFast()

   
    P = nx.DiGraph()
    for src, dst in cfg_obj.graph.edges():
        if src.block and dst.block:
            P.add_node(hex(src.addr), label=get_semantic_label(src.block))
            P.add_node(hex(dst.addr), label=get_semantic_label(dst.block))
            P.add_edge(hex(src.addr), hex(dst.addr))

   
    mal_start_hex = hex(MALWARE_START)
    mal_end_hex = hex(MALWARE_START + 0x500)
    mal_nodes = [n for n in P.nodes if mal_start_hex <= n <= mal_end_hex]
    M = P.subgraph(mal_nodes).copy()

    
    hijack_nodes = []
    for node in mal_nodes:
        # predecessors are nodes that point TO this node
        for pred in P.predecessors(node):
            if pred not in mal_nodes:
                hijack_nodes.append(pred)

    # VF2 Matching 
    nm = lambda n1, n2: n1['label'] == n2['label']
    gm = isomorphism.DiGraphMatcher(P, M, node_match=nm)

    if gm.subgraph_is_isomorphic():
        print("\n" + "╔" + "═"*58 + "╗")
        print("║" + " "*14 + "CFG-BASED MALWARE DETECTION ALERT" + " "*11 + "║")
        print("╚" + "═"*58 + "╝")
        
        
        if hijack_nodes:
            print(f"  [!] INJECTION POINT DETECTED:")
            print(f"      - Benign Host Node: {hijack_nodes[0]}")
            print(f"      - Redirects To:     {mal_start_hex} (Payload Start)")
        
        match_map = next(gm.subgraph_isomorphisms_iter())
        print("-" * 60)
        print(f"  [+] Match Result:   Found {len(match_map)} blocks matching Archetype M")
        
        
        labels = [P.nodes[node]['label'] for node in match_map.keys()]
        print(f"  [i] Payload Profile: {labels.count('ARITHMETIC')} Arith | "
              f"{labels.count('SYSTEM_CALL')} Syscall | "
              f"{labels.count('DATA_TRANSFER')} Data")
        
        print("-" * 60)
        print(f"  [✓] VERDICT: Binary compromised by structural injection.")
        print("=" * 60 + "\n")

if __name__ == "__main__":
    run_detection()