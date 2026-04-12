import angr
import networkx as nx
import matplotlib.pyplot as plt
import os
import time


TARGET_LS = "../ls_infected"
GRAPH_DIR = "../graphs"
# Virtual Address: 0x400000 (Base) + 0x14f00 (Cave Offset)
MALWARE_ADDR = 0x414f00 

def generate_final_report():
    
    if not os.path.exists(GRAPH_DIR):
        os.makedirs(GRAPH_DIR)

    start_time = time.time()
    
   
    if not os.path.exists(TARGET_LS):
        print(f"[!] Error: {TARGET_LS} not found.")
        return

    print(f"[*] Loading {TARGET_LS} and building Inter-procedural CFG...")
    proj = angr.Project(TARGET_LS, auto_load_libs=False)
    cfg_obj = proj.analyses.CFGFast()

    # using hex(node.addr) as the key ensures compatibility with path strings
    full_graph = nx.DiGraph()
    for src, dst in cfg_obj.graph.edges():
        full_graph.add_edge(hex(src.addr), hex(dst.addr))
        
    print(f"[*] CFG Built: {len(full_graph.nodes)} nodes identified.")

    #  Malware Subgraph (M)
    mal_start_hex = hex(MALWARE_ADDR)
    mal_end_hex = hex(MALWARE_ADDR + 0x600) # Increased range slightly to capture the full cave
    mal_nodes = [n for n in full_graph.nodes if mal_start_hex <= n <= mal_end_hex]

    if not mal_nodes:
        print("[!] Warning: No malware nodes found at the specified address range.")

   
    plt.figure(figsize=(20, 20))
    
    print("[*] Computing Force-Directed Layout (this is the 'Search Space' P)...")
    pos = nx.spring_layout(full_graph, k=0.06, iterations=60) 
    
    # Host' Program (P) in Light Blue
    nx.draw_networkx_nodes(full_graph, pos, 
                           node_color='#A0CBE2', 
                           node_size=15, 
                           alpha=0.3)
    
    # 'Malicious Subgraph' (M) in Vibrant Red
    nx.draw_networkx_nodes(full_graph, pos, 
                           nodelist=mal_nodes, 
                           node_color='red', 
                           node_size=70, 
                           label='Detected Malware Subgraph (M)')

    
    nx.draw_networkx_edges(full_graph, pos, alpha=0.1, edge_color='gray')

    end_time = time.time()
    duration = round(end_time - start_time, 2)

    
    plt.title(f"Full CFG Analysis: {len(full_graph.nodes)} Nodes\n"
              f"Red = Detected Malicious Subgraph | Analysis Time: {duration}s", fontsize=22)
    
    
    output_path = os.path.join(GRAPH_DIR, "full_infected_cfg_final.png")
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"[+] Success! Structural analysis complete.")
    print(f"[+] Final graph saved to: {output_path}")

if __name__ == "__main__":
    generate_final_report()