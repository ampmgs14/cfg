#!/bin/bash

# CONFIG
ORIGINAL_LS="/bin/ls"
GRAPH_DIR="./graphs"
OUTPUT_PNG="$GRAPH_DIR/clean_ls_original.png"
TEMP_DOT="$GRAPH_DIR/temp_clean.dot"

if [ ! -d "$GRAPH_DIR" ]; then
    echo "[*] Creating $GRAPH_DIR directory..."
    mkdir -p "$GRAPH_DIR"
fi

echo "[*] Analyzing original binary: $ORIGINAL_LS"


# s entry0  : Seek to the main entry point of the program
# af        : Analyze the function at that entry point
# agfd      : Generate Graphviz (DOT) format for the function
r2 -batch -qc "s entry0; af; agfd" "$ORIGINAL_LS" > "$TEMP_DOT"


if command -v dot >/dev/null 2>&1; then
    echo "[*] Rendering CFG to $OUTPUT_PNG..."
    dot -Tpng "$TEMP_DOT" -o "$OUTPUT_PNG"
    
    
    rm "$TEMP_DOT"
    echo "[+] Done! You can now open $OUTPUT_PNG to show the clean 'ls' structure."
else
    echo "[!] Error: 'graphviz' is not installed. Run 'sudo apt install graphviz'."
fi
