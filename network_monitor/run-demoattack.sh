#!/bin/bash

# Percorso al venv del progetto
VENV_PATH="./venv"

# Percorso allo script Python degli attacchi demo
DEMO_SCRIPT="./demo_attack/demo_attack_simulator.py"

# Funzione per attivare il venv
activate_venv() {
    if [ ! -f "$VENV_PATH/bin/activate" ]; then
        echo "[INFO] Virtual environment non trovato, lo creo..."
        python3 -m venv "$VENV_PATH"
        source "$VENV_PATH/bin/activate"
        pip install --upgrade pip
        pip install -r requirements.txt
    else
        source "$VENV_PATH/bin/activate"
    fi
}

# Funzione per stampare il menu
show_menu() {
    echo "=============================="
    echo "  Demo Attacchi Rete"
    echo "=============================="
    echo "1) ARP Spoofing"
    echo "2) SYN Flood"
    echo "3) ICMP Flood"
    echo "4) TCP Reset Attack"
    echo "5) UDP Amplification"
    echo "6) DNS Tunneling"
    echo "7) DDoS Simulation"
    echo "8) Tutti gli attacchi"
    echo "0) Esci"
    echo "=============================="
}

# Attivazione venv
activate_venv

# Loop menu
while true; do
    show_menu
    read -p "Seleziona un attacco (0-8): " choice
    case $choice in
        1) python "$DEMO_SCRIPT" arp ;;
        2) python "$DEMO_SCRIPT" syn ;;
        3) python "$DEMO_SCRIPT" icmp ;;
        4) python "$DEMO_SCRIPT" tcpreset ;;
        5) python "$DEMO_SCRIPT" udp ;;
        6) python "$DEMO_SCRIPT" dns ;;
        7) python "$DEMO_SCRIPT" ddos ;;
        8) python "$DEMO_SCRIPT" all ;;
        0) echo "Uscita."; break ;;
        *) echo "Scelta non valida, riprova." ;;
    esac
    echo "Premi INVIO per continuare..."
    read
done


